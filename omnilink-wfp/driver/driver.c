/*
 * OmniLink WFP Callout Driver - Skeleton Implementation
 *
 * This is a skeleton for a WFP callout driver that intercepts
 * outgoing TCP connections at the ALE_CONNECT_REDIRECT layer
 * and redirects them to a local proxy.
 *
 * TODO: This requires WDK to compile. See README.md for build instructions.
 */

#include "driver.h"

/* Globals */
static HANDLE g_engine_handle = NULL;
static UINT32 g_callout_id_v4 = 0;
static UINT64 g_filter_id_v4 = 0;
static HANDLE g_redirect_handle = NULL;
static PDEVICE_OBJECT g_device_object = NULL;

static DRIVER_CONFIG g_config = {0};
static NAT_ENTRY g_nat_table[MAX_NAT_ENTRIES] = {0};
static KSPIN_LOCK g_nat_lock;

static DRIVER_STATS g_stats = {0};

/* GUIDs for WFP registration */
/* {A1B2C3D4-E5F6-7890-ABCD-EF0123456789} */
DEFINE_GUID(OMNILINK_CALLOUT_V4_GUID,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89);

DEFINE_GUID(OMNILINK_SUBLAYER_GUID,
    0xa1b2c3d5, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x8a);

/* ---- Driver Entry / Unload ---- */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&g_nat_lock);

    /* Create device object for IOCTL */
    RtlInitUnicodeString(&deviceName, OMNILINK_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_NETWORK,
        0,
        FALSE,
        &g_device_object
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Create symbolic link */
    RtlInitUnicodeString(&symlinkName, OMNILINK_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_device_object);
        return status;
    }

    /* Set up IRP dispatch routines */
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

    /* Register WFP callouts */
    status = RegisterWfpCallouts();
    if (!NT_SUCCESS(status)) {
        UNICODE_STRING symlink;
        RtlInitUnicodeString(&symlink, OMNILINK_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_device_object);
        return status;
    }

    return STATUS_SUCCESS;
}

void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(DriverObject);

    /* Unregister WFP */
    UnregisterWfpCallouts();

    /* Remove symbolic link and device */
    RtlInitUnicodeString(&symlinkName, OMNILINK_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (g_device_object) {
        IoDeleteDevice(g_device_object);
    }
}

/* ---- WFP Registration ---- */

NTSTATUS RegisterWfpCallouts(void)
{
    NTSTATUS status;
    FWPM_SESSION0 session = {0};
    FWPS_CALLOUT3 sCallout = {0};
    FWPM_CALLOUT0 mCallout = {0};
    FWPM_FILTER0 filter = {0};
    FWPM_SUBLAYER0 sublayer = {0};

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    /* Open filter engine */
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_engine_handle);
    if (!NT_SUCCESS(status)) return status;

    /* Create redirect handle */
    status = FwpsRedirectHandleCreate0(&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, 0, &g_redirect_handle);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(g_engine_handle);
        return status;
    }

    /* Begin transaction */
    status = FwpmTransactionBegin0(g_engine_handle, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    /* Add sublayer */
    sublayer.subLayerKey = OMNILINK_SUBLAYER_GUID;
    sublayer.displayData.name = L"OmniLink Sublayer";
    sublayer.weight = 0xFFFF;
    status = FwpmSubLayerAdd0(g_engine_handle, &sublayer, NULL);
    if (!NT_SUCCESS(status)) goto abort;

    /* Register callout (kernel) */
    sCallout.calloutKey = OMNILINK_CALLOUT_V4_GUID;
    sCallout.classifyFn = ClassifyConnectV4;
    sCallout.notifyFn = NotifyConnectV4;
    status = FwpsCalloutRegister3(g_device_object, &sCallout, &g_callout_id_v4);
    if (!NT_SUCCESS(status)) goto abort;

    /* Add callout (management) */
    mCallout.calloutKey = OMNILINK_CALLOUT_V4_GUID;
    mCallout.displayData.name = L"OmniLink Connect Redirect V4";
    mCallout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    status = FwpmCalloutAdd0(g_engine_handle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) goto abort;

    /* Add filter */
    filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    filter.subLayerKey = OMNILINK_SUBLAYER_GUID;
    filter.displayData.name = L"OmniLink Connect Redirect Filter V4";
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = OMNILINK_CALLOUT_V4_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x0F;
    status = FwpmFilterAdd0(g_engine_handle, &filter, NULL, &g_filter_id_v4);
    if (!NT_SUCCESS(status)) goto abort;

    /* Commit transaction */
    status = FwpmTransactionCommit0(g_engine_handle);
    if (!NT_SUCCESS(status)) goto cleanup;

    return STATUS_SUCCESS;

abort:
    FwpmTransactionAbort0(g_engine_handle);
cleanup:
    if (g_redirect_handle) {
        FwpsRedirectHandleDestroy0(g_redirect_handle);
        g_redirect_handle = NULL;
    }
    FwpmEngineClose0(g_engine_handle);
    g_engine_handle = NULL;
    return status;
}

void UnregisterWfpCallouts(void)
{
    if (g_engine_handle) {
        FwpmFilterDeleteById0(g_engine_handle, g_filter_id_v4);
        FwpmCalloutDeleteByKey0(g_engine_handle, &OMNILINK_CALLOUT_V4_GUID);
        FwpmSubLayerDeleteByKey0(g_engine_handle, &OMNILINK_SUBLAYER_GUID);
        FwpmEngineClose0(g_engine_handle);
        g_engine_handle = NULL;
    }

    if (g_callout_id_v4) {
        FwpsCalloutUnregisterById0(g_callout_id_v4);
        g_callout_id_v4 = 0;
    }

    if (g_redirect_handle) {
        FwpsRedirectHandleDestroy0(g_redirect_handle);
        g_redirect_handle = NULL;
    }
}

/* ---- WFP Classify Callback ---- */

void NTAPI ClassifyConnectV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    FWPS_CONNECT_REQUEST0* connectRequest = NULL;
    UINT32 remoteAddr;
    UINT16 remotePort;
    UINT64 processId;

    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!g_config.enabled || !layerData) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    /* Get process ID */
    if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        processId = inMetaValues->processId;
    } else {
        processId = 0;
    }

    /* Skip our own proxy process */
    if ((UINT32)processId == g_config.proxy_pid) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    /* Extract original destination */
    remoteAddr = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    remotePort = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;

    /* Skip loopback */
    if (remoteAddr == 0x7F000001) { /* 127.0.0.1 in host byte order */
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    /* Get the connect request for modification */
    /* TODO: Use FwpsAcquireClassifyHandle0 + FwpsAcquireWritableLayerDataPointer0
       to get a writable FWPS_CONNECT_REQUEST0 and modify the remote address/port.
       This is the core redirection logic:
       1. Save original destination to NAT table
       2. Set connectRequest->remoteAddressAndPort to proxy address
       3. Set connectRequest->localRedirectTargetPID
       4. Call FwpsApplyModifiedLayerData0
    */

    /* For now, just permit */
    classifyOut->actionType = FWP_ACTION_PERMIT;
    InterlockedIncrement64((LONG64*)&g_stats.total_passed);
}

NTSTATUS NTAPI NotifyConnectV4(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* ---- IRP Dispatch ---- */

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_OMNILINK_SET_CONFIG:
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(DRIVER_CONFIG)) {
            RtlCopyMemory(&g_config, Irp->AssociatedIrp.SystemBuffer, sizeof(DRIVER_CONFIG));
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_OMNILINK_GET_ORIGINAL_DST:
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(ORIGINAL_DST_QUERY) &&
            irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(ORIGINAL_DST_RESULT)) {
            PORIGINAL_DST_QUERY query = (PORIGINAL_DST_QUERY)Irp->AssociatedIrp.SystemBuffer;
            PORIGINAL_DST_RESULT result = (PORIGINAL_DST_RESULT)Irp->AssociatedIrp.SystemBuffer;

            status = NatLookup(query->src_addr, query->src_port,
                             &result->original_addr, &result->original_port);
            result->found = NT_SUCCESS(status);
            info = sizeof(ORIGINAL_DST_RESULT);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_OMNILINK_GET_STATS:
        if (irpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(DRIVER_STATS)) {
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &g_stats, sizeof(DRIVER_STATS));
            info = sizeof(DRIVER_STATS);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ---- NAT Table Operations ---- */

NTSTATUS NatInsert(UINT32 src_addr, UINT16 src_port,
                   UINT32 original_addr, UINT16 original_port)
{
    KIRQL oldIrql;
    ULONG i;

    KeAcquireSpinLock(&g_nat_lock, &oldIrql);

    for (i = 0; i < MAX_NAT_ENTRIES; i++) {
        if (!g_nat_table[i].in_use) {
            g_nat_table[i].src_addr = src_addr;
            g_nat_table[i].src_port = src_port;
            g_nat_table[i].original_dst_addr = original_addr;
            g_nat_table[i].original_dst_port = original_port;
            KeQuerySystemTime(&g_nat_table[i].timestamp);
            g_nat_table[i].in_use = TRUE;

            KeReleaseSpinLock(&g_nat_lock, oldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_nat_lock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS NatLookup(UINT32 src_addr, UINT16 src_port,
                   PUINT32 original_addr, PUINT16 original_port)
{
    KIRQL oldIrql;
    ULONG i;

    KeAcquireSpinLock(&g_nat_lock, &oldIrql);

    for (i = 0; i < MAX_NAT_ENTRIES; i++) {
        if (g_nat_table[i].in_use &&
            g_nat_table[i].src_addr == src_addr &&
            g_nat_table[i].src_port == src_port) {

            *original_addr = g_nat_table[i].original_dst_addr;
            *original_port = g_nat_table[i].original_dst_port;

            /* Remove entry after lookup */
            g_nat_table[i].in_use = FALSE;

            KeReleaseSpinLock(&g_nat_lock, oldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_nat_lock, oldIrql);
    return STATUS_NOT_FOUND;
}

void NatCleanupExpired(void)
{
    /* TODO: Implement TTL-based cleanup using g_nat_table[i].timestamp */
}
