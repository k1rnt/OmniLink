/*
 * OmniLink WFP Callout Driver
 *
 * Windows Filtering Platform callout driver for transparent traffic
 * interception. Hooks ALE_CONNECT_REDIRECT layers to redirect outgoing
 * TCP connections to a local proxy.
 *
 * Build requirements:
 * - Windows Driver Kit (WDK) 10
 * - Visual Studio 2022+ with WDK integration
 * - EV Code Signing Certificate (for production)
 *
 * Test requirements:
 * - Enable test signing: bcdedit /set testsigning on
 * - Reboot
 */

#pragma once

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntstrsafe.h>

/* Device name for user-mode IOCTL communication */
#define OMNILINK_DEVICE_NAME    L"\\Device\\OmniLinkWFP"
#define OMNILINK_SYMLINK_NAME   L"\\DosDevices\\OmniLinkWFP"

/* IOCTL codes */
#define IOCTL_OMNILINK_GET_ORIGINAL_DST \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_OMNILINK_SET_CONFIG \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_OMNILINK_GET_STATS \
    CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

/* Maximum number of NAT entries */
#define MAX_NAT_ENTRIES 65536

/* NAT entry: maps a rewritten connection to the original destination */
typedef struct _NAT_ENTRY {
    UINT32 src_addr;         /* Source IPv4 address (network byte order) */
    UINT16 src_port;         /* Source port (network byte order) */
    UINT32 original_dst_addr; /* Original destination IPv4 (network byte order) */
    UINT16 original_dst_port; /* Original destination port (network byte order) */
    LARGE_INTEGER timestamp;  /* Entry creation time */
    BOOLEAN in_use;
} NAT_ENTRY, *PNAT_ENTRY;

/* Driver configuration set by user-mode service */
typedef struct _DRIVER_CONFIG {
    UINT32 proxy_addr;   /* Local proxy address (127.0.0.1, network byte order) */
    UINT16 proxy_port;   /* Local proxy port (network byte order) */
    UINT32 proxy_pid;    /* PID of the proxy process (excluded from interception) */
    BOOLEAN enabled;     /* Whether interception is active */
} DRIVER_CONFIG, *PDRIVER_CONFIG;

/* IOCTL input for querying original destination */
typedef struct _ORIGINAL_DST_QUERY {
    UINT32 src_addr;
    UINT16 src_port;
} ORIGINAL_DST_QUERY, *PORIGINAL_DST_QUERY;

/* IOCTL output for original destination */
typedef struct _ORIGINAL_DST_RESULT {
    UINT32 original_addr;
    UINT16 original_port;
    BOOLEAN found;
} ORIGINAL_DST_RESULT, *PORIGINAL_DST_RESULT;

/* Driver statistics */
typedef struct _DRIVER_STATS {
    UINT64 total_intercepted;
    UINT64 total_passed;
    UINT64 active_nat_entries;
} DRIVER_STATS, *PDRIVER_STATS;

/* Function prototypes */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS RegisterWfpCallouts(void);

_IRQL_requires_max_(DISPATCH_LEVEL)
void UnregisterWfpCallouts(void);

_IRQL_requires_max_(DISPATCH_LEVEL)
void NTAPI ClassifyConnectV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI NotifyConnectV4(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter
);

/* NAT table operations */
NTSTATUS NatInsert(UINT32 src_addr, UINT16 src_port,
                   UINT32 original_addr, UINT16 original_port);
NTSTATUS NatLookup(UINT32 src_addr, UINT16 src_port,
                   PUINT32 original_addr, PUINT16 original_port);
void NatCleanupExpired(void);
