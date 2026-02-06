import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { useUpdater } from "../hooks/useUpdater";
import { useToast } from "../hooks/useToast";
import type { AppState } from "../types";

interface ProfileInfo {
  name: string;
  path: string;
  active: boolean;
}

interface NEStatusInfo {
  installed: boolean;
  enabled: boolean;
  running: boolean;
  server_running: boolean;
}

interface Props {
  state: AppState;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function SettingsView({ state }: Props) {
  const { success, error: showError } = useToast();
  const [sysproxyEnabled, setSysproxyEnabled] = useState(false);
  const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
  const [newProfileName, setNewProfileName] = useState("");
  const [appVersion, setAppVersion] = useState("");
  const [isMacOS] = useState(() => navigator.platform.toUpperCase().includes("MAC"));
  const [neStatus, setNeStatus] = useState<NEStatusInfo>({ installed: false, enabled: false, running: false, server_running: false });
  const [pfStatus, setPfStatus] = useState(false);
  const { updateInfo, progress, error, checkForUpdates, downloadAndInstall, restartApp } = useUpdater();

  useEffect(() => {
    getVersion().then(setAppVersion);
  }, []);

  const fetchProfiles = useCallback(async () => {
    try {
      const data = await invoke<ProfileInfo[]>("get_profiles");
      setProfiles(data);
    } catch (e) {
      console.error("Failed to fetch profiles:", e);
    }
  }, []);

  const fetchSysproxy = useCallback(async () => {
    try {
      const enabled = await invoke<boolean>("get_sysproxy_status");
      setSysproxyEnabled(enabled);
    } catch (e) {
      console.error("Failed to fetch sysproxy status:", e);
    }
  }, []);

  const fetchNeStatus = useCallback(async () => {
    if (!isMacOS) return;
    try {
      const status = await invoke<NEStatusInfo>("get_ne_status");
      setNeStatus(status);
    } catch (e) {
      console.error("Failed to fetch NE status:", e);
    }
  }, [isMacOS]);

  const fetchPfStatus = useCallback(async () => {
    if (!isMacOS) return;
    try {
      const running = await invoke<boolean>("get_pf_interceptor_status");
      setPfStatus(running);
    } catch (e) {
      console.error("Failed to fetch pf status:", e);
    }
  }, [isMacOS]);

  useEffect(() => {
    fetchSysproxy();
    fetchProfiles();
    fetchNeStatus();
    fetchPfStatus();
  }, [fetchSysproxy, fetchProfiles, fetchNeStatus, fetchPfStatus]);

  const showMessage = (msg: string) => {
    if (msg.toLowerCase().startsWith("error")) {
      showError(msg);
    } else {
      success(msg);
    }
  };

  const handleToggleSysproxy = async () => {
    try {
      const result = await invoke<string>("toggle_sysproxy");
      showMessage(result);
      await fetchSysproxy();
    } catch (e) {
      showMessage(`Error: ${e}`);
    }
  };

  const handleLoadConfig = async () => {
    try {
      const filePath = await openDialog({
        filters: [{ name: "YAML", extensions: ["yaml", "yml"] }],
        multiple: false,
      });
      if (!filePath) return;
      const result = await invoke<string>("load_config", { path: filePath });
      showMessage(result);
    } catch (e) {
      showMessage(`Error: ${e}`);
    }
  };

  const handleSaveConfig = async () => {
    try {
      const filePath = await saveDialog({
        defaultPath: "config.yaml",
        filters: [{ name: "YAML", extensions: ["yaml", "yml"] }],
      });
      if (!filePath) return;
      const result = await invoke<string>("save_config_to", { path: filePath });
      showMessage(result);
    } catch (e) {
      showMessage(`Error: ${e}`);
    }
  };

  const handleResetStats = async () => {
    try {
      const result = await invoke<string>("reset_stats");
      showMessage(result);
    } catch (e) {
      showMessage(`Error: ${e}`);
    }
  };

  return (
    <div className="settings-panel">
      <div className="setting-group">
        <h3>Updates</h3>
        <div className="setting-row">
          <span className="setting-label">Current Version</span>
          <span className="setting-value">v{appVersion}</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Check for Updates</span>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {progress.status === "checking" ? (
              <span className="setting-value">Checking...</span>
            ) : (
              <button
                className="btn btn-primary"
                style={{ padding: "3px 10px", fontSize: 11 }}
                onClick={checkForUpdates}
              >
                Check Now
              </button>
            )}
          </div>
        </div>
        {updateInfo.available && progress.status === "idle" && (
          <div className="setting-row">
            <span className="setting-label">
              New version available: <strong>v{updateInfo.newVersion}</strong>
            </span>
            <button
              className="btn btn-primary"
              style={{ padding: "3px 10px", fontSize: 11 }}
              onClick={downloadAndInstall}
            >
              Download & Install
            </button>
          </div>
        )}
        {progress.status === "downloading" && (
          <div className="setting-row">
            <span className="setting-label">Downloading</span>
            <span className="setting-value">
              {progress.totalBytes > 0
                ? `${Math.round((progress.downloadedBytes / progress.totalBytes) * 100)}% (${formatBytes(progress.downloadedBytes)} / ${formatBytes(progress.totalBytes)})`
                : `${formatBytes(progress.downloadedBytes)}`}
            </span>
          </div>
        )}
        {progress.status === "ready" && (
          <div className="setting-row">
            <span className="setting-label">Update ready</span>
            <button
              className="btn btn-primary"
              style={{ padding: "3px 10px", fontSize: 11 }}
              onClick={restartApp}
            >
              Restart Now
            </button>
          </div>
        )}
        {progress.status === "error" && error && (
          <div className="setting-row">
            <span className="setting-label" style={{ color: "var(--error)" }}>
              Error: {error}
            </span>
            <button
              className="btn"
              style={{ padding: "3px 10px", fontSize: 11 }}
              onClick={checkForUpdates}
            >
              Retry
            </button>
          </div>
        )}
        {!updateInfo.available && progress.status === "idle" && (
          <div className="setting-row">
            <span className="setting-label" style={{ color: "var(--text-secondary)" }}>
              You're up to date
            </span>
          </div>
        )}
      </div>

      <div className="setting-group">
        <h3>General</h3>
        <div className="setting-row">
          <span className="setting-label">Listen Address</span>
          <span className="setting-value">{state.listen_addr}</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Status</span>
          <span className="setting-value">{state.running ? "Running" : "Stopped"}</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Active Connections</span>
          <span className="setting-value">{state.active_connections}</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Total Connections</span>
          <span className="setting-value">{state.total_connections}</span>
        </div>
      </div>

      <div className="setting-group">
        <h3>DNS</h3>
        <div className="setting-row">
          <span className="setting-label">Resolution Mode</span>
          <span className="setting-value">{state.dns_mode}</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Fake IP Range</span>
          <span className="setting-value">198.18.0.0/15</span>
        </div>
      </div>

      <div className="setting-group">
        <h3>System Proxy</h3>
        <div className="setting-row">
          <span className="setting-label">SOCKS Proxy</span>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className="setting-value">{sysproxyEnabled ? "Enabled" : "Disabled"}</span>
            <button
              className={`btn ${sysproxyEnabled ? "" : "btn-primary"}`}
              style={{ padding: "3px 10px", fontSize: 11 }}
              onClick={handleToggleSysproxy}
            >
              {sysproxyEnabled ? "Disable" : "Enable"}
            </button>
          </div>
        </div>
      </div>

      {isMacOS && (
        <div className="setting-group" style={{ opacity: 0.5 }}>
          <h3>Network Extension (macOS)</h3>
          <div className="setting-row">
            <span className="setting-label">Extension Status</span>
            <span className="setting-value">Not Available</span>
          </div>
          <div className="setting-row">
            <span className="setting-label">NE Server</span>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="setting-value">
                {neStatus.server_running ? "Running" : "Stopped"}
              </span>
              <button
                className="btn"
                style={{ padding: "3px 10px", fontSize: 11 }}
                disabled
              >
                {neStatus.server_running ? "Stop" : "Start"}
              </button>
            </div>
          </div>
          <div className="setting-row">
            <span
              className="setting-label"
              style={{ fontSize: 11, color: "var(--text-secondary)" }}
            >
              Requires Apple Developer Program membership.
              Use "Transparent Proxy (pf)" below instead.
            </span>
          </div>
        </div>
      )}

      {isMacOS && (
        <div className="setting-group">
          <h3>Transparent Proxy (pf)</h3>
          <div className="setting-row">
            <span className="setting-label">Status</span>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="setting-value">
                {pfStatus ? "Running" : "Stopped"}
              </span>
              <button
                className={`btn ${pfStatus ? "" : "btn-primary"}`}
                style={{ padding: "3px 10px", fontSize: 11 }}
                onClick={async () => {
                  try {
                    const cmd = pfStatus ? "stop_pf_interceptor" : "start_pf_interceptor";
                    const result = await invoke<string>(cmd);
                    showMessage(result);
                    await fetchPfStatus();
                  } catch (e) {
                    showMessage(`Error: ${e}`);
                  }
                }}
              >
                {pfStatus ? "Stop" : "Start"}
              </button>
            </div>
          </div>
          <div className="setting-row">
            <span
              className="setting-label"
              style={{ fontSize: 11, color: "var(--text-secondary)" }}
            >
              Intercepts TCP traffic using macOS Packet Filter (pf).
              Requires admin password. No Apple Developer membership needed.
            </span>
          </div>
        </div>
      )}

      <div className="setting-group">
        <h3>Profiles</h3>
        {profiles.map((profile) => (
          <div className="setting-row" key={profile.name}>
            <span className="setting-label">
              {profile.name}
              {profile.active && (
                <span style={{ fontSize: 10, color: "var(--accent)", marginLeft: 6 }}>active</span>
              )}
            </span>
            {!profile.active && (
              <button
                className="btn btn-primary"
                style={{ padding: "3px 10px", fontSize: 11 }}
                onClick={async () => {
                  try {
                    const result = await invoke<string>("switch_profile", { path: profile.path });
                    showMessage(result);
                    await fetchProfiles();
                  } catch (e) {
                    showMessage(`Error: ${e}`);
                  }
                }}
              >
                Switch
              </button>
            )}
          </div>
        ))}
        <div className="setting-row">
          <span className="setting-label">Save as Profile</span>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              className="search-input"
              placeholder="profile name"
              value={newProfileName}
              onChange={(e) => setNewProfileName(e.target.value)}
              style={{ width: 150 }}
            />
            <button
              className="btn"
              style={{ padding: "3px 10px", fontSize: 11 }}
              onClick={async () => {
                if (!newProfileName) return;
                try {
                  const result = await invoke<string>("save_profile", { name: newProfileName });
                  showMessage(result);
                  setNewProfileName("");
                  await fetchProfiles();
                } catch (e) {
                  showMessage(`Error: ${e}`);
                }
              }}
            >
              Save
            </button>
          </div>
        </div>
      </div>

      <div className="setting-group">
        <h3>Configuration</h3>
        <div className="setting-row">
          <span className="setting-label">Load Config File</span>
          <button className="btn" style={{ padding: "3px 10px", fontSize: 11 }} onClick={handleLoadConfig}>
            Open...
          </button>
        </div>
        <div className="setting-row">
          <span className="setting-label">Export Config File</span>
          <button className="btn" style={{ padding: "3px 10px", fontSize: 11 }} onClick={handleSaveConfig}>
            Save As...
          </button>
        </div>
      </div>

      <div className="setting-group">
        <h3>Statistics</h3>
        <div className="setting-row">
          <span className="setting-label">Reset Traffic Statistics</span>
          <button
            className="btn"
            style={{ padding: "3px 10px", fontSize: 11, color: "var(--error)" }}
            onClick={handleResetStats}
          >
            Reset
          </button>
        </div>
      </div>
    </div>
  );
}

export default SettingsView;
