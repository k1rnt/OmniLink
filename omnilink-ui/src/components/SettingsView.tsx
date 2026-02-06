import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { useUpdater } from "../hooks/useUpdater";
import type { AppState } from "../types";

interface ProfileInfo {
  name: string;
  path: string;
  active: boolean;
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
  const [sysproxyEnabled, setSysproxyEnabled] = useState(false);
  const [configPath, setConfigPath] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
  const [newProfileName, setNewProfileName] = useState("");
  const [appVersion, setAppVersion] = useState("");
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

  useEffect(() => {
    fetchSysproxy();
    fetchProfiles();
  }, [fetchSysproxy, fetchProfiles]);

  const showMessage = (msg: string) => {
    setMessage(msg);
    setTimeout(() => setMessage(null), 3000);
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
      const path = configPath || undefined;
      const result = await invoke<string>("load_config", { path });
      showMessage(result);
    } catch (e) {
      showMessage(`Error: ${e}`);
    }
  };

  const handleSaveConfig = async () => {
    try {
      const result = await invoke<string>("save_config");
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
      {message && (
        <div
          style={{
            padding: "8px 12px",
            background: "var(--bg-tertiary)",
            border: "1px solid var(--border)",
            borderRadius: 4,
            marginBottom: 12,
            fontSize: 12,
          }}
        >
          {message}
        </div>
      )}

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
          <span className="setting-label">Config File</span>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              className="search-input"
              placeholder="config.yaml"
              value={configPath}
              onChange={(e) => setConfigPath(e.target.value)}
              style={{ width: 200 }}
            />
            <button className="btn" style={{ padding: "3px 10px", fontSize: 11 }} onClick={handleLoadConfig}>
              Load
            </button>
          </div>
        </div>
        <div className="setting-row">
          <span className="setting-label">Save Current Config</span>
          <button className="btn" style={{ padding: "3px 10px", fontSize: 11 }} onClick={handleSaveConfig}>
            Save
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
