import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { AppState } from "../types";

interface Props {
  state: AppState;
}

function SettingsView({ state }: Props) {
  const [sysproxyEnabled, setSysproxyEnabled] = useState(false);
  const [configPath, setConfigPath] = useState("");
  const [message, setMessage] = useState<string | null>(null);

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
  }, [fetchSysproxy]);

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
