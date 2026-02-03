import type { AppState } from "../types";

interface Props {
  state: AppState;
}

function SettingsView({ state }: Props) {
  return (
    <div className="settings-panel">
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
        <h3>Logging</h3>
        <div className="setting-row">
          <span className="setting-label">Log Level</span>
          <span className="setting-value">info</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Log to File</span>
          <span className="setting-value">disabled</span>
        </div>
      </div>

      <div className="setting-group">
        <h3>Network Interception</h3>
        <div className="setting-row">
          <span className="setting-label">TUN Device</span>
          <span className="setting-value">omni0 (not active)</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">System Proxy</span>
          <span className="setting-value">disabled</span>
        </div>
      </div>
    </div>
  );
}

export default SettingsView;
