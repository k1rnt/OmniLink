import { useState } from "react";
import ConnectionsView from "./components/ConnectionsView";
import RulesView from "./components/RulesView";
import ProxiesView from "./components/ProxiesView";
import SettingsView from "./components/SettingsView";
import type { AppState } from "./types";

type Tab = "connections" | "rules" | "proxies" | "settings";

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("connections");
  const [appState, setAppState] = useState<AppState>({
    running: false,
    listen_addr: "127.0.0.1:1080",
    total_connections: 0,
    active_connections: 0,
    dns_mode: "fake_ip",
  });

  const toggleService = () => {
    setAppState((prev) => ({ ...prev, running: !prev.running }));
  };

  return (
    <div className="app-layout">
      <div className="toolbar" data-tauri-drag-region>
        <h1>OmniLink</h1>
        <div className="toolbar-actions">
          <div className="status-indicator">
            <span className={`status-dot ${appState.running ? "active" : ""}`} />
            {appState.running ? "Running" : "Stopped"}
          </div>
          <button className={`btn ${appState.running ? "" : "btn-primary"}`} onClick={toggleService}>
            {appState.running ? "Stop" : "Start"}
          </button>
        </div>
      </div>

      <div className="nav-tabs">
        {(["connections", "rules", "proxies", "settings"] as Tab[]).map((tab) => (
          <button
            key={tab}
            className={`nav-tab ${activeTab === tab ? "active" : ""}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      <div className="main-content">
        {activeTab === "connections" && <ConnectionsView />}
        {activeTab === "rules" && <RulesView />}
        {activeTab === "proxies" && <ProxiesView />}
        {activeTab === "settings" && <SettingsView state={appState} />}
      </div>

      <div className="status-bar">
        <span>Listen: {appState.listen_addr}</span>
        <span>Active: {appState.active_connections} | Total: {appState.total_connections}</span>
        <span>DNS: {appState.dns_mode}</span>
      </div>
    </div>
  );
}

export default App;
