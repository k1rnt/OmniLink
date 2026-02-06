import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import ConnectionsView from "./components/ConnectionsView";
import RulesView from "./components/RulesView";
import ProxiesView from "./components/ProxiesView";
import SettingsView from "./components/SettingsView";
import TrafficView from "./components/TrafficView";
import AppsView from "./components/AppsView";
import UpdateNotification from "./components/UpdateNotification";
import type { AppState } from "./types";

type Tab = "connections" | "rules" | "apps" | "proxies" | "traffic" | "settings";

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("connections");
  const [appState, setAppState] = useState<AppState>({
    running: false,
    listen_addr: "127.0.0.1:1080",
    total_connections: 0,
    active_connections: 0,
    dns_mode: "FakeIp",
  });

  const fetchStatus = useCallback(async () => {
    try {
      const status = await invoke<AppState & { total_sent: number; total_received: number }>("get_status");
      setAppState({
        running: status.running,
        listen_addr: status.listen_addr,
        total_connections: status.total_connections,
        active_connections: status.active_connections,
        dns_mode: status.dns_mode,
      });
    } catch (e) {
      console.error("Failed to fetch status:", e);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 2000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const toggleService = async () => {
    try {
      if (appState.running) {
        await invoke("stop_service");
      } else {
        await invoke("start_service");
      }
      await fetchStatus();
    } catch (e) {
      alert(`Service error: ${e}`);
    }
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
        {(["connections", "rules", "apps", "proxies", "traffic", "settings"] as Tab[]).map((tab) => (
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
        {activeTab === "apps" && <AppsView />}
        {activeTab === "proxies" && <ProxiesView />}
        {activeTab === "traffic" && <TrafficView />}
        {activeTab === "settings" && <SettingsView state={appState} />}
      </div>

      <div className="status-bar">
        <span>Listen: {appState.listen_addr}</span>
        <span>Active: {appState.active_connections} | Total: {appState.total_connections}</span>
        <span>DNS: {appState.dns_mode}</span>
      </div>

      <UpdateNotification />
    </div>
  );
}

export default App;
