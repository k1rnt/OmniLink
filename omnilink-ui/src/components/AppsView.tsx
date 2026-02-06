import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { ApplicationInfo, ProxyServer } from "../types";

interface AppRuleConfig {
  action: "direct" | "proxy" | "block";
  proxyName?: string;
}

export default function AppsView() {
  const [apps, setApps] = useState<ApplicationInfo[]>([]);
  const [proxies, setProxies] = useState<ProxyServer[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedApp, setSelectedApp] = useState<ApplicationInfo | null>(null);
  const [appConfig, setAppConfig] = useState<AppRuleConfig>({ action: "direct" });

  const fetchApps = useCallback(async () => {
    setLoading(true);
    try {
      const result = await invoke<ApplicationInfo[]>("list_installed_apps");
      setApps(result);
    } catch (e) {
      console.error("Failed to fetch apps:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchProxies = useCallback(async () => {
    try {
      const result = await invoke<ProxyServer[]>("get_proxies");
      setProxies(result);
    } catch (e) {
      console.error("Failed to fetch proxies:", e);
    }
  }, []);

  useEffect(() => {
    fetchApps();
    fetchProxies();
  }, [fetchApps, fetchProxies]);

  const filteredApps = apps.filter(
    (app) =>
      app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      app.executable_name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleAppClick = (app: ApplicationInfo) => {
    setSelectedApp(app);
    setAppConfig({ action: "direct" });
  };

  const handleCreateRule = async () => {
    if (!selectedApp) return;

    try {
      const req = {
        name: `App: ${selectedApp.name}`,
        conditions: [{ type: "process_name", value: selectedApp.executable_name }],
        action: appConfig.action,
        proxy_name: appConfig.action === "proxy" ? appConfig.proxyName || null : null,
        priority: 50,
      };
      await invoke("add_rule", { req });
      setSelectedApp(null);
      alert(`Rule created for ${selectedApp.name}`);
    } catch (e) {
      console.error("Failed to create rule:", e);
      alert(`Failed to create rule: ${e}`);
    }
  };

  return (
    <div className="apps-view">
      <div className="apps-toolbar">
        <input
          type="text"
          placeholder="Search apps..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="search-input"
        />
        <button onClick={fetchApps} className="btn" disabled={loading}>
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {loading ? (
        <div className="loading-state">Loading installed applications...</div>
      ) : (
        <div className="apps-grid">
          {filteredApps.map((app) => (
            <div
              key={app.executable_path}
              className="app-card"
              onClick={() => handleAppClick(app)}
            >
              <div className="app-icon">
                {app.icon_base64 ? (
                  <img src={`data:image/png;base64,${app.icon_base64}`} alt={app.name} />
                ) : (
                  <div className="app-icon-placeholder">{app.name.charAt(0)}</div>
                )}
              </div>
              <div className="app-name" title={app.name}>
                {app.name}
              </div>
              <div className="app-exec" title={app.executable_name}>
                {app.executable_name}
              </div>
            </div>
          ))}
        </div>
      )}

      {filteredApps.length === 0 && !loading && (
        <div className="empty-state">No applications found</div>
      )}

      {/* Rule creation modal */}
      {selectedApp && (
        <div className="modal-overlay" onClick={() => setSelectedApp(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Create Rule for {selectedApp.name}</h3>
            <div className="modal-body">
              <div className="form-row">
                <label>Process Name:</label>
                <input type="text" value={selectedApp.executable_name} readOnly />
              </div>
              <div className="form-row">
                <label>Action:</label>
                <select
                  value={appConfig.action}
                  onChange={(e) =>
                    setAppConfig({ ...appConfig, action: e.target.value as AppRuleConfig["action"] })
                  }
                >
                  <option value="direct">Direct</option>
                  <option value="proxy">Proxy</option>
                  <option value="block">Block</option>
                </select>
              </div>
              {appConfig.action === "proxy" && (
                <div className="form-row">
                  <label>Proxy:</label>
                  <select
                    value={appConfig.proxyName || ""}
                    onChange={(e) => setAppConfig({ ...appConfig, proxyName: e.target.value })}
                  >
                    <option value="">Select proxy...</option>
                    {proxies.map((p) => (
                      <option key={p.name} value={p.name}>
                        {p.name} ({p.protocol})
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
            <div className="modal-actions">
              <button className="btn" onClick={() => setSelectedApp(null)}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={handleCreateRule}
                disabled={appConfig.action === "proxy" && !appConfig.proxyName}
              >
                Create Rule
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
