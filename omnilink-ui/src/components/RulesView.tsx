import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useToast } from "../hooks/useToast";
import type { ApplicationInfo } from "../types";

interface RuleInfo {
  index: number;
  name: string;
  conditions: string[];
  action: string;
  priority: number;
  enabled: boolean;
}

interface AddRuleForm {
  name: string;
  conditionType: string;
  conditionValue: string;
  action: string;
  proxyName: string;
  priority: number;
}

const emptyForm: AddRuleForm = {
  name: "",
  conditionType: "domain",
  conditionValue: "",
  action: "direct",
  proxyName: "",
  priority: 0,
};

function RulesView() {
  const { success, error: showError, warning } = useToast();
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<AddRuleForm>(emptyForm);
  const [showAppSelector, setShowAppSelector] = useState(false);
  const [apps, setApps] = useState<ApplicationInfo[]>([]);
  const [appSearchQuery, setAppSearchQuery] = useState("");

  const fetchRules = useCallback(async () => {
    try {
      const data = await invoke<RuleInfo[]>("get_rules");
      setRules(data);
    } catch (e) {
      console.error("Failed to fetch rules:", e);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const handleToggle = async (index: number) => {
    try {
      await invoke("toggle_rule", { index });
      await fetchRules();
    } catch (e) {
      showError(`Failed to toggle rule: ${e}`);
    }
  };

  const handleDelete = async (index: number) => {
    try {
      await invoke("delete_rule", { index });
      await fetchRules();
    } catch (e) {
      showError(`Failed to delete rule: ${e}`);
    }
  };

  const handleAdd = async () => {
    if (!form.name) {
      warning("Please enter a rule name");
      return;
    }
    if (!form.conditionValue) {
      warning("Please enter a condition value");
      return;
    }

    const condition = {
      type: form.conditionType,
      value: form.conditionType === "port"
        ? parseInt(form.conditionValue, 10)
        : form.conditionValue,
    };

    try {
      await invoke("add_rule", {
        req: {
          name: form.name,
          conditions: [condition],
          action: form.action,
          proxy_name: form.action === "proxy" ? form.proxyName : null,
          priority: form.priority,
        },
      });
      setForm(emptyForm);
      setShowForm(false);
      await fetchRules();
    } catch (e) {
      showError(`Failed to add rule: ${e}`);
    }
  };

  const handleExport = async () => {
    try {
      const yaml = await invoke<string>("export_rules_yaml");
      await navigator.clipboard.writeText(yaml);
      success("Rules exported to clipboard as YAML");
    } catch (e) {
      showError(`Export failed: ${e}`);
    }
  };

  const openAppSelector = async () => {
    try {
      const result = await invoke<ApplicationInfo[]>("list_installed_apps");
      setApps(result);
      setShowAppSelector(true);
      setAppSearchQuery("");
    } catch (e) {
      showError(`Failed to load apps: ${e}`);
    }
  };

  const selectApp = (app: ApplicationInfo) => {
    setForm({
      ...form,
      conditionType: "process_name",
      conditionValue: app.executable_name,
      name: form.name || `Rule: ${app.name}`,
    });
    setShowAppSelector(false);
  };

  const filteredApps = apps.filter(
    (app) =>
      app.name.toLowerCase().includes(appSearchQuery.toLowerCase()) ||
      app.executable_name.toLowerCase().includes(appSearchQuery.toLowerCase())
  );

  return (
    <div className="rules-panel">
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <h3 style={{ fontSize: 16, fontWeight: 600 }}>Routing Rules</h3>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn" onClick={handleExport}>
            Export YAML
          </button>
          <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
            {showForm ? "Cancel" : "Add Rule"}
          </button>
        </div>
      </div>

      {showForm && (
        <div className="rule-card" style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="search-input"
                placeholder="Rule name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                style={{ flex: 1 }}
              />
              <input
                className="search-input"
                type="number"
                placeholder="Priority"
                value={form.priority}
                onChange={(e) => setForm({ ...form, priority: parseInt(e.target.value, 10) || 0 })}
                style={{ width: 80 }}
              />
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <select
                className="search-input"
                value={form.conditionType}
                onChange={(e) => setForm({ ...form, conditionType: e.target.value })}
                style={{ width: 140 }}
              >
                <option value="domain">Domain</option>
                <option value="cidr">CIDR</option>
                <option value="port">Port</option>
                <option value="process_name">Process Name</option>
              </select>
              <input
                className="search-input"
                placeholder="Value (e.g. *.example.com)"
                value={form.conditionValue}
                onChange={(e) => setForm({ ...form, conditionValue: e.target.value })}
                style={{ flex: 1 }}
              />
              {form.conditionType === "process_name" && (
                <button className="btn" onClick={openAppSelector} style={{ whiteSpace: "nowrap" }}>
                  Select App
                </button>
              )}
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <select
                className="search-input"
                value={form.action}
                onChange={(e) => setForm({ ...form, action: e.target.value })}
                style={{ width: 120 }}
              >
                <option value="direct">Direct</option>
                <option value="proxy">Proxy</option>
                <option value="block">Block</option>
              </select>
              {form.action === "proxy" && (
                <input
                  className="search-input"
                  placeholder="Proxy name"
                  value={form.proxyName}
                  onChange={(e) => setForm({ ...form, proxyName: e.target.value })}
                  style={{ width: 160 }}
                />
              )}
              <button className="btn btn-primary" onClick={handleAdd} style={{ marginLeft: "auto" }}>
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {rules.length === 0 ? (
        <div className="empty-state" style={{ height: 200 }}>
          <div className="empty-state-title">No rules configured</div>
          <div className="empty-state-desc">Load a configuration or add rules manually</div>
        </div>
      ) : (
        rules.map((rule) => (
          <div className="rule-card" key={rule.index} style={{ opacity: rule.enabled ? 1 : 0.5 }}>
            <div className="rule-card-header">
              <span className="rule-card-name">{rule.name}</span>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span
                  className={`badge ${
                    rule.action === "Block"
                      ? "badge-block"
                      : rule.action === "Direct"
                        ? "badge-direct"
                        : "badge-proxy"
                  }`}
                >
                  {rule.action}
                </span>
                <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                  P:{rule.priority}
                </span>
                <button
                  className="btn"
                  style={{ padding: "2px 8px", fontSize: 11 }}
                  onClick={() => handleToggle(rule.index)}
                >
                  {rule.enabled ? "Disable" : "Enable"}
                </button>
                <button
                  className="btn"
                  style={{ padding: "2px 8px", fontSize: 11, color: "var(--error)" }}
                  onClick={() => handleDelete(rule.index)}
                >
                  Delete
                </button>
              </div>
            </div>
            <div className="rule-card-conditions">
              {rule.conditions.map((cond, i) => (
                <span className="condition-tag" key={i}>
                  {cond}
                </span>
              ))}
            </div>
          </div>
        ))
      )}

      {/* App Selector Modal */}
      {showAppSelector && (
        <div className="modal-overlay" onClick={() => setShowAppSelector(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxHeight: "70vh", display: "flex", flexDirection: "column" }}>
            <h3>Select Application</h3>
            <input
              type="text"
              className="search-input"
              placeholder="Search apps..."
              value={appSearchQuery}
              onChange={(e) => setAppSearchQuery(e.target.value)}
              style={{ marginBottom: 12, width: "100%" }}
            />
            <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
              {filteredApps.map((app) => (
                <div
                  key={app.executable_path}
                  className="app-selector-item"
                  onClick={() => selectApp(app)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: "8px 12px",
                    background: "var(--bg-primary)",
                    borderRadius: 4,
                    cursor: "pointer",
                  }}
                >
                  <div style={{ width: 32, height: 32, display: "flex", alignItems: "center", justifyContent: "center" }}>
                    {app.icon_base64 ? (
                      <img src={`data:image/png;base64,${app.icon_base64}`} alt="" style={{ width: 32, height: 32 }} />
                    ) : (
                      <div style={{ width: 32, height: 32, background: "var(--bg-tertiary)", borderRadius: 4, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14 }}>
                        {app.name.charAt(0)}
                      </div>
                    )}
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{app.name}</div>
                    <div style={{ fontSize: 11, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{app.executable_name}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className="modal-actions" style={{ marginTop: 12 }}>
              <button className="btn" onClick={() => setShowAppSelector(false)}>
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default RulesView;
