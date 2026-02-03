import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

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
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<AddRuleForm>(emptyForm);

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
      console.error("Failed to toggle rule:", e);
    }
  };

  const handleDelete = async (index: number) => {
    try {
      await invoke("delete_rule", { index });
      await fetchRules();
    } catch (e) {
      console.error("Failed to delete rule:", e);
    }
  };

  const handleAdd = async () => {
    if (!form.name || !form.conditionValue) return;

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
      console.error("Failed to add rule:", e);
    }
  };

  return (
    <div className="rules-panel">
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <h3 style={{ fontSize: 16, fontWeight: 600 }}>Routing Rules</h3>
        <button className="btn btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? "Cancel" : "Add Rule"}
        </button>
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
    </div>
  );
}

export default RulesView;
