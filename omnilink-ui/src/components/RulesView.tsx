import { useState } from "react";

interface RuleDisplay {
  name: string;
  conditions: string[];
  action: string;
  priority: number;
}

const MOCK_RULES: RuleDisplay[] = [
  {
    name: "Block Ads",
    conditions: ["domain: *.ads.example.com", "domain: *.tracking.com"],
    action: "Block",
    priority: 100,
  },
  {
    name: "Proxy Private Networks",
    conditions: ["cidr: 10.0.0.0/8"],
    action: "Proxy: my-socks5",
    priority: 50,
  },
  {
    name: "Direct Local",
    conditions: ["cidr: 192.168.0.0/16", "cidr: 172.16.0.0/12"],
    action: "Direct",
    priority: 50,
  },
  {
    name: "Proxy Chrome Traffic",
    conditions: ["process: chrome*", "port_range: 443"],
    action: "Proxy: my-socks5",
    priority: 30,
  },
];

function RulesView() {
  const [rules] = useState<RuleDisplay[]>(MOCK_RULES);

  return (
    <div className="rules-panel">
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <h3 style={{ fontSize: 16, fontWeight: 600 }}>Routing Rules</h3>
        <button className="btn btn-primary">Add Rule</button>
      </div>

      {rules.map((rule) => (
        <div className="rule-card" key={rule.name}>
          <div className="rule-card-header">
            <span className="rule-card-name">{rule.name}</span>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className={`badge ${
                rule.action === "Block" ? "badge-block" :
                rule.action === "Direct" ? "badge-direct" : "badge-proxy"
              }`}>
                {rule.action}
              </span>
              <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                Priority: {rule.priority}
              </span>
            </div>
          </div>
          <div className="rule-card-conditions">
            {rule.conditions.map((cond, i) => (
              <span className="condition-tag" key={i}>{cond}</span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export default RulesView;
