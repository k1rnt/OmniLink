import { useState } from "react";

interface ProxyDisplay {
  name: string;
  protocol: string;
  address: string;
  port: number;
  hasAuth: boolean;
}

const MOCK_PROXIES: ProxyDisplay[] = [
  {
    name: "my-socks5",
    protocol: "SOCKS5",
    address: "proxy.example.com",
    port: 1080,
    hasAuth: true,
  },
  {
    name: "my-http",
    protocol: "HTTP",
    address: "httpproxy.example.com",
    port: 8080,
    hasAuth: false,
  },
];

function ProxiesView() {
  const [proxies] = useState<ProxyDisplay[]>(MOCK_PROXIES);

  return (
    <div className="proxy-list">
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <h3 style={{ fontSize: 16, fontWeight: 600 }}>Proxy Servers</h3>
        <button className="btn btn-primary">Add Proxy</button>
      </div>

      {proxies.map((proxy) => (
        <div className="proxy-card" key={proxy.name}>
          <div className="proxy-info">
            <span className="proxy-name">{proxy.name}</span>
            <span className="proxy-addr">
              {proxy.address}:{proxy.port}
              {proxy.hasAuth && " (auth)"}
            </span>
          </div>
          <span className="proxy-protocol">{proxy.protocol}</span>
        </div>
      ))}

      <div style={{ marginTop: 24 }}>
        <h3 style={{ fontSize: 16, fontWeight: 600, marginBottom: 12 }}>Proxy Chains</h3>
        <div className="rule-card">
          <div className="rule-card-header">
            <span className="rule-card-name">double-hop</span>
          </div>
          <div className="rule-card-conditions">
            <span className="condition-tag">my-socks5</span>
            <span style={{ color: "var(--text-secondary)", margin: "0 4px" }}>&rarr;</span>
            <span className="condition-tag">my-http</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ProxiesView;
