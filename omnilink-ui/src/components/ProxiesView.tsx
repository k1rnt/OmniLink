import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ProxyInfo {
  name: string;
  protocol: string;
  address: string;
  port: number;
  auth: boolean;
}

interface ChainInfo {
  name: string;
  proxies: string[];
  mode: string;
}

interface AddProxyForm {
  name: string;
  protocol: string;
  address: string;
  port: string;
  username: string;
  password: string;
}

interface AddChainForm {
  name: string;
  proxies: string;
  mode: string;
}

const emptyProxyForm: AddProxyForm = {
  name: "",
  protocol: "socks5",
  address: "",
  port: "1080",
  username: "",
  password: "",
};

const emptyChainForm: AddChainForm = {
  name: "",
  proxies: "",
  mode: "strict",
};

function ProxiesView() {
  const [proxies, setProxies] = useState<ProxyInfo[]>([]);
  const [chains, setChains] = useState<ChainInfo[]>([]);
  const [showProxyForm, setShowProxyForm] = useState(false);
  const [showChainForm, setShowChainForm] = useState(false);
  const [proxyForm, setProxyForm] = useState<AddProxyForm>(emptyProxyForm);
  const [chainForm, setChainForm] = useState<AddChainForm>(emptyChainForm);

  const fetchData = useCallback(async () => {
    try {
      const [p, c] = await Promise.all([
        invoke<ProxyInfo[]>("get_proxies"),
        invoke<ChainInfo[]>("get_chains"),
      ]);
      setProxies(p);
      setChains(c);
    } catch (e) {
      console.error("Failed to fetch proxy data:", e);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleAddProxy = async () => {
    if (!proxyForm.name || !proxyForm.address) return;
    try {
      await invoke("add_proxy", {
        req: {
          name: proxyForm.name,
          protocol: proxyForm.protocol,
          address: proxyForm.address,
          port: parseInt(proxyForm.port, 10) || 1080,
          username: proxyForm.username || null,
          password: proxyForm.password || null,
        },
      });
      setProxyForm(emptyProxyForm);
      setShowProxyForm(false);
      await fetchData();
    } catch (e) {
      console.error("Failed to add proxy:", e);
    }
  };

  const handleDeleteProxy = async (name: string) => {
    try {
      await invoke("delete_proxy", { name });
      await fetchData();
    } catch (e) {
      console.error("Failed to delete proxy:", e);
    }
  };

  const handleAddChain = async () => {
    if (!chainForm.name || !chainForm.proxies) return;
    try {
      await invoke("add_chain", {
        req: {
          name: chainForm.name,
          proxies: chainForm.proxies.split(",").map((s) => s.trim()).filter(Boolean),
          mode: chainForm.mode,
        },
      });
      setChainForm(emptyChainForm);
      setShowChainForm(false);
      await fetchData();
    } catch (e) {
      console.error("Failed to add chain:", e);
    }
  };

  const handleDeleteChain = async (name: string) => {
    try {
      await invoke("delete_chain", { name });
      await fetchData();
    } catch (e) {
      console.error("Failed to delete chain:", e);
    }
  };

  return (
    <div className="proxy-list">
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
        <h3 style={{ fontSize: 16, fontWeight: 600 }}>Proxy Servers</h3>
        <button className="btn btn-primary" onClick={() => setShowProxyForm(!showProxyForm)}>
          {showProxyForm ? "Cancel" : "Add Proxy"}
        </button>
      </div>

      {showProxyForm && (
        <div className="rule-card" style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="search-input"
                placeholder="Name"
                value={proxyForm.name}
                onChange={(e) => setProxyForm({ ...proxyForm, name: e.target.value })}
                style={{ flex: 1 }}
              />
              <select
                className="search-input"
                value={proxyForm.protocol}
                onChange={(e) => setProxyForm({ ...proxyForm, protocol: e.target.value })}
                style={{ width: 120 }}
              >
                <option value="socks5">SOCKS5</option>
                <option value="socks4">SOCKS4</option>
                <option value="socks4a">SOCKS4a</option>
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
                <option value="ssh_tunnel">SSH Tunnel</option>
              </select>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                className="search-input"
                placeholder="Address"
                value={proxyForm.address}
                onChange={(e) => setProxyForm({ ...proxyForm, address: e.target.value })}
                style={{ flex: 1 }}
              />
              <input
                className="search-input"
                placeholder="Port"
                value={proxyForm.port}
                onChange={(e) => setProxyForm({ ...proxyForm, port: e.target.value })}
                style={{ width: 80 }}
              />
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                className="search-input"
                placeholder="Username (optional)"
                value={proxyForm.username}
                onChange={(e) => setProxyForm({ ...proxyForm, username: e.target.value })}
                style={{ flex: 1 }}
              />
              <input
                className="search-input"
                type="password"
                placeholder="Password (optional)"
                value={proxyForm.password}
                onChange={(e) => setProxyForm({ ...proxyForm, password: e.target.value })}
                style={{ flex: 1 }}
              />
              <button className="btn btn-primary" onClick={handleAddProxy}>
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {proxies.length === 0 ? (
        <div className="empty-state" style={{ height: 120 }}>
          <div className="empty-state-desc">No proxy servers configured</div>
        </div>
      ) : (
        proxies.map((proxy) => (
          <div className="proxy-card" key={proxy.name}>
            <div className="proxy-info">
              <span className="proxy-name">{proxy.name}</span>
              <span className="proxy-addr">
                {proxy.address}:{proxy.port}
                {proxy.auth && " (auth)"}
              </span>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className="proxy-protocol">{proxy.protocol}</span>
              <button
                className="btn"
                style={{ padding: "2px 8px", fontSize: 11, color: "var(--error)" }}
                onClick={() => handleDeleteProxy(proxy.name)}
              >
                Delete
              </button>
            </div>
          </div>
        ))
      )}

      <div style={{ marginTop: 24 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
          <h3 style={{ fontSize: 16, fontWeight: 600 }}>Proxy Chains</h3>
          <button className="btn btn-primary" onClick={() => setShowChainForm(!showChainForm)}>
            {showChainForm ? "Cancel" : "Add Chain"}
          </button>
        </div>

        {showChainForm && (
          <div className="rule-card" style={{ marginBottom: 12 }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  className="search-input"
                  placeholder="Chain name"
                  value={chainForm.name}
                  onChange={(e) => setChainForm({ ...chainForm, name: e.target.value })}
                  style={{ flex: 1 }}
                />
                <select
                  className="search-input"
                  value={chainForm.mode}
                  onChange={(e) => setChainForm({ ...chainForm, mode: e.target.value })}
                  style={{ width: 140 }}
                >
                  <option value="strict">Strict</option>
                  <option value="failover">Failover</option>
                  <option value="round_robin">Round Robin</option>
                  <option value="random">Random</option>
                </select>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input
                  className="search-input"
                  placeholder="Proxy names (comma-separated)"
                  value={chainForm.proxies}
                  onChange={(e) => setChainForm({ ...chainForm, proxies: e.target.value })}
                  style={{ flex: 1 }}
                />
                <button className="btn btn-primary" onClick={handleAddChain}>
                  Save
                </button>
              </div>
            </div>
          </div>
        )}

        {chains.length === 0 ? (
          <div className="empty-state" style={{ height: 80 }}>
            <div className="empty-state-desc">No chains configured</div>
          </div>
        ) : (
          chains.map((chain) => (
            <div className="rule-card" key={chain.name}>
              <div className="rule-card-header">
                <span className="rule-card-name">{chain.name}</span>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: "var(--text-secondary)" }}>
                    {chain.mode}
                  </span>
                  <button
                    className="btn"
                    style={{ padding: "2px 8px", fontSize: 11, color: "var(--error)" }}
                    onClick={() => handleDeleteChain(chain.name)}
                  >
                    Delete
                  </button>
                </div>
              </div>
              <div className="rule-card-conditions">
                {chain.proxies.map((p, i) => (
                  <span key={i}>
                    <span className="condition-tag">{p}</span>
                    {i < chain.proxies.length - 1 && (
                      <span style={{ color: "var(--text-secondary)", margin: "0 4px" }}>&rarr;</span>
                    )}
                  </span>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default ProxiesView;
