import { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

interface BandwidthSample {
  sent_bps: number;
  recv_bps: number;
}

interface ProxyTraffic {
  proxy_name: string;
  bytes_sent: number;
  bytes_received: number;
  connection_count: number;
  error_count: number;
}

interface DomainTraffic {
  domain: string;
  bytes_sent: number;
  bytes_received: number;
  connection_count: number;
}

interface StatsSnapshot {
  total_sent: number;
  total_received: number;
  total_connections: number;
  active_connections: number;
  top_proxies: ProxyTraffic[];
  top_domains: DomainTraffic[];
  bandwidth_history: BandwidthSample[];
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec} B/s`;
  if (bytesPerSec < 1024 * 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${(bytesPerSec / (1024 * 1024)).toFixed(1)} MB/s`;
}

function BandwidthGraph({ history }: { history: BandwidthSample[] }) {
  const width = 600;
  const height = 120;
  const padding = { top: 10, right: 10, bottom: 20, left: 50 };
  const graphW = width - padding.left - padding.right;
  const graphH = height - padding.top - padding.bottom;

  if (history.length === 0) {
    return (
      <div style={{ textAlign: "center", padding: 20, color: "var(--text-secondary)", fontSize: 12 }}>
        No bandwidth data yet. Start the service to see traffic.
      </div>
    );
  }

  const maxVal = Math.max(
    1024,
    ...history.map((s) => Math.max(s.sent_bps, s.recv_bps))
  );

  const stepX = graphW / Math.max(history.length - 1, 1);

  const toPath = (data: number[]): string => {
    return data
      .map((v, i) => {
        const x = padding.left + i * stepX;
        const y = padding.top + graphH - (v / maxVal) * graphH;
        return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(" ");
  };

  const toArea = (data: number[]): string => {
    const linePath = toPath(data);
    const lastX = padding.left + (data.length - 1) * stepX;
    const baseY = padding.top + graphH;
    return `${linePath} L ${lastX.toFixed(1)} ${baseY} L ${padding.left} ${baseY} Z`;
  };

  const sentData = history.map((s) => s.sent_bps);
  const recvData = history.map((s) => s.recv_bps);

  // Y-axis labels
  const yLabels = [0, maxVal / 2, maxVal].map((v) => ({
    value: v,
    y: padding.top + graphH - (v / maxVal) * graphH,
    label: formatRate(v),
  }));

  const currentSent = history.length > 0 ? history[history.length - 1].sent_bps : 0;
  const currentRecv = history.length > 0 ? history[history.length - 1].recv_bps : 0;

  return (
    <div>
      <div style={{ display: "flex", gap: 16, marginBottom: 8, fontSize: 11, color: "var(--text-secondary)" }}>
        <span>
          <span style={{ color: "#e94560", fontWeight: 600 }}>--- Upload:</span> {formatRate(currentSent)}
        </span>
        <span>
          <span style={{ color: "#4ecdc4", fontWeight: 600 }}>--- Download:</span> {formatRate(currentRecv)}
        </span>
      </div>
      <svg width={width} height={height} style={{ width: "100%", height: "auto" }} viewBox={`0 0 ${width} ${height}`}>
        {/* Grid lines */}
        {yLabels.map((yl, i) => (
          <g key={i}>
            <line
              x1={padding.left} y1={yl.y}
              x2={width - padding.right} y2={yl.y}
              stroke="var(--border)" strokeWidth="0.5" strokeDasharray="4,4"
            />
            <text x={padding.left - 4} y={yl.y + 3} textAnchor="end" fill="var(--text-secondary)" fontSize="9">
              {yl.label}
            </text>
          </g>
        ))}

        {/* Upload area + line */}
        <path d={toArea(sentData)} fill="rgba(233, 69, 96, 0.15)" />
        <path d={toPath(sentData)} fill="none" stroke="#e94560" strokeWidth="1.5" />

        {/* Download area + line */}
        <path d={toArea(recvData)} fill="rgba(78, 205, 196, 0.15)" />
        <path d={toPath(recvData)} fill="none" stroke="#4ecdc4" strokeWidth="1.5" />

        {/* X-axis */}
        <line
          x1={padding.left} y1={padding.top + graphH}
          x2={width - padding.right} y2={padding.top + graphH}
          stroke="var(--border)" strokeWidth="1"
        />
        <text x={padding.left} y={height - 2} fill="var(--text-secondary)" fontSize="9">
          -{history.length}s
        </text>
        <text x={width - padding.right} y={height - 2} textAnchor="end" fill="var(--text-secondary)" fontSize="9">
          now
        </text>
      </svg>
    </div>
  );
}

function TrafficView() {
  const [stats, setStats] = useState<StatsSnapshot | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      const data = await invoke<StatsSnapshot>("get_traffic_stats");
      setStats(data);
    } catch (e) {
      console.error("Failed to fetch traffic stats:", e);
    }
  }, []);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 1000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  if (!stats) {
    return (
      <div className="empty-state">
        <div className="empty-state-desc">Loading traffic data...</div>
      </div>
    );
  }

  return (
    <div className="settings-panel">
      <div className="setting-group">
        <h3>Bandwidth</h3>
        <BandwidthGraph history={stats.bandwidth_history} />
      </div>

      <div className="setting-group">
        <h3>Summary</h3>
        <div className="setting-row">
          <span className="setting-label">Total Sent</span>
          <span className="setting-value">{formatBytes(stats.total_sent)}</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Total Received</span>
          <span className="setting-value">{formatBytes(stats.total_received)}</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Total Connections</span>
          <span className="setting-value">{stats.total_connections}</span>
        </div>
        <div className="setting-row">
          <span className="setting-label">Active Connections</span>
          <span className="setting-value">{stats.active_connections}</span>
        </div>
      </div>

      {stats.top_proxies.length > 0 && (
        <div className="setting-group">
          <h3>Top Proxies</h3>
          {stats.top_proxies.map((p) => (
            <div className="setting-row" key={p.proxy_name}>
              <span className="setting-label">{p.proxy_name}</span>
              <span className="setting-value" style={{ fontSize: 11 }}>
                {formatBytes(p.bytes_sent + p.bytes_received)} | {p.connection_count} conn
                {p.error_count > 0 && (
                  <span style={{ color: "var(--error)", marginLeft: 6 }}>{p.error_count} err</span>
                )}
              </span>
            </div>
          ))}
        </div>
      )}

      {stats.top_domains.length > 0 && (
        <div className="setting-group">
          <h3>Top Domains</h3>
          {stats.top_domains.map((d) => (
            <div className="setting-row" key={d.domain}>
              <span className="setting-label" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis" }}>
                {d.domain}
              </span>
              <span className="setting-value" style={{ fontSize: 11 }}>
                {formatBytes(d.bytes_sent + d.bytes_received)} | {d.connection_count} conn
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default TrafficView;
