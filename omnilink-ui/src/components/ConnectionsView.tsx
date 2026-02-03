import { useState } from "react";
import type { Session } from "../types";

const MOCK_SESSIONS: Session[] = [
  {
    id: 1,
    status: "active",
    process_name: "chrome.exe",
    destination: "google.com:443",
    proxy_name: "my-socks5",
    action: "proxy:my-socks5",
    bytes_sent: 15420,
    bytes_received: 128300,
    elapsed_ms: 5200,
  },
  {
    id: 2,
    status: "active",
    process_name: "firefox",
    destination: "github.com:443",
    proxy_name: null,
    action: "direct",
    bytes_sent: 8100,
    bytes_received: 45600,
    elapsed_ms: 3100,
  },
  {
    id: 3,
    status: "closed",
    process_name: "curl",
    destination: "api.example.com:443",
    proxy_name: "my-socks5",
    action: "proxy:my-socks5",
    bytes_sent: 512,
    bytes_received: 2048,
    elapsed_ms: 1500,
  },
  {
    id: 4,
    status: "connecting",
    process_name: "docker",
    destination: "registry.docker.io:443",
    proxy_name: "my-socks5",
    action: "proxy:my-socks5",
    bytes_sent: 0,
    bytes_received: 0,
    elapsed_ms: 100,
  },
];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function getActionBadge(action: string): string {
  if (action === "direct") return "badge-direct";
  if (action.startsWith("proxy:")) return "badge-proxy";
  if (action === "block") return "badge-block";
  return "";
}

function getStatusBadge(status: string): string {
  switch (status) {
    case "active": return "badge-active";
    case "closed": return "badge-closed";
    case "connecting": return "badge-connecting";
    default: return "";
  }
}

function ConnectionsView() {
  const [sessions] = useState<Session[]>(MOCK_SESSIONS);

  if (sessions.length === 0) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">No connections</div>
        <div className="empty-state-desc">Start the service to see active connections</div>
      </div>
    );
  }

  return (
    <table className="connection-list">
      <thead>
        <tr>
          <th>#</th>
          <th>Status</th>
          <th>Process</th>
          <th>Destination</th>
          <th>Action</th>
          <th>Sent</th>
          <th>Received</th>
          <th>Duration</th>
        </tr>
      </thead>
      <tbody>
        {sessions.map((session) => (
          <tr key={session.id}>
            <td>{session.id}</td>
            <td>
              <span className={`badge ${getStatusBadge(session.status)}`}>
                {session.status}
              </span>
            </td>
            <td>{session.process_name ?? "-"}</td>
            <td>{session.destination}</td>
            <td>
              <span className={`badge ${getActionBadge(session.action)}`}>
                {session.action}
              </span>
            </td>
            <td>{formatBytes(session.bytes_sent)}</td>
            <td>{formatBytes(session.bytes_received)}</td>
            <td>{formatDuration(session.elapsed_ms)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default ConnectionsView;
