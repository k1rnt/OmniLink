import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useToast } from "../hooks/useToast";
import type { Session } from "../types";

type FilterMode = "all" | "active" | "closed";

const MAX_RENDERED_ROWS = 200;

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

interface ContextMenuState {
  visible: boolean;
  x: number;
  y: number;
  session: Session | null;
}

function ConnectionsView() {
  const { error: showError } = useToast();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [contextMenu, setContextMenu] = useState<ContextMenuState>({
    visible: false, x: 0, y: 0, session: null,
  });
  const sessionsRef = useRef(sessions);
  sessionsRef.current = sessions;

  const fetchSessions = useCallback(async () => {
    try {
      const data = await invoke<Session[]>("get_sessions");
      setSessions(data);
    } catch (e) {
      showError(`Failed to fetch sessions: ${e}`);
    }
  }, []);

  useEffect(() => {
    fetchSessions();
    const interval = setInterval(fetchSessions, 1000);
    return () => clearInterval(interval);
  }, [fetchSessions]);

  const filteredSessions = useMemo(() => {
    const filtered = sessions.filter((s) => {
      if (filter === "active" && s.status !== "active" && s.status !== "connecting") return false;
      if (filter === "closed" && s.status !== "closed") return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          (s.process_name?.toLowerCase().includes(q) ?? false) ||
          s.destination.toLowerCase().includes(q) ||
          s.action.toLowerCase().includes(q)
        );
      }
      return true;
    });
    return filtered;
  }, [sessions, filter, searchQuery]);

  const displayedSessions = useMemo(
    () => filteredSessions.slice(0, MAX_RENDERED_ROWS),
    [filteredSessions]
  );

  const handleContextMenu = useCallback((e: React.MouseEvent, session: Session) => {
    e.preventDefault();
    setContextMenu({ visible: true, x: e.clientX, y: e.clientY, session });
  }, []);

  const closeContextMenu = useCallback(() => {
    setContextMenu((prev) => ({ ...prev, visible: false }));
  }, []);

  const handleCreateRule = useCallback(async () => {
    if (contextMenu.session) {
      const s = contextMenu.session;
      const [host] = s.destination.split(":");
      try {
        await invoke("add_rule", {
          req: {
            name: `rule-${host}`,
            conditions: [{ type: "domain", value: host }],
            action: s.action.startsWith("proxy:") ? "proxy" : s.action,
            proxy_name: s.action.startsWith("proxy:") ? s.action.replace("proxy:", "") : null,
            priority: 100,
          },
        });
      } catch (e) {
        showError(`Failed to create rule: ${e}`);
      }
    }
    closeContextMenu();
  }, [contextMenu.session, closeContextMenu]);

  const handleTerminate = useCallback(async () => {
    if (contextMenu.session) {
      try {
        await invoke("terminate_session", { sessionId: contextMenu.session.id });
      } catch (e) {
        showError(`Failed to terminate session: ${e}`);
      }
    }
    closeContextMenu();
  }, [contextMenu.session, closeContextMenu]);

  const handleCopyDest = useCallback(() => {
    if (contextMenu.session) {
      navigator.clipboard.writeText(contextMenu.session.destination);
    }
    closeContextMenu();
  }, [contextMenu.session, closeContextMenu]);

  const handleClearClosed = useCallback(async () => {
    try {
      await invoke("clear_closed_sessions");
      await fetchSessions();
    } catch (e) {
      showError(`Failed to clear sessions: ${e}`);
    }
  }, [fetchSessions]);

  const totalSent = useMemo(() => sessions.reduce((a, s) => a + s.bytes_sent, 0), [sessions]);
  const totalRecv = useMemo(() => sessions.reduce((a, s) => a + s.bytes_received, 0), [sessions]);

  return (
    <div onClick={closeContextMenu}>
      <div className="connection-toolbar">
        <div className="filter-buttons">
          {(["all", "active", "closed"] as FilterMode[]).map((f) => (
            <button
              key={f}
              className={`btn ${filter === f ? "btn-primary" : ""}`}
              onClick={() => setFilter(f)}
            >
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
          <button className="btn" onClick={handleClearClosed} title="Remove all closed connections">
            Clear Closed
          </button>
        </div>
        <input
          className="search-input"
          type="text"
          placeholder="Filter by process, host, or action..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
        <div className="traffic-summary">
          {filteredSessions.length !== sessions.length && (
            <span>{filteredSessions.length} / </span>
          )}
          {sessions.length} conn | Sent: {formatBytes(totalSent)} | Recv: {formatBytes(totalRecv)}
        </div>
      </div>

      {filteredSessions.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-title">No connections</div>
          <div className="empty-state-desc">
            {searchQuery ? "No connections match your filter" : "Start the service to see active connections"}
          </div>
        </div>
      ) : (
        <>
          <div style={{ maxHeight: "calc(100vh - 180px)", overflowY: "auto" }}>
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
                {displayedSessions.map((session) => (
                  <tr
                    key={session.id}
                    onContextMenu={(e) => handleContextMenu(e, session)}
                  >
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
          </div>
          {filteredSessions.length > MAX_RENDERED_ROWS && (
            <div style={{ textAlign: "center", padding: "8px", color: "var(--text-secondary)", fontSize: 12 }}>
              Showing {MAX_RENDERED_ROWS} of {filteredSessions.length} connections
            </div>
          )}
        </>
      )}

      {contextMenu.visible && contextMenu.session && (
        <div
          className="context-menu"
          style={{ top: contextMenu.y, left: contextMenu.x }}
        >
          <button className="context-menu-item" onClick={handleCreateRule}>
            Create Rule from Connection
          </button>
          <button className="context-menu-item" onClick={handleCopyDest}>
            Copy Destination
          </button>
          <div className="context-menu-divider" />
          <button className="context-menu-item context-menu-danger" onClick={handleTerminate}>
            Terminate Connection
          </button>
        </div>
      )}
    </div>
  );
}

export default ConnectionsView;
