export interface Session {
  id: number;
  status: "connecting" | "active" | "closed" | "error";
  process_name: string | null;
  destination: string;
  proxy_name: string | null;
  action: string;
  bytes_sent: number;
  bytes_received: number;
  elapsed_ms: number;
}

export interface ProxyServer {
  name: string;
  protocol: string;
  address: string;
  port: number;
  auth: boolean;
}

export interface Rule {
  name: string;
  conditions: Condition[];
  action: RuleAction;
  priority: number;
}

export type Condition =
  | { process_name: string }
  | { domain: string }
  | { cidr: string }
  | { port: number }
  | { port_range: [number, number] };

export type RuleAction =
  | "direct"
  | "block"
  | { proxy: string };

export interface AppState {
  running: boolean;
  listen_addr: string;
  total_connections: number;
  active_connections: number;
  dns_mode: string;
  pf_running: boolean;
}

export interface ApplicationInfo {
  name: string;
  bundle_id: string | null;
  executable_name: string;
  executable_path: string;
  icon_base64: string | null;
  version: string | null;
}
