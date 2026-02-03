use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use serde::Serialize;

use crate::rule::Action;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Status of a connection session.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Connecting,
    Active,
    Closed,
    Error(String),
}

/// A tracked connection session.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub id: u64,
    pub status: SessionStatus,
    pub process_name: Option<String>,
    pub destination: String,
    pub proxy_name: Option<String>,
    pub action: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    #[serde(skip)]
    pub started_at: Instant,
    pub elapsed_ms: u64,
}

impl Session {
    pub fn new(destination: String, action: &Action, proxy_name: Option<String>) -> Self {
        let action_str = match action {
            Action::Direct => "direct".to_string(),
            Action::Proxy(name) => format!("proxy:{}", name),
            Action::Block => "block".to_string(),
        };

        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            status: SessionStatus::Connecting,
            process_name: None,
            destination,
            proxy_name,
            action: action_str,
            bytes_sent: 0,
            bytes_received: 0,
            started_at: Instant::now(),
            elapsed_ms: 0,
        }
    }
}

/// Connection session manager for tracking active/historical connections.
pub struct SessionManager {
    sessions: Mutex<HashMap<u64, Session>>,
    max_history: usize,
}

impl SessionManager {
    pub fn new(max_history: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_history,
        }
    }

    pub fn create_session(
        &self,
        destination: String,
        action: &Action,
        proxy_name: Option<String>,
    ) -> u64 {
        let session = Session::new(destination, action, proxy_name);
        let id = session.id;
        self.sessions.lock().unwrap().insert(id, session);
        id
    }

    pub fn update_status(&self, id: u64, status: SessionStatus) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(&id) {
            session.status = status;
            session.elapsed_ms = session.started_at.elapsed().as_millis() as u64;
        }
    }

    pub fn update_bytes(&self, id: u64, sent: u64, received: u64) {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(&id) {
            session.bytes_sent += sent;
            session.bytes_received += received;
        }
    }

    pub fn get_sessions(&self) -> Vec<Session> {
        let mut sessions: Vec<Session> = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .map(|s| {
                let mut s = s.clone();
                s.elapsed_ms = s.started_at.elapsed().as_millis() as u64;
                s
            })
            .collect();
        sessions.sort_by(|a, b| b.id.cmp(&a.id));
        sessions
    }

    pub fn get_active_sessions(&self) -> Vec<Session> {
        self.get_sessions()
            .into_iter()
            .filter(|s| matches!(s.status, SessionStatus::Connecting | SessionStatus::Active))
            .collect()
    }

    pub fn cleanup_closed(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        let closed: Vec<u64> = sessions
            .iter()
            .filter(|(_, s)| matches!(s.status, SessionStatus::Closed | SessionStatus::Error(_)))
            .map(|(id, _)| *id)
            .collect();

        if closed.len() > self.max_history {
            let to_remove = closed.len() - self.max_history;
            for id in closed.into_iter().take(to_remove) {
                sessions.remove(&id);
            }
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(1000)
    }
}
