use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: u64,
    pub status: String,
    pub process_name: Option<String>,
    pub destination: String,
    pub action: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub elapsed_ms: u64,
}

#[tauri::command]
fn get_sessions() -> Vec<SessionInfo> {
    // Placeholder: will connect to the core engine
    vec![]
}

#[tauri::command]
fn get_status() -> String {
    "stopped".to_string()
}

#[tauri::command]
fn start_service() -> Result<String, String> {
    Ok("Service started".to_string())
}

#[tauri::command]
fn stop_service() -> Result<String, String> {
    Ok("Service stopped".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_sessions,
            get_status,
            start_service,
            stop_service,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
