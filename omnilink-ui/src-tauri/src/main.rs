#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // When launched as root with --pf-helper, run the privileged DIOCNATLOOK
    // server instead of the full Tauri app. This is invoked by osascript during
    // pf interceptor setup.
    #[cfg(target_os = "macos")]
    if std::env::args().any(|a| a == "--pf-helper") {
        omnilink_tun::run_pf_helper();
        return;
    }

    omnilink_tauri_lib::run();
}
