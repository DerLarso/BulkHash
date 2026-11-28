use crate::app::{
    info::{AppInfo, AppStatus},
    state::AppState,
};

/// Lightweight IPC connectivity check for the desktop frontend.
#[tauri::command]
#[must_use]
pub const fn ping() -> &'static str {
    "pong"
}

/// Returns application identity, host platform info, supported hashing/format capabilities, and
/// resolved OS application directories.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn get_app_info(state: tauri::State<'_, AppState>) -> AppInfo {
    state.app_info()
}

/// Returns a live runtime status snapshot (initialization state, uptime, active scans, and
/// loaded snapshot sessions).
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn get_app_status(state: tauri::State<'_, AppState>) -> AppStatus {
    state.app_status()
}
