pub mod commands;
pub mod info;
pub mod state;

pub use info::{
    AlgorithmDescriptor, AppDirectories, AppIdentity, AppInfo, AppStatus,
    CompressionPresetDescriptor, DEFAULT_APP_IDENTIFIER, FormatCapabilities, MAIN_WINDOW_LABEL,
    PlatformInfo, SNAPSHOT_FILE_EXTENSION, WEBKIT_DMABUF_ENV_VAR,
};
pub use state::{
    ActiveScanGuard, ActiveScanSummary, AppState, LoadedSnapshotSummary, ScanJobKind,
};

use crate::core::io::bulk_hash_error::BulkHashError;
use tauri::Manager;

/// Startup behavior options for [`configure_builder_with_options`] and [`build_app_with_options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppSetupOptions {
    /// Whether `.setup()` should proactively create `config_dir` and `data_dir` on disk.
    pub ensure_base_directories: bool,
}

impl Default for AppSetupOptions {
    fn default() -> Self {
        Self {
            ensure_base_directories: true,
        }
    }
}

/// Applies platform-specific runtime environment safeguards prior to starting the Tauri webview.
///
/// Must be called from the main thread before spawning worker threads or initializing Tauri.
pub fn prepare_runtime_environment() {
    #[cfg(target_os = "linux")]
    {
        let wayland_active =
            std::env::var_os("WAYLAND_DISPLAY").is_some_and(|value| !value.is_empty());
        let user_override = std::env::var_os(WEBKIT_DMABUF_ENV_VAR).is_some();

        if wayland_active && !user_override {
            // SAFETY: Called at process startup on the main thread before any worker threads
            // or webview runtimes are spawned.
            unsafe {
                std::env::set_var(WEBKIT_DMABUF_ENV_VAR, "1");
            }
        }
    }
}

/// Configures a [`tauri::Builder`] with `BulkHash`'s plugins, managed [`AppState`], startup hook,
/// window lifecycle handler, and IPC command router.
#[must_use]
pub fn configure_builder<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
    configure_builder_with_state(builder, AppState::new())
}

/// Configures a [`tauri::Builder`] using a pre-constructed [`AppState`] instance and default
/// [`AppSetupOptions`].
///
/// Useful for tests and future CLI/startup-argument bootstrapping that pre-populate state prior
/// to building the Tauri application.
#[must_use]
pub fn configure_builder_with_state<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    state: AppState,
) -> tauri::Builder<R> {
    configure_builder_with_options(builder, state, AppSetupOptions::default())
}

/// Configures a [`tauri::Builder`] with explicit [`AppState`] and [`AppSetupOptions`].
#[must_use]
pub fn configure_builder_with_options<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    state: AppState,
    options: AppSetupOptions,
) -> tauri::Builder<R> {
    builder
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .setup(move |app| setup_app(app, options))
        .on_window_event(handle_window_event)
        .invoke_handler(tauri::generate_handler![
            commands::ping,
            commands::get_app_info,
            commands::get_app_status,
        ])
}

/// Builds a configured `BulkHash` Tauri [`tauri::App`] without entering the blocking event loop.
///
/// # Errors
///
/// Returns [`BulkHashError::TauriError`] if Tauri fails to initialize plugins, setup hooks, or
/// runtime resources.
pub fn build_app<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    context: tauri::Context<R>,
) -> Result<tauri::App<R>, BulkHashError> {
    build_app_with_options(builder, context, AppState::new(), AppSetupOptions::default())
}

/// Builds a configured `BulkHash` Tauri [`tauri::App`] with a custom initial [`AppState`].
///
/// # Errors
///
/// Returns [`BulkHashError::TauriError`] if Tauri fails to initialize plugins, setup hooks, or
/// runtime resources.
pub fn build_app_with_state<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    context: tauri::Context<R>,
    state: AppState,
) -> Result<tauri::App<R>, BulkHashError> {
    build_app_with_options(builder, context, state, AppSetupOptions::default())
}

/// Builds a configured `BulkHash` Tauri [`tauri::App`] with explicit [`AppState`] and
/// [`AppSetupOptions`].
///
/// # Errors
///
/// Returns [`BulkHashError::TauriError`] if Tauri fails to initialize plugins, setup hooks, or
/// runtime resources.
pub fn build_app_with_options<R: tauri::Runtime>(
    builder: tauri::Builder<R>,
    context: tauri::Context<R>,
    state: AppState,
    options: AppSetupOptions,
) -> Result<tauri::App<R>, BulkHashError> {
    Ok(configure_builder_with_options(builder, state, options).build(context)?)
}

/// Builds and runs the `BulkHash` desktop application event loop until exit.
///
/// # Errors
///
/// Returns [`BulkHashError::TauriError`] if the Tauri desktop runtime cannot be built.
pub fn run_app() -> Result<(), BulkHashError> {
    let app = build_app(tauri::Builder::default(), tauri::generate_context!())?;
    app.run(|app_handle, event| handle_run_event(app_handle, &event));
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn setup_app<R: tauri::Runtime>(
    app: &mut tauri::App<R>,
    options: AppSetupOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let identity = AppIdentity::from_tauri(app.package_info(), app.config());
    let directories = AppDirectories::resolve_from_path_resolver(app.path());

    if options.ensure_base_directories {
        for (dir_name, err) in directories.ensure_base_directories() {
            eprintln!("Warning: could not initialize BulkHash {dir_name}: {err}");
        }
    }

    app.state::<AppState>()
        .mark_initialized(identity, directories);

    Ok(())
}

fn handle_window_event<R: tauri::Runtime>(window: &tauri::Window<R>, event: &tauri::WindowEvent) {
    if window.label() != MAIN_WINDOW_LABEL {
        return;
    }

    if matches!(
        event,
        tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
    ) {
        let _ = window.app_handle().state::<AppState>().begin_shutdown();
    }
}

/// Handles Tauri application run-loop lifecycle events (`ExitRequested`, `Exit`) to ensure
/// graceful shutdown of all active scans.
pub fn handle_run_event<R: tauri::Runtime>(
    app_handle: &tauri::AppHandle<R>,
    event: &tauri::RunEvent,
) {
    if matches!(
        event,
        tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit
    ) {
        let _ = app_handle.state::<AppState>().begin_shutdown();
    }
}
