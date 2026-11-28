pub mod app;
pub mod core;

pub use app::{
    AppSetupOptions, AppState, build_app, build_app_with_options, build_app_with_state,
    configure_builder, configure_builder_with_options, configure_builder_with_state,
    prepare_runtime_environment, run_app,
};

/// Desktop and mobile Tauri application entry point.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    prepare_runtime_environment();

    if let Err(err) = run_app() {
        eprintln!("BulkHash failed to start: {err}");
        std::process::exit(1);
    }
}
