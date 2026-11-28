use bulk_hash_lib::{
    AppSetupOptions, AppState,
    app::{
        AppDirectories, AppIdentity, AppInfo, AppStatus, FormatCapabilities, MAIN_WINDOW_LABEL,
        PlatformInfo, SNAPSHOT_FILE_EXTENSION, ScanJobKind, build_app_with_options,
        handle_run_event,
    },
    core::{
        hash_manager::HashAlgorithm,
        io::{
            bulk_hash_error::BulkHashError,
            compression::{CompressionPreset, DEFAULT_COMPRESSION_LEVEL},
            directory_node::DirectoryNode,
            encryption::{EncryptionOptions, KdfParams},
            file_manager::FileManager,
            meta_data::MetaData,
            migration::{CURRENT_FORMAT_VERSION, MIN_SUPPORTED_FORMAT_VERSION},
        },
        scan_control::ScanControlState,
        scan_manager::ScanManager,
    },
};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::Manager;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "bulkhash_app_test_{prefix}_{}_{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp test dir");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn ipc_request(url: tauri::Url, cmd: &str) -> tauri::webview::InvokeRequest {
    tauri::webview::InvokeRequest {
        cmd: cmd.into(),
        callback: tauri::ipc::CallbackFn(0),
        error: tauri::ipc::CallbackFn(1),
        url,
        body: tauri::ipc::InvokeBody::default(),
        headers: tauri::http::HeaderMap::default(),
        invoke_key: tauri::test::INVOKE_KEY.to_string(),
    }
}

fn trusted_app_origin(config: &tauri::Config) -> tauri::Url {
    if cfg!(dev)
        && let Some(dev_url) = &config.build.dev_url
    {
        return dev_url.clone();
    }
    let origin = if cfg!(any(windows, target_os = "android")) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    };
    origin.parse().expect("valid tauri origin url")
}

fn run_mock_app_with_real_config<F>(state: AppState, on_ready: F)
where
    F: FnOnce(&tauri::AppHandle<tauri::test::MockRuntime>) + 'static,
{
    let webview_data_dir = TempDir::new("mock_webview_data");
    let mut context = tauri::generate_context!();
    // Defer window creation until `RunEvent::Ready` so we can point the webview `data_directory`
    // at an isolated temp directory while still building from the real `tauri.conf.json` window.
    for window in &mut context.config_mut().app.windows {
        window.create = false;
    }

    let app = build_app_with_options(
        tauri::test::mock_builder(),
        context,
        state,
        AppSetupOptions {
            ensure_base_directories: false,
        },
    )
    .expect("build mock BulkHash Tauri app");

    let ready_ran = Arc::new(AtomicBool::new(false));
    let ready_ran_cb = Arc::clone(&ready_ran);
    let data_dir_path = webview_data_dir.path().to_path_buf();
    let mut on_ready = Some(on_ready);

    let exit_code = app.run_return(move |app_handle, event| {
        handle_run_event(app_handle, &event);
        if matches!(event, tauri::RunEvent::Ready) {
            ready_ran_cb.store(true, Ordering::SeqCst);
            let main_cfg = &app_handle.config().app.windows[0];
            let main_window = tauri::WebviewWindowBuilder::from_config(app_handle, main_cfg)
                .expect("build webview builder from real tauri.conf.json")
                .data_directory(data_dir_path.clone())
                .build()
                .expect("create main webview window");

            if let Some(check) = on_ready.take() {
                check(app_handle);
            }
            let _ = main_window.close();
        }
    });

    assert_eq!(exit_code, 0);
    assert!(
        ready_ran.load(Ordering::SeqCst),
        "RunEvent::Ready must execute during mock app lifecycle"
    );
}

#[test]
fn mock_tauri_app_setup_initializes_real_config_state_and_main_window() {
    run_mock_app_with_real_config(AppState::new(), |app_handle| {
        let main_window = app_handle
            .get_webview_window(MAIN_WINDOW_LABEL)
            .expect("main window should be created from tauri.conf.json");
        assert_eq!(main_window.label(), MAIN_WINDOW_LABEL);
        assert_eq!(app_handle.config().app.windows.len(), 1);
        assert_eq!(app_handle.config().app.windows[0].label, MAIN_WINDOW_LABEL);
        assert_eq!(app_handle.config().app.windows[0].title, "BulkHash");
        assert_eq!(app_handle.config().app.windows[0].min_width, Some(800.0));
        assert_eq!(app_handle.config().app.windows[0].min_height, Some(540.0));

        let state = app_handle.state::<AppState>();
        assert!(state.is_initialized());
        assert!(!state.is_shutting_down());

        let info = state.app_info();
        assert!(info.initialized);
        assert_eq!(info.identity.name, "BulkHash");
        assert_eq!(info.identity.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(info.identity.identifier, "de.derlarso.BulkHash");
        assert_eq!(info.platform.os, std::env::consts::OS);
        assert_eq!(info.platform.arch, std::env::consts::ARCH);
        assert!(info.platform.available_parallelism >= 1);
        assert!(info.platform.default_rayon_threads >= 1);

        assert_eq!(info.capabilities.file_extension, SNAPSHOT_FILE_EXTENSION);
        assert_eq!(info.capabilities.current_version, CURRENT_FORMAT_VERSION);
        assert_eq!(
            info.capabilities.min_supported_version,
            MIN_SUPPORTED_FORMAT_VERSION
        );
        assert!(info.capabilities.supports_encryption);
        assert_eq!(info.capabilities.default_algorithm, HashAlgorithm::Blake3);
        assert_eq!(
            info.capabilities.supported_algorithms.len(),
            HashAlgorithm::all().len()
        );
        assert_eq!(
            info.capabilities.default_compression_level,
            DEFAULT_COMPRESSION_LEVEL
        );
        assert_eq!(
            info.capabilities.compression_presets.len(),
            CompressionPreset::ALL.len()
        );
    });
}

#[test]
fn mock_tauri_ipc_commands_dispatch_ping_app_info_and_app_status() {
    let preloaded_state = AppState::new();
    preloaded_state.push_startup_path(PathBuf::from("/tmp/example.hashed"));

    run_mock_app_with_real_config(preloaded_state, |app_handle| {
        let webview = app_handle
            .get_webview_window(MAIN_WINDOW_LABEL)
            .expect("main webview window");
        let origin = trusted_app_origin(app_handle.config());

        let pong: String = tauri::test::get_ipc_response(&webview, ipc_request(origin.clone(), "ping"))
            .expect("ping IPC call should succeed")
            .deserialize()
            .expect("deserialize pong");
        assert_eq!(pong, "pong");

        let info: AppInfo =
            tauri::test::get_ipc_response(&webview, ipc_request(origin.clone(), "get_app_info"))
                .expect("get_app_info IPC call should succeed")
                .deserialize()
                .expect("deserialize AppInfo");
        assert!(info.initialized);
        assert_eq!(info.identity.name, "BulkHash");
        assert_eq!(info.identity.identifier, "de.derlarso.BulkHash");
        assert!(
            info.capabilities
                .supported_algorithms
                .iter()
                .any(|alg| alg.id == HashAlgorithm::Blake3 && alg.is_default && alg.cryptographic)
        );
        assert!(
            info.capabilities
                .supported_algorithms
                .iter()
                .any(|alg| alg.id == HashAlgorithm::XxHash128 && !alg.cryptographic)
        );

        let status: AppStatus =
            tauri::test::get_ipc_response(&webview, ipc_request(origin.clone(), "get_app_status"))
                .expect("get_app_status IPC call should succeed")
                .deserialize()
                .expect("deserialize AppStatus");
        assert!(status.initialized);
        assert!(!status.shutting_down);
        assert_eq!(status.active_scan_count, 0);
        assert_eq!(status.paused_scan_count, 0);
        assert_eq!(status.loaded_snapshot_count, 0);
        assert_eq!(status.pending_startup_paths_count, 1);

        let state = app_handle.state::<AppState>();
        let guard = state
            .register_scan(ScanJobKind::Directory, "/data/project", HashAlgorithm::Sha256)
            .expect("register scan");
        state.pause_scan(guard.job_id()).expect("pause active scan");

        let live_status: AppStatus =
            tauri::test::get_ipc_response(&webview, ipc_request(origin.clone(), "get_app_status"))
                .expect("get_app_status IPC call with active scan")
                .deserialize()
                .expect("deserialize live AppStatus");
        assert_eq!(live_status.active_scan_count, 1);
        assert_eq!(live_status.paused_scan_count, 1);
        assert_eq!(live_status.active_scans[0].job_id, guard.job_id());
        assert_eq!(live_status.active_scans[0].kind, ScanJobKind::Directory);
        assert_eq!(live_status.active_scans[0].algorithm, HashAlgorithm::Sha256);
        assert_eq!(live_status.active_scans[0].state, ScanControlState::Paused);

        guard.finish();
        let after_finish: AppStatus =
            tauri::test::get_ipc_response(&webview, ipc_request(origin, "get_app_status"))
                .expect("get_app_status after finish")
                .deserialize()
                .expect("deserialize after-finish AppStatus");
        assert_eq!(after_finish.active_scan_count, 0);
        assert_eq!(after_finish.paused_scan_count, 0);
    });
}

#[test]
fn app_state_scan_registry_controls_raii_cleanup_and_panic_safety() {
    let state = AppState::new();

    let guard_a = state
        .register_scan(ScanJobKind::Directory, "/tmp/dir_a", HashAlgorithm::Blake3)
        .expect("register scan A");
    let guard_b = state
        .register_scan(
            ScanJobKind::LiveCompare,
            "/tmp/dir_b",
            HashAlgorithm::XxHash3,
        )
        .expect("register scan B");

    assert_eq!(guard_a.job_id(), 1);
    assert_eq!(guard_b.job_id(), 2);
    assert_eq!(state.active_scan_count(), 2);

    assert_eq!(
        state.pause_scan(guard_a.job_id()).expect("pause scan A"),
        ScanControlState::Paused
    );
    assert_eq!(
        state.resume_scan(guard_a.job_id()).expect("resume scan A"),
        ScanControlState::Running
    );
    assert_eq!(
        state
            .toggle_pause_scan(guard_a.job_id())
            .expect("toggle pause on"),
        ScanControlState::Paused
    );
    assert_eq!(
        state
            .toggle_pause_scan(guard_a.job_id())
            .expect("toggle pause off"),
        ScanControlState::Running
    );
    assert_eq!(
        state.cancel_scan(guard_a.job_id()).expect("cancel scan A"),
        ScanControlState::Cancelled
    );
    assert!(guard_a.is_cancelled());

    let missing_err = state
        .cancel_scan(9999)
        .expect_err("unknown scan id should fail");
    assert!(matches!(missing_err, BulkHashError::ScanJobNotFound(9999)));
    assert_eq!(missing_err.kind(), "ScanJobNotFound");

    // Dropping guard_a automatically removes it from the registry.
    drop(guard_a);
    assert_eq!(state.active_scan_count(), 1);
    assert_eq!(state.list_active_scans()[0].job_id, guard_b.job_id());

    // Simulate a worker thread panicking while holding a guard; RAII drop must clean up.
    let panic_guard = state
        .register_scan(ScanJobKind::SingleFile, "/tmp/file.bin", HashAlgorithm::Md5)
        .expect("register panic guard");
    assert_eq!(state.active_scan_count(), 2);

    let join_res = thread::spawn(move || {
        let _held = panic_guard;
        panic!("simulated worker panic");
    })
    .join();
    assert!(join_res.is_err());
    assert_eq!(state.active_scan_count(), 1);

    guard_b.finish();
    assert_eq!(state.active_scan_count(), 0);
}

#[test]
fn begin_shutdown_cancels_running_scan_manager_and_rejects_new_scans() {
    let dir = TempDir::new("shutdown_cancel");
    for idx in 0..8 {
        fs::write(
            dir.path().join(format!("file_{idx}.txt")),
            format!("sample payload {idx}"),
        )
        .expect("write test file");
    }

    let state = AppState::new();
    let guard = state
        .register_scan(
            ScanJobKind::Directory,
            dir.path().to_string_lossy().into_owned(),
            HashAlgorithm::Blake3,
        )
        .expect("register scan before shutdown");
    let control = guard.control();

    // Pause before starting so the scan blocks cleanly at the first checkpoint.
    state.pause_scan(guard.job_id()).expect("pause scan");

    let scan_path = dir.path().to_string_lossy().into_owned();
    let scan_control = control.clone();
    let worker = thread::spawn(move || {
        let mut manager = ScanManager::new(HashAlgorithm::Blake3).with_control(scan_control);
        manager.start_hash(scan_path)
    });

    assert!(
        control.wait_for_paused_threads(1, Duration::from_secs(2)),
        "worker should enter paused state"
    );

    let cancelled_count = state.begin_shutdown();
    assert_eq!(cancelled_count, 1);
    assert!(state.is_shutting_down());
    assert!(guard.is_cancelled());

    let scan_result = worker.join().expect("join scan thread");
    assert!(
        matches!(scan_result, Err(BulkHashError::ScanCancelled)),
        "scan should exit with ScanCancelled on shutdown, got {scan_result:?}"
    );

    // Calling begin_shutdown again is idempotent.
    let _ = state.begin_shutdown();
    guard.finish();

    let rejected = state
        .register_scan(ScanJobKind::Directory, "/tmp/after", HashAlgorithm::Blake3)
        .expect_err("new scans must be rejected during shutdown");
    assert!(matches!(rejected, BulkHashError::AppShuttingDown));
    assert!(rejected.is_shutting_down());
    assert_eq!(rejected.kind(), "AppShuttingDown");
}

#[test]
fn app_state_snapshot_store_manages_plain_and_encrypted_snapshots() {
    let dir = TempDir::new("snapshot_store");
    let input_dir = dir.path().join("input");
    let out_dir = dir.path().join("out");
    fs::create_dir_all(&input_dir).expect("create input dir");
    fs::create_dir_all(&out_dir).expect("create out dir");
    fs::write(input_dir.join("alpha.txt"), b"alpha content").expect("write alpha");
    fs::write(input_dir.join("beta.txt"), b"beta content 12345").expect("write beta");

    let mut scanner = ScanManager::new(HashAlgorithm::Blake3);
    scanner
        .start_hash(input_dir.to_string_lossy().into_owned())
        .expect("scan input dir");
    let tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
    let meta = MetaData::new(
        scanner.get_hash_manager().get_files_counted(),
        scanner.get_hash_time(),
        Utc::now(),
    )
    .with_algorithm(scanner.get_algorithm())
    .with_total_size(scanner.get_total_size());

    let plain_path = FileManager::save_file(&out_dir, &tree, &meta).expect("save plain snapshot");
    let plain_loaded = FileManager::open_file(&plain_path).expect("open plain snapshot");

    let enc_out = dir.path().join("enc_out");
    fs::create_dir_all(&enc_out).expect("create enc out dir");
    let fast_kdf = KdfParams::new(8 * 1024, 1, 1).expect("valid fast kdf");
    let enc_opts = EncryptionOptions::new("secret-pass")
        .expect("valid password")
        .with_kdf_params(fast_kdf)
        .expect("apply fast kdf");
    let enc_path = FileManager::save_file_encrypted(&enc_out, &tree, &meta, &enc_opts)
        .expect("save encrypted snapshot");
    let enc_loaded =
        FileManager::open_file_with_password(&enc_path, "secret-pass").expect("open encrypted");

    let state = AppState::new();
    let plain_id = state.insert_snapshot(Some(plain_path.clone()), plain_loaded);
    let enc_id = state.insert_snapshot(Some(enc_path.clone()), enc_loaded);

    assert_eq!(plain_id, 1);
    assert_eq!(enc_id, 2);
    assert_eq!(state.snapshot_count(), 2);

    let plain_summary = state
        .get_snapshot_summary(plain_id)
        .expect("plain snapshot summary");
    assert_eq!(plain_summary.files_hashed, 2);
    assert_eq!(plain_summary.algorithm, Some(HashAlgorithm::Blake3));
    assert!(!plain_summary.encrypted);
    assert_eq!(plain_summary.version, CURRENT_FORMAT_VERSION);
    assert_eq!(
        plain_summary.source_path.as_deref(),
        Some(plain_path.to_string_lossy().as_ref())
    );

    let enc_summary = state
        .get_snapshot_summary(enc_id)
        .expect("encrypted snapshot summary");
    assert!(enc_summary.encrypted);
    assert_eq!(enc_summary.files_hashed, 2);
    assert_eq!(enc_summary.tree_hash, plain_summary.tree_hash);

    let arc_plain = state.get_snapshot(plain_id).expect("get plain Arc");
    assert_eq!(arc_plain.get_meta().get_files_hashed(), 2);

    state.remove_snapshot(plain_id).expect("remove plain");
    assert_eq!(state.snapshot_count(), 1);
    let missing = state
        .get_snapshot(plain_id)
        .expect_err("removed snapshot must not exist");
    assert!(matches!(missing, BulkHashError::SnapshotNotFound(1)));
    assert_eq!(missing.kind(), "SnapshotNotFound");

    assert_eq!(state.clear_snapshots(), 1);
    assert_eq!(state.snapshot_count(), 0);
}

#[test]
fn app_directories_ensure_startup_paths_and_json_serde_roundtrip() {
    let dir = TempDir::new("app_dirs");
    let config_path = dir.path().join("config");
    let data_path = dir.path().join("data");

    let dirs = AppDirectories {
        config_dir: Some(config_path.to_string_lossy().into_owned()),
        data_dir: Some(data_path.to_string_lossy().into_owned()),
        local_data_dir: None,
        cache_dir: None,
        log_dir: None,
    };
    let errs = dirs.ensure_base_directories();
    assert!(errs.is_empty(), "expected no directory errors: {errs:?}");
    assert!(config_path.is_dir());
    assert!(data_path.is_dir());
    assert_eq!(dirs.config_path(), Some(config_path));
    assert_eq!(dirs.data_path(), Some(data_path));

    let state = AppState::new();
    state.mark_initialized(AppIdentity::from_cargo_metadata(), dirs.clone());
    state.push_startup_paths([PathBuf::from("a.hashed"), PathBuf::from("b.hashed")]);
    assert_eq!(state.pending_startup_paths_count(), 2);
    assert_eq!(
        state.peek_startup_paths(),
        vec![PathBuf::from("a.hashed"), PathBuf::from("b.hashed")]
    );
    let taken = state.take_startup_paths();
    assert_eq!(taken, vec![PathBuf::from("a.hashed"), PathBuf::from("b.hashed")]);
    assert_eq!(state.pending_startup_paths_count(), 0);

    let info = state.app_info();
    let info_json = serde_json::to_string(&info).expect("serialize AppInfo");
    let info_back: AppInfo = serde_json::from_str(&info_json).expect("deserialize AppInfo");
    assert_eq!(info_back, info);

    let status = state.app_status();
    let status_json = serde_json::to_string(&status).expect("serialize AppStatus");
    let status_back: AppStatus =
        serde_json::from_str(&status_json).expect("deserialize AppStatus");
    assert_eq!(status_back, status);

    let caps = FormatCapabilities::current();
    assert_eq!(caps.file_extension, SNAPSHOT_FILE_EXTENSION);
    assert!(PlatformInfo::detect().available_parallelism >= 1);

    // Verify JSON serialization of the new BulkHashError variants.
    for (err, expected_kind) in [
        (BulkHashError::AppShuttingDown, "AppShuttingDown"),
        (BulkHashError::ScanJobNotFound(42), "ScanJobNotFound"),
        (BulkHashError::SnapshotNotFound(7), "SnapshotNotFound"),
    ] {
        let val = serde_json::to_value(&err).expect("serialize BulkHashError");
        assert_eq!(val["kind"], expected_kind);
        assert!(!val["message"].as_str().unwrap_or_default().is_empty());
    }
}

#[test]
fn closing_main_window_triggers_graceful_shutdown_and_cancels_active_scans() {
    let state = AppState::new();
    let guard = state
        .register_scan(ScanJobKind::Directory, "/tmp/work", HashAlgorithm::Blake3)
        .expect("register scan");
    let control = guard.control();
    assert!(!state.is_shutting_down());
    assert!(!control.is_cancelled());

    let shutdown_observed_on_exit = Arc::new(AtomicBool::new(false));
    let shutdown_observed_cb = Arc::clone(&shutdown_observed_on_exit);

    let webview_data_dir = TempDir::new("mock_webview_shutdown");
    let mut context = tauri::generate_context!();
    for window in &mut context.config_mut().app.windows {
        window.create = false;
    }

    let app = build_app_with_options(
        tauri::test::mock_builder(),
        context,
        state,
        AppSetupOptions {
            ensure_base_directories: false,
        },
    )
    .expect("build mock BulkHash Tauri app");

    let data_dir_path = webview_data_dir.path().to_path_buf();
    let exit_code = app.run_return(move |app_handle, event| {
        handle_run_event(app_handle, &event);
        match event {
            tauri::RunEvent::Ready => {
                let st = app_handle.state::<AppState>();
                assert!(!st.is_shutting_down());
                let main_cfg = &app_handle.config().app.windows[0];
                let main_window = tauri::WebviewWindowBuilder::from_config(app_handle, main_cfg)
                    .expect("build webview builder from real config")
                    .data_directory(data_dir_path.clone())
                    .build()
                    .expect("create main window");
                main_window.close().expect("request main window close");
            }
            tauri::RunEvent::Exit => {
                shutdown_observed_cb
                    .store(app_handle.state::<AppState>().is_shutting_down(), Ordering::SeqCst);
            }
            _ => {}
        }
    });

    assert_eq!(exit_code, 0);
    assert!(
        shutdown_observed_on_exit.load(Ordering::SeqCst),
        "closing the main window should mark AppState as shutting down"
    );
    assert!(
        control.is_cancelled(),
        "closing the main window should cancel active scan jobs"
    );
    guard.finish();
}
