pub mod core;

use crate::core::{
    hash_manager::HashAlgorithm,
    io::{
        bulk_hash_error::BulkHashError, directory_node::DirectoryNode, file_manager::FileManager,
        meta_data::MetaData,
    },
    scan_manager::ScanManager,
};
use chrono::Utc;
use std::thread;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "linux")]
    {
        if std::env::var("WAYLAND_DISPLAY").is_ok() {
            // SAFETY: this program is single-threaded up to this point
            unsafe {
                std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
            }
        }
    }

    if let Err(err) = run_app() {
        eprintln!("{err}");
    }
}

fn run_app() -> Result<(), BulkHashError> {
    tauri::Builder::default()
        .setup(|_app| {
            thread::Builder::new()
                .name(String::from("cli-scan"))
                .spawn(cli)?;
            Ok(())
        })
        .run(tauri::generate_context!())?;
    Ok(())
}

//temp
fn cli() {
    let mut scan = ScanManager::new(HashAlgorithm::Blake3);
    match scan.start_hash(String::from("/home/lars/Downloads/")) {
        Ok(()) => handle_success(&scan),
        Err(err) => eprintln!("{err}"),
    }
}

fn handle_success(s: &ScanManager) {
    let finished_list = s.get_list();

    let tree = DirectoryNode::build_tree(s.get_path(), finished_list);
    let meta = MetaData::new(
        s.get_hash_manager().get_files_counted(),
        s.get_hash_time(),
        Utc::now(),
    )
    .with_algorithm(s.get_algorithm());

    match FileManager::save_file("/home/lars/Downloads", &tree, &meta) {
        Ok(saved_path) => {
            if let Err(err) = FileManager::open_file(&saved_path) {
                eprintln!("Failed to verify saved file: {err}");
            }
        }
        Err(err) => eprintln!("{err}"),
    }
}
