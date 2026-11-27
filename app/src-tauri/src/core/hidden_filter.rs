use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
const WINDOWS_FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
#[cfg(windows)]
const WINDOWS_FILE_ATTRIBUTE_SYSTEM: u32 = 0x0000_0004;
#[cfg(target_os = "macos")]
const MACOS_UF_HIDDEN: u32 = 0x0000_8000;

const KNOWN_SYSTEM_NAMES_ASCII_LOWER: &[&str] = &[
    // Windows Explorer, shell, and volume metadata
    "desktop.ini",
    "thumbs.db",
    "ehthumbs.db",
    "ehthumbs_vista.db",
    "$recycle.bin",
    "system volume information",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "ntuser.dat",
    // macOS Finder and volume metadata
    ".ds_store",
    ".appledouble",
    ".spotlight-v100",
    ".trashes",
    ".fseventsd",
    ".temporaryitems",
    // Unix / Linux filesystem metadata
    "lost+found",
];

/// Configuration for filtering hidden files, dotfiles, and OS system metadata entries during scans.
///
/// By default (`HiddenFileFilter::include_all()` / `HiddenFileFilter::default()`), hidden and
/// system files are **included** so scans hash everything unless filtering is explicitly enabled.
/// Mandatory OS pseudo-filesystem exclusions (such as `/proc`, `/sys`, `/dev`, `/run` on Linux
/// and `pagefile.sys` on Windows) are always enforced independently.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub struct HiddenFileFilter {
    #[serde(default)]
    exclude_dotfiles: bool,
    #[serde(default)]
    exclude_os_hidden: bool,
    #[serde(default)]
    exclude_system_files: bool,
}

impl HiddenFileFilter {
    /// Creates a filter that includes all hidden and system files (no filtering).
    #[must_use]
    pub const fn new() -> Self {
        Self::include_all()
    }

    /// Creates a filter that includes all hidden files, dotfiles, and OS system metadata entries.
    #[must_use]
    pub const fn include_all() -> Self {
        Self {
            exclude_dotfiles: false,
            exclude_os_hidden: false,
            exclude_system_files: false,
        }
    }

    /// Creates a filter that excludes dotfiles, OS-hidden entries, and OS system metadata entries.
    #[must_use]
    pub const fn exclude_all() -> Self {
        Self {
            exclude_dotfiles: true,
            exclude_os_hidden: true,
            exclude_system_files: true,
        }
    }

    /// Creates a filter that excludes dotfiles and OS-hidden entries, while still including
    /// non-hidden system metadata files.
    #[must_use]
    pub const fn exclude_hidden() -> Self {
        Self {
            exclude_dotfiles: true,
            exclude_os_hidden: true,
            exclude_system_files: false,
        }
    }

    /// Creates a filter that excludes only Unix-style dotfiles and dot-directories.
    #[must_use]
    pub const fn exclude_dotfiles() -> Self {
        Self {
            exclude_dotfiles: true,
            exclude_os_hidden: false,
            exclude_system_files: false,
        }
    }

    /// Creates a filter that excludes only OS system and metadata files/directories.
    #[must_use]
    pub const fn exclude_system_files() -> Self {
        Self {
            exclude_dotfiles: false,
            exclude_os_hidden: false,
            exclude_system_files: true,
        }
    }

    /// Builder method to configure excluding Unix-style dotfiles and dot-directories.
    #[must_use]
    pub const fn with_exclude_dotfiles(mut self, exclude: bool) -> Self {
        self.exclude_dotfiles = exclude;
        self
    }

    /// Builder method to configure excluding entries with OS-native hidden attributes
    /// (`FILE_ATTRIBUTE_HIDDEN` on Windows, `UF_HIDDEN` on macOS).
    #[must_use]
    pub const fn with_exclude_os_hidden(mut self, exclude: bool) -> Self {
        self.exclude_os_hidden = exclude;
        self
    }

    /// Builder method to configure excluding OS system and metadata files/directories.
    #[must_use]
    pub const fn with_exclude_system_files(mut self, exclude: bool) -> Self {
        self.exclude_system_files = exclude;
        self
    }

    /// Sets whether Unix-style dotfiles and dot-directories are excluded.
    pub const fn set_exclude_dotfiles(&mut self, exclude: bool) {
        self.exclude_dotfiles = exclude;
    }

    /// Sets whether OS-native hidden entries are excluded.
    pub const fn set_exclude_os_hidden(&mut self, exclude: bool) {
        self.exclude_os_hidden = exclude;
    }

    /// Sets whether OS system and metadata files/directories are excluded.
    pub const fn set_exclude_system_files(&mut self, exclude: bool) {
        self.exclude_system_files = exclude;
    }

    /// Returns `true` if Unix-style dotfiles and dot-directories are excluded.
    #[must_use]
    pub const fn excludes_dotfiles(&self) -> bool {
        self.exclude_dotfiles
    }

    /// Returns `true` if OS-native hidden entries are excluded.
    #[must_use]
    pub const fn excludes_os_hidden(&self) -> bool {
        self.exclude_os_hidden
    }

    /// Returns `true` if OS system and metadata files/directories are excluded.
    #[must_use]
    pub const fn excludes_system_files(&self) -> bool {
        self.exclude_system_files
    }

    /// Returns `true` if any hidden or system file exclusion rule is enabled.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.exclude_dotfiles || self.exclude_os_hidden || self.exclude_system_files
    }

    /// Returns `true` if all hidden and system files are included (no filtering active).
    #[must_use]
    pub const fn includes_all(&self) -> bool {
        !self.is_active()
    }

    /// Returns `true` if dotfiles, OS-hidden entries, and OS system files are all excluded.
    #[must_use]
    pub const fn excludes_all(&self) -> bool {
        self.exclude_dotfiles && self.exclude_os_hidden && self.exclude_system_files
    }

    /// Returns `true` if evaluating this filter may require reading OS filesystem metadata
    /// attributes on the current target platform.
    #[must_use]
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(clippy::unused_self))]
    pub const fn needs_os_metadata(&self) -> bool {
        #[cfg(windows)]
        {
            self.exclude_os_hidden || self.exclude_system_files
        }
        #[cfg(target_os = "macos")]
        {
            self.exclude_os_hidden
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            false
        }
    }

    /// Checks whether a single file or directory name matches name-based exclusion rules
    /// (dotfiles and well-known OS system/metadata names) without performing any I/O.
    #[must_use]
    pub fn matches_name(&self, name: &OsStr) -> bool {
        (self.exclude_dotfiles && is_dotfile_name(name))
            || (self.exclude_system_files && is_known_system_name(name))
    }

    /// Checks whether filesystem metadata matches OS-native hidden or system attributes.
    #[must_use]
    pub fn matches_metadata(&self, metadata: &fs::Metadata) -> bool {
        (self.exclude_os_hidden && has_os_hidden_attribute(metadata))
            || (self.exclude_system_files && has_os_system_attribute(metadata))
    }

    /// Checks whether an entry with the given name and optional metadata should be excluded.
    #[must_use]
    pub fn matches_entry(&self, name: &OsStr, metadata: Option<&fs::Metadata>) -> bool {
        if self.matches_name(name) {
            return true;
        }
        metadata.is_some_and(|meta| self.matches_metadata(meta))
    }

    /// Checks whether the single entry at `path` (ignoring ancestor directories) should be
    /// excluded by this filter.
    #[must_use]
    pub fn is_hidden_entry(&self, path: impl AsRef<Path>) -> bool {
        if !self.is_active() {
            return false;
        }

        let path_ref = path.as_ref();
        if let Some(name) = path_ref.file_name()
            && self.matches_name(name)
        {
            return true;
        }

        if self.needs_os_metadata()
            && let Ok(metadata) = path_ref.symlink_metadata()
            && self.matches_metadata(&metadata)
        {
            return true;
        }

        false
    }

    /// Checks whether `full_path` located under `root` should be excluded by this filter.
    ///
    /// Evaluates every normal path component strictly beneath `root` (top-down), so hidden
    /// directories inside the scan root exclude all of their descendants, while hidden
    /// directories *above* `root` (such as `~/.config/app`) never cause entries inside `root`
    /// to be excluded.
    #[must_use]
    pub fn is_hidden_under(&self, root: impl AsRef<Path>, full_path: impl AsRef<Path>) -> bool {
        if !self.is_active() {
            return false;
        }

        let root_ref = root.as_ref();
        let full_ref = full_path.as_ref();

        let Ok(relative) = full_ref.strip_prefix(root_ref) else {
            return self.is_hidden_path(full_ref);
        };

        let needs_meta = self.needs_os_metadata();
        let mut current = needs_meta.then(|| root_ref.to_path_buf());

        for component in relative.components() {
            if let Component::Normal(part) = component {
                if self.matches_name(part) {
                    return true;
                }
                if let Some(ref mut path_buf) = current {
                    path_buf.push(part);
                    if let Ok(metadata) = path_buf.symlink_metadata()
                        && self.matches_metadata(&metadata)
                    {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Checks whether `path` should be excluded by this filter.
    ///
    /// Checks every normal path component against name-based hidden/system rules. When OS-native
    /// metadata filtering is enabled, also checks the entry's own metadata (and relative ancestor
    /// metadata when `path` is relative, avoiding false positives from OS-hidden system ancestors
    /// such as `AppData` in absolute paths on Windows).
    #[must_use]
    pub fn is_hidden_path(&self, path: impl AsRef<Path>) -> bool {
        if !self.is_active() {
            return false;
        }

        let path_ref = path.as_ref();
        let needs_meta = self.needs_os_metadata();
        let check_ancestor_meta = needs_meta && path_ref.is_relative();
        let mut current = check_ancestor_meta.then(PathBuf::new);

        for component in path_ref.components() {
            match component {
                Component::Normal(part) => {
                    if self.matches_name(part) {
                        return true;
                    }
                    if let Some(ref mut path_buf) = current {
                        path_buf.push(part);
                        if let Ok(metadata) = path_buf.symlink_metadata()
                            && self.matches_metadata(&metadata)
                        {
                            return true;
                        }
                    }
                }
                Component::CurDir | Component::ParentDir => {
                    if let Some(ref mut path_buf) = current {
                        path_buf.push(component.as_os_str());
                    }
                }
                Component::Prefix(_) | Component::RootDir => {}
            }
        }

        if needs_meta
            && !check_ancestor_meta
            && let Ok(metadata) = path_ref.symlink_metadata()
            && self.matches_metadata(&metadata)
        {
            return true;
        }

        false
    }
}

/// Returns `true` if `name` is a Unix-style dotfile or dot-directory name
/// (starts with `.` and is neither `.` nor `..`).
#[must_use]
pub fn is_dotfile_name(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes.starts_with(b".") && bytes != b"." && bytes != b".."
}

/// Returns `true` if `name` matches a well-known OS system or metadata file/directory name
/// (such as `desktop.ini`, `Thumbs.db`, `$RECYCLE.BIN`, `.DS_Store`, `lost+found`, or
/// `.Trash-<uid>`).
#[must_use]
pub fn is_known_system_name(name: &OsStr) -> bool {
    let Some(name_str) = name.to_str() else {
        return false;
    };

    KNOWN_SYSTEM_NAMES_ASCII_LOWER
        .iter()
        .any(|known| name_str.eq_ignore_ascii_case(known))
        || is_freedesktop_trash_dir(name_str)
}

/// Returns `true` if OS-native metadata marks this entry as hidden
/// (`FILE_ATTRIBUTE_HIDDEN` on Windows, `UF_HIDDEN` on macOS).
#[must_use]
pub fn has_os_hidden_attribute(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        (metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_HIDDEN) != 0
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt;
        (metadata.st_flags() & MACOS_UF_HIDDEN) != 0
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = metadata;
        false
    }
}

/// Returns `true` if OS-native metadata marks this entry as a system entry
/// (`FILE_ATTRIBUTE_SYSTEM` on Windows).
#[must_use]
pub fn has_os_system_attribute(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        (metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_SYSTEM) != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn is_freedesktop_trash_dir(name: &str) -> bool {
    if name.eq_ignore_ascii_case(".trash") {
        return true;
    }

    if let Some((prefix, suffix)) = name.split_at_checked(7) {
        return prefix.eq_ignore_ascii_case(".trash-")
            && !suffix.is_empty()
            && suffix.bytes().all(|b| b.is_ascii_digit());
    }

    false
}
