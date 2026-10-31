//! What the app built on this crate tells it about itself.

use std::path::PathBuf;
use std::sync::OnceLock;

static VERSION: OnceLock<&'static str> = OnceLock::new();
static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Sent in the user agent. Call once at start, before any request.
pub fn set_version(version: &'static str) {
    let _ = VERSION.set(version);
}

pub fn version() -> &'static str {
    VERSION.get().copied().unwrap_or("unknown")
}

/// Vault and log folder. Call once at start, before the vault is opened.
pub fn set_data_dir(dir: PathBuf) {
    let _ = DATA_DIR.set(dir);
}

pub(crate) fn data_dir_override() -> Option<PathBuf> {
    DATA_DIR.get().cloned()
}
