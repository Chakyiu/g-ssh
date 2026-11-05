//! The terminal grid, its tabs, and the keys, search, and suggestions on it.

use std::time::Duration;

use gpui::AsyncApp;
use gssh::ssh::shell::ShellHandle;

pub mod colors;
pub mod element;
pub mod keymap;
pub mod link;
pub mod mouse;
pub mod script;
pub mod search;
pub mod suggestions;
pub mod tabs;
pub mod view;

/// The shell's current folder.
///
/// A shell on this computer is read from the operating system. An SSH shell is
/// asked with `pwd`: a directory it reported at login is still the home
/// directory after `cd`. The wait uses gpui's timer, because this runs on the
/// UI executor, which is not a Tokio runtime. `ask` must be false while a
/// full-screen program owns the terminal.
pub(crate) async fn working_directory(
    shell: &ShellHandle,
    ask: bool,
    cx: &AsyncApp,
) -> Option<String> {
    if let Some(path) = shell.native_directory() {
        return Some(path);
    }
    if !ask {
        return None;
    }
    shell.ask_working_directory().await;
    for _ in 0..40 {
        cx.background_executor()
            .timer(Duration::from_millis(50))
            .await;
        if let Some(path) = shell.fresh_working_directory().await {
            return Some(path);
        }
    }
    None
}
