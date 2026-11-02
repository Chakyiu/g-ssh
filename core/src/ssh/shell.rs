use async_channel::{Receiver, Sender};
use russh::Channel;
use russh::ChannelMsg;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

use crate::ssh::terminal::TermEmulator;

/// While the window cannot be seen (minimized, hidden or fully covered), workers keep feeding
/// the emulator but stop copying the screen, and send one fresh copy when it shows again.
static IS_WINDOW_VISIBLE: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::channel(true).0);

/// Minimum time between screen copies while output streams in: the UI draws one per frame
/// and drops the rest, and copying a big screen costs more than parsing its output.
pub(crate) const SNAPSHOT_INTERVAL: Duration = Duration::from_millis(4);

pub fn is_window_visible() -> bool {
    *IS_WINDOW_VISIBLE.borrow()
}

pub fn set_window_visible(is_visible: bool) {
    IS_WINDOW_VISIBLE.send_replace(is_visible);
}

pub(crate) fn subscribe_window_visible() -> watch::Receiver<bool> {
    IS_WINDOW_VISIBLE.subscribe()
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MouseModeFlags {
    pub report_click: bool,
    pub report_drag: bool,
    pub report_motion: bool,
    pub sgr: bool,
}

impl MouseModeFlags {
    pub fn any_active(&self) -> bool {
        self.report_click || self.report_drag || self.report_motion
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SelectionType {
    Simple,
    Semantic,
    Lines,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SelectionSide {
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GridPoint {
    pub line: i32,
    pub column: usize,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GridSelectionRange {
    pub start: GridPoint,
    pub end: GridPoint,
}

/// Selected terminal text, with 1-based line numbers counted from the top of
/// the scrollback. Line 1 is the oldest row still in the buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionExcerpt {
    pub text: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// What the terminal is showing, for the agent to read after a command.
pub struct TerminalRead {
    pub text: String,
    pub alt_screen: bool,
}

/// Where a scrollback key moves the viewport.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScrollTarget {
    PageUp,
    PageDown,
    Top,
    Bottom,
}

#[derive(Clone)]
pub struct ShellHandle {
    cmd_tx: Sender<ShellCmd>,
    event_rx: Receiver<ShellEvent>,
    /// Folder of a shell on this computer, read from the operating system.
    /// Empty for an SSH or Telnet shell.
    native_cwd: Option<Arc<dyn Fn() -> Option<String> + Send + Sync>>,
}

impl ShellHandle {
    pub(crate) fn new(cmd_tx: Sender<ShellCmd>, event_rx: Receiver<ShellEvent>) -> Self {
        Self {
            cmd_tx,
            event_rx,
            native_cwd: None,
        }
    }

    pub(crate) fn with_native_cwd(
        mut self,
        query: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        self.native_cwd = Some(query);
        self
    }

    /// The folder of a shell on this computer. `None` for an SSH shell: its
    /// folder is on the other machine, so it has to be asked.
    pub fn native_directory(&self) -> Option<String> {
        self.native_cwd.as_ref().and_then(|query| query())
    }

    /// Type `pwd` and keep what it prints. The answer is
    /// [`Self::fresh_working_directory`].
    pub async fn ask_working_directory(&self) {
        let _ = self.cmd_tx.send(ShellCmd::AskWorkingDirectory).await;
    }

    /// The folder from the `pwd` started by [`Self::ask_working_directory`],
    /// once the shell has printed it.
    pub async fn fresh_working_directory(&self) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(ShellCmd::FreshDirectory { reply: tx })
            .await
            .is_err()
        {
            return None;
        }
        rx.await.ok().flatten()
    }

    /// The shell's folder, without typing into it. A local shell is read from
    /// the operating system. An SSH shell uses the directory it last reported.
    pub async fn current_directory(&self) -> Option<String> {
        if let Some(query) = &self.native_cwd {
            if let Some(path) = query() {
                return Some(path);
            }
        }
        self.reported_directory().await
    }

    async fn reported_directory(&self) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(ShellCmd::WorkingDirectory { reply: tx })
            .await
            .is_err()
        {
            return None;
        }
        rx.await.ok().flatten()
    }

    pub async fn send_input(&self, data: Vec<u8>) {
        let _ = self.cmd_tx.send(ShellCmd::Input(data)).await;
    }

    pub async fn resize(&self, rows: u16, cols: u16) {
        let _ = self.cmd_tx.send(ShellCmd::Resize { rows, cols }).await;
    }

    pub fn subscribe(&self) -> Receiver<ShellEvent> {
        self.event_rx.clone()
    }

    pub async fn set_selection(
        &self,
        ty: SelectionType,
        anchor: GridPoint,
        anchor_side: SelectionSide,
        head: GridPoint,
        head_side: SelectionSide,
    ) -> Option<GridSelectionRange> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ShellCmd::SetSelection {
                ty,
                anchor,
                anchor_side,
                head,
                head_side,
                reply: tx,
            })
            .await;
        rx.await.ok().flatten()
    }

    /// Unlike `set_selection`, keeps the anchor pinned, so a drag stays correct while the
    /// buffer scrolls underneath it.
    pub async fn update_selection_head(
        &self,
        head: GridPoint,
        head_side: SelectionSide,
    ) -> Option<GridSelectionRange> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ShellCmd::UpdateSelectionHead {
                head,
                head_side,
                reply: tx,
            })
            .await;
        rx.await.ok().flatten()
    }

    pub async fn extract_selection_text(&self) -> Option<String> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ShellCmd::ExtractSelectionText { reply: tx })
            .await;
        rx.await.ok().flatten()
    }

    /// The selection and the scrollback lines it covers. `None` when nothing
    /// is selected.
    pub async fn extract_selection_excerpt(&self) -> Option<SelectionExcerpt> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ShellCmd::ExtractSelectionExcerpt { reply: tx })
            .await;
        rx.await.ok().flatten()
    }

    /// The text on screen, including scrollback. `None` once the session is gone.
    pub async fn read_terminal(&self) -> Option<TerminalRead> {
        let (tx, rx) = oneshot::channel();
        let _ = self.cmd_tx.send(ShellCmd::ReadTerminal { reply: tx }).await;
        rx.await.ok()
    }

    pub async fn select_all(&self) -> Option<GridSelectionRange> {
        let (tx, rx) = oneshot::channel();
        let _ = self.cmd_tx.send(ShellCmd::SelectAll { reply: tx }).await;
        rx.await.ok().flatten()
    }

    /// Returns the match count; an empty query clears the search. `None` once the session
    /// is gone, so a closed session is not shown as "no matches" while still on screen.
    pub async fn set_search(&self, query: String) -> Option<usize> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ShellCmd::SetSearch { query, reply: tx })
            .await;
        rx.await.ok()
    }

    /// Scrolls to the next or previous match. Returns its 1-based position and the total,
    /// `(0, 0)` if nothing matches, or `None` once the session is gone.
    pub async fn step_search(&self, forward: bool) -> Option<(usize, usize)> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ShellCmd::StepSearch { forward, reply: tx })
            .await;
        rx.await.ok()
    }

    pub async fn scroll_delta(&self, lines: i32) {
        let _ = self.cmd_tx.send(ShellCmd::ScrollDelta(lines)).await;
    }

    /// Scroll to `offset` lines above the bottom (0 = live tail). Resolved in the emulator,
    /// so fast scrollbar drags do not drift.
    pub async fn scroll_to_offset(&self, offset: usize) {
        let _ = self.cmd_tx.send(ShellCmd::ScrollToOffset(offset)).await;
    }

    pub async fn scroll_to(&self, target: ScrollTarget) {
        let _ = self.cmd_tx.send(ShellCmd::ScrollTo(target)).await;
    }

    /// Wipe the scrollback and the screen. The shell is not told, so follow it
    /// with a Ctrl-L to make it draw its prompt again.
    pub async fn clear_scrollback(&self) {
        let _ = self.cmd_tx.send(ShellCmd::ClearScrollback).await;
    }
}

pub enum ShellCmd {
    Input(Vec<u8>),
    Resize {
        rows: u16,
        cols: u16,
    },
    SetSelection {
        ty: SelectionType,
        anchor: GridPoint,
        anchor_side: SelectionSide,
        head: GridPoint,
        head_side: SelectionSide,
        reply: oneshot::Sender<Option<GridSelectionRange>>,
    },
    UpdateSelectionHead {
        head: GridPoint,
        head_side: SelectionSide,
        reply: oneshot::Sender<Option<GridSelectionRange>>,
    },
    ExtractSelectionText {
        reply: oneshot::Sender<Option<String>>,
    },
    ExtractSelectionExcerpt {
        reply: oneshot::Sender<Option<SelectionExcerpt>>,
    },
    ReadTerminal {
        reply: oneshot::Sender<TerminalRead>,
    },
    SelectAll {
        reply: oneshot::Sender<Option<GridSelectionRange>>,
    },
    SetSearch {
        query: String,
        reply: oneshot::Sender<usize>,
    },
    StepSearch {
        forward: bool,
        reply: oneshot::Sender<(usize, usize)>,
    },
    ScrollDelta(i32),
    ScrollToOffset(usize),
    ScrollTo(ScrollTarget),
    ClearScrollback,
    WorkingDirectory {
        reply: oneshot::Sender<Option<String>>,
    },
    /// Type the command that prints the folder, and remember the output.
    AskWorkingDirectory,
    FreshDirectory {
        reply: oneshot::Sender<Option<String>>,
    },
}

/// Keys that print the shell's folder. A Windows prompt (`C:\...>`) is `cmd`,
/// which has no `pwd` and shows `^E` and `^U` as text, so it is asked with
/// `cmd /c cd`. That also works in PowerShell. Anything else is a POSIX shell:
/// Ctrl+E, Ctrl+U drop a half-typed line first, the same way [`cd_input`] does.
pub fn directory_probe_input(screen: &str) -> Vec<u8> {
    if is_windows_prompt(screen) {
        b"cmd /c cd\r".to_vec()
    } else {
        b"\x05\x15pwd\r".to_vec()
    }
}

fn is_windows_prompt(screen: &str) -> bool {
    screen
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .is_some_and(|line| line.contains(":\\") && line.ends_with('>'))
}

pub enum ShellEvent {
    Snapshot(TermSnapshot),
    /// The shell or its channel ended (`exit`, Ctrl+D); the connection may still be fine.
    Exited,
    /// The channel went away with the connection.
    Disconnected,
    Error(String),
}

pub struct TermSnapshot {
    pub rows: u16,
    pub cols: u16,
    pub cells: Vec<Vec<SnapshotCell>>,
    /// Per row: true on a soft wrap, where the row's text runs on into the next.
    pub is_row_wrapped: Vec<bool>,
    pub cursor: (u16, u16),
    pub cursor_visible: bool,
    /// True while an app holds the alternate screen (vim, htop, less). Used to
    /// suppress command suggestions, which only make sense at a shell prompt.
    pub alt_screen: bool,
    /// Bracketed paste is on (DECSET 2004): wrap pasted text in ESC[200~ and ESC[201~ so the
    /// app takes it as data, not typing; otherwise every newline runs a command.
    pub bracketed_paste: bool,
    /// Cursor keys in application form (DECCKM): arrows send ESC O A, not ESC [ A.
    pub is_app_cursor: bool,
    /// The wheel sends arrow keys on the alternate screen (DECSET 1007). On by default.
    pub is_alternate_scroll: bool,
    pub mouse_mode: MouseModeFlags,
    pub display_offset: usize,
    pub history_size: usize,
    /// Kept on its text by the emulator as output scrolls; `None` if absent or empty.
    pub selection: Option<GridSelectionRange>,
    /// Matches on the visible rows, in the same coordinates as `selection`.
    pub search_matches: Vec<GridSelectionRange>,
    /// The match the user stepped to, painted stronger than the rest.
    pub current_match: Option<GridSelectionRange>,
}

pub struct SnapshotCell {
    pub c: char,
    pub fg: SnapshotColor,
    pub bg: SnapshotColor,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikethrough: bool,
    pub dim: bool,
    pub inverse: bool,
    pub wide_char: bool,
    pub wide_char_spacer: bool,
}

impl Default for SnapshotCell {
    fn default() -> Self {
        Self {
            c: ' ',
            fg: SnapshotColor::Default,
            bg: SnapshotColor::Default,
            bold: false,
            italic: false,
            underline: false,
            strikethrough: false,
            dim: false,
            inverse: false,
            wide_char: false,
            wide_char_spacer: false,
        }
    }
}

pub enum SnapshotColor {
    Default,
    Indexed(u8),
    Rgb(u8, u8, u8),
}

/// What a [`ShellCmd`] asks of the emulator. The bytes and the resize also have
/// to reach the PTY, so those are handed back. The SSH channel and the local
/// shell both go through this, so selection, search and scrolling stay in step.
pub(crate) enum ShellCmdEffect {
    Write(Vec<u8>),
    Resize {
        rows: u16,
        cols: u16,
    },
    /// The screen changed and a snapshot should go out.
    Snapshot,
    /// A reply was sent. The screen did not change.
    Quiet,
}

pub(crate) fn apply_shell_cmd(emulator: &mut TermEmulator, cmd: ShellCmd) -> ShellCmdEffect {
    match cmd {
        ShellCmd::Input(data) => {
            emulator.scroll_to_bottom();
            ShellCmdEffect::Write(data)
        }
        ShellCmd::Resize { rows, cols } => ShellCmdEffect::Resize { rows, cols },
        ShellCmd::SetSelection {
            ty,
            anchor,
            anchor_side,
            head,
            head_side,
            reply,
        } => {
            let range = emulator.set_selection(ty, anchor, anchor_side, head, head_side);
            let _ = reply.send(range);
            ShellCmdEffect::Quiet
        }
        ShellCmd::UpdateSelectionHead {
            head,
            head_side,
            reply,
        } => {
            let range = emulator.update_selection_head(head, head_side);
            let _ = reply.send(range);
            ShellCmdEffect::Quiet
        }
        ShellCmd::ExtractSelectionText { reply } => {
            let _ = reply.send(emulator.selection_to_string());
            ShellCmdEffect::Quiet
        }
        ShellCmd::ExtractSelectionExcerpt { reply } => {
            let _ = reply.send(emulator.selection_excerpt());
            ShellCmdEffect::Quiet
        }
        ShellCmd::ReadTerminal { reply } => {
            let _ = reply.send(TerminalRead {
                text: emulator.buffer_text(),
                alt_screen: emulator.is_alt_screen(),
            });
            ShellCmdEffect::Quiet
        }
        ShellCmd::SelectAll { reply } => {
            let range = emulator.select_all();
            let _ = reply.send(range);
            ShellCmdEffect::Quiet
        }
        ShellCmd::SetSearch { query, reply } => {
            let total = emulator.set_search(query);
            let _ = reply.send(total);
            ShellCmdEffect::Snapshot
        }
        ShellCmd::StepSearch { forward, reply } => {
            let progress = emulator.step_search(forward);
            let _ = reply.send(progress);
            ShellCmdEffect::Snapshot
        }
        ShellCmd::ScrollDelta(lines) => {
            emulator.scroll_delta(lines);
            ShellCmdEffect::Snapshot
        }
        ShellCmd::ScrollToOffset(offset) => {
            emulator.scroll_to_offset(offset);
            ShellCmdEffect::Snapshot
        }
        ShellCmd::ScrollTo(target) => {
            emulator.scroll_to(target);
            ShellCmdEffect::Snapshot
        }
        ShellCmd::ClearScrollback => {
            emulator.clear_scrollback();
            ShellCmdEffect::Snapshot
        }
        ShellCmd::WorkingDirectory { reply } => {
            let _ = reply.send(emulator.working_directory());
            ShellCmdEffect::Quiet
        }
        ShellCmd::AskWorkingDirectory => {
            let screen = emulator.buffer_text();
            emulator.begin_pwd_watch();
            ShellCmdEffect::Write(directory_probe_input(&screen))
        }
        ShellCmd::FreshDirectory { reply } => {
            let _ = reply.send(emulator.fresh_directory());
            ShellCmdEffect::Quiet
        }
    }
}

pub async fn handle_shell_commands(
    mut channel: Channel<russh::client::Msg>,
    initial_rows: u16,
    initial_cols: u16,
    cmd_rx: Receiver<ShellCmd>,
    event_tx: Sender<ShellEvent>,
) {
    let mut emulator = TermEmulator::new(initial_rows, initial_cols);
    let mut window_visibility = IS_WINDOW_VISIBLE.subscribe();
    let mut is_snapshot_stale = false;
    // Output came in that the UI has not seen yet; the timer sends it.
    let mut is_snapshot_due = false;
    let mut last_snapshot_at = Instant::now();
    let snapshot_timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(snapshot_timer);

    // An empty screen first, so the UI has something to draw at once.
    let _ = event_tx
        .send(ShellEvent::Snapshot(emulator.snapshot()))
        .await;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Ok(cmd) => match apply_shell_cmd(&mut emulator, cmd) {
                        ShellCmdEffect::Write(data) => {
                            if let Err(e) = channel.data(data.as_slice()).await {
                                let _ = event_tx.send(ShellEvent::Error(format!("send input: {e}"))).await;
                                break;
                            }
                        }
                        ShellCmdEffect::Resize { rows, cols } => {
                            if let Err(e) = channel.window_change(cols as u32, rows as u32, 0, 0).await {
                                let _ = event_tx.send(ShellEvent::Error(format!("resize: {e}"))).await;
                                break;
                            }
                            emulator.resize(rows, cols);
                            let _ = event_tx.send(ShellEvent::Snapshot(emulator.snapshot())).await;
                        }
                        ShellCmdEffect::Snapshot => {
                            let _ = event_tx.send(ShellEvent::Snapshot(emulator.snapshot())).await;
                        }
                        ShellCmdEffect::Quiet => {}
                    },
                    Err(_) => {
                        // The tab was closed. russh does not close a dropped channel, so the
                        // remote shell would otherwise live on until the connection ends.
                        let _ = channel.close().await;
                        break;
                    }
                }
            }

            Ok(()) = window_visibility.changed() => {
                if *window_visibility.borrow_and_update() && is_snapshot_stale {
                    is_snapshot_stale = false;
                    let _ = event_tx.send(ShellEvent::Snapshot(emulator.snapshot())).await;
                }
            }

            () = &mut snapshot_timer, if is_snapshot_due => {
                is_snapshot_due = false;
                if *window_visibility.borrow() {
                    last_snapshot_at = Instant::now();
                    let _ = event_tx.send(ShellEvent::Snapshot(emulator.snapshot())).await;
                } else {
                    is_snapshot_stale = true;
                }
            }

            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        emulator.advance(data.as_ref());
                        let replies = emulator.take_replies();
                        if !replies.is_empty() {
                            if let Err(e) = channel.data(replies.as_slice()).await {
                                let _ = event_tx.send(ShellEvent::Error(format!("send reply: {e}"))).await;
                                break;
                            }
                        }
                        if !*window_visibility.borrow() {
                            is_snapshot_stale = true;
                        } else if last_snapshot_at.elapsed() >= SNAPSHOT_INTERVAL {
                            // A keystroke's echo goes out at once.
                            is_snapshot_due = false;
                            last_snapshot_at = Instant::now();
                            let _ = event_tx.send(ShellEvent::Snapshot(emulator.snapshot())).await;
                        } else if !is_snapshot_due {
                            is_snapshot_due = true;
                            snapshot_timer.as_mut().reset(last_snapshot_at + SNAPSHOT_INTERVAL);
                        }
                    }
                    Some(ChannelMsg::ExitStatus { .. })
                    | Some(ChannelMsg::Eof)
                    | Some(ChannelMsg::Close) => {
                        let _ = event_tx.send(ShellEvent::Exited).await;
                        break;
                    }
                    None => {
                        let _ = event_tx.send(ShellEvent::Disconnected).await;
                        break;
                    }
                    Some(_) => {}
                }
            }
        }
    }
}

/// One shell word for POSIX shells, fish and csh. `'`, `\` and `!` go outside the quotes:
/// fish reads `\` in single quotes as an escape, and csh expands `!` history in them.
fn shell_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('\'');
    for character in text.chars() {
        match character {
            '\'' => quoted.push_str(r"'\''"),
            '\\' => quoted.push_str(r"'\\'"),
            '!' => quoted.push_str(r"'\!'"),
            other => quoted.push(other),
        }
    }
    quoted.push('\'');
    quoted
}

/// Keys that make an interactive shell `cd` into `path`. `None` if the path has a control
/// character: the line editor acts on those even in quotes (a newline runs the line).
pub fn cd_input(path: &str) -> Option<Vec<u8>> {
    if path.is_empty() || path.chars().any(char::is_control) {
        return None;
    }
    // Ctrl+E, Ctrl+U drop a half-typed line first: `rm -rf ` plus our text is another command.
    // The leading space keeps the cd out of history where the shell is set up for that.
    Some(format!("\x05\x15 cd -- {}\r", shell_quote(path)).into_bytes())
}

/// `{path}` in `command` marks where the quoted path goes, else it goes at the end.
/// `path` is absolute, so it cannot read as an option. `None` on control characters.
pub fn editor_input(command: &str, path: &str) -> Option<Vec<u8>> {
    let command = command.trim();
    if command.is_empty() || path.is_empty() {
        return None;
    }
    if command.chars().chain(path.chars()).any(char::is_control) {
        return None;
    }
    // A quoted placeholder would put our quoted path inside the user's quotes,
    // where `$(...)` in a file name would run. Drop such quotes first.
    let command = command
        .replace("\"{path}\"", PATH_PLACEHOLDER)
        .replace("'{path}'", PATH_PLACEHOLDER);
    if is_placeholder_in_quotes(&command) {
        return None;
    }
    let quoted = shell_quote(path);
    let line = if command.contains(PATH_PLACEHOLDER) {
        command.replace(PATH_PLACEHOLDER, &quoted)
    } else {
        format!("{command} {quoted}")
    };
    // `&& exit` closes the tab only after a clean quit, so an error stays on screen.
    Some(format!(" {line} && exit\r").into_bytes())
}

pub const PATH_PLACEHOLDER: &str = "{path}";

/// Whether any `{path}` sits inside quotes (after an odd number of them).
fn is_placeholder_in_quotes(command: &str) -> bool {
    command.match_indices(PATH_PLACEHOLDER).any(|(index, _)| {
        let before = &command[..index];
        let single_quotes = before.matches('\'').count();
        let double_quotes = before.matches('"').count();
        single_quotes % 2 == 1 || double_quotes % 2 == 1
    })
}

/// Commands that run another program. Their name says nothing about the editor.
const WRAPPER_COMMANDS: [&str; 6] = ["sudo", "doas", "env", "nice", "command", "exec"];

/// The editor's name for menus, or `None` when `command` has no plain program name.
pub fn editor_name(command: &str) -> Option<&str> {
    // `TERM=xterm vim` names vim, `/usr/bin/nvim -R` names nvim.
    let program = command
        .split_whitespace()
        .find(|word| !word.contains('='))?;
    let name = program.rsplit('/').next()?;
    let is_plain = !name.is_empty() && name != PATH_PLACEHOLDER;
    (is_plain && !WRAPPER_COMMANDS.contains(&name)).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor_line(command: &str, path: &str) -> String {
        String::from_utf8(editor_input(command, path).unwrap()).unwrap()
    }

    #[test]
    fn editor_input_puts_the_quoted_path_at_the_end() {
        assert_eq!(
            editor_line("vim", "/etc/nginx/nginx.conf"),
            " vim '/etc/nginx/nginx.conf' && exit\r"
        );
        assert_eq!(
            editor_line("  nvim -R ", "/srv/my app/it's.conf"),
            r" nvim -R '/srv/my app/it'\''s.conf' && exit".to_string() + "\r"
        );
        assert_eq!(
            editor_line("nano", "/srv/папка/$(reboot).txt"),
            " nano '/srv/папка/$(reboot).txt' && exit\r"
        );
    }

    #[test]
    fn editor_input_fills_every_placeholder() {
        assert_eq!(
            editor_line("sudoedit {path}", "/etc/hosts"),
            " sudoedit '/etc/hosts' && exit\r"
        );
        assert_eq!(
            editor_line("cp {path} /tmp/x && vim {path}", "/a b"),
            " cp '/a b' /tmp/x && vim '/a b' && exit\r"
        );
    }

    #[test]
    fn editor_input_drops_quotes_around_the_placeholder() {
        assert_eq!(
            editor_line("vim \"{path}\"", "/srv/$(id).txt"),
            " vim '/srv/$(id).txt' && exit\r"
        );
        assert_eq!(
            editor_line("vim '{path}'", "/srv/$(id).txt"),
            " vim '/srv/$(id).txt' && exit\r"
        );
    }

    #[test]
    fn editor_input_refuses_a_placeholder_inside_quotes() {
        assert!(editor_input("sh -c \"vim {path}\"", "/srv/$(id)").is_none());
        assert!(editor_input("sh -c 'vim {path}'", "/srv/$(id)").is_none());
        assert!(editor_input("vim \"x\" {path}", "/srv/a").is_some());
    }

    #[test]
    fn editor_input_refuses_control_characters_and_empty_input() {
        assert!(editor_input("vim", "/srv/a\nrm -rf ~").is_none());
        assert!(editor_input("vim\nrm -rf ~", "/srv/a").is_none());
        assert!(editor_input("vim", "").is_none());
        assert!(editor_input("  ", "/srv/a").is_none());
    }

    #[test]
    fn editor_name_is_the_program() {
        assert_eq!(editor_name("vim"), Some("vim"));
        assert_eq!(editor_name("/usr/bin/nvim -R"), Some("nvim"));
        assert_eq!(editor_name("TERM=xterm vim {path}"), Some("vim"));
        assert_eq!(editor_name("sudoedit {path}"), Some("sudoedit"));
        assert_eq!(editor_name("{path}"), None);
        assert_eq!(editor_name("sudo vim"), None);
        assert_eq!(editor_name("/usr/bin/doas nano"), None);
        assert_eq!(editor_name("env TERM=xterm vim"), None);
        assert_eq!(editor_name("nice vim"), None);
        assert_eq!(editor_name("command vim"), None);
        assert_eq!(editor_name("exec vim"), None);
        assert_eq!(editor_name(""), None);
    }

    fn typed(path: &str) -> String {
        String::from_utf8(cd_input(path).unwrap()).unwrap()
    }

    #[test]
    fn cd_input_quotes_a_plain_path() {
        assert_eq!(typed("/var/www/app"), "\x05\x15 cd -- '/var/www/app'\r");
    }

    #[test]
    fn cd_input_keeps_shell_syntax_inside_quotes() {
        assert_eq!(
            typed("/srv/my app/$(reboot);`id` && !x *"),
            "\x05\x15 cd -- '/srv/my app/$(reboot);`id` && '\\!'x *'\r"
        );
        assert_eq!(typed("/srv/-rf"), "\x05\x15 cd -- '/srv/-rf'\r");
        assert_eq!(typed("/srv/папка"), "\x05\x15 cd -- '/srv/папка'\r");
    }

    #[test]
    fn shell_quote_escapes_quotes_and_backslashes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("'"), r"''\'''");
        assert_eq!(shell_quote(r"a\b"), r"'a'\\'b'");
        // A trailing backslash must not swallow the closing quote in fish.
        assert_eq!(shell_quote("dir\\"), r"'dir'\\''");
        assert_eq!(shell_quote(r#"a"b"#), r#"'a"b'"#);
        assert_eq!(shell_quote("notes!.txt"), r"'notes'\!'.txt'");
    }

    #[test]
    fn pwd_report_asks_for_the_folder_without_running_the_typed_line() {
        let posix = String::from_utf8(directory_probe_input("root@k3s:/etc# ")).unwrap();
        assert_eq!(posix, "\u{5}\u{15}pwd\r");
        let cmd = String::from_utf8(directory_probe_input(r"C:\Users\lcyha\Downloads>")).unwrap();
        assert_eq!(cmd, "cmd /c cd\r");
        let powershell = String::from_utf8(directory_probe_input(r"PS C:\Users\lcyha>")).unwrap();
        assert_eq!(powershell, "cmd /c cd\r");
    }

    #[test]
    fn cd_input_refuses_control_characters_and_empty_paths() {
        assert!(cd_input("/srv/a\nrm -rf ~").is_none());
        assert!(cd_input("/srv/a\rb").is_none());
        assert!(cd_input("/srv/a\tb").is_none());
        assert!(cd_input("/srv/a\x1b[201~").is_none());
        assert!(cd_input("/srv/a\x7fb").is_none());
        assert!(cd_input("").is_none());
    }
}
