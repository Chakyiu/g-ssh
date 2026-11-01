//! Terminal tabs: several shells for one host over the same SSH connection,
//! so a second shell needs no second login. A right-click renames a terminal
//! tab or colours it. A middle-click closes it. Dragging a tab docks it into
//! a second pane, which keeps its own tab list. Dropping a tab on an edge
//! splits that cell, so the grid
//! can grow to four, five, or more. SFTP for a host is its own workspace tab,
//! opened from the host list.
//!
//! The methods belong to `ServerSession`. They live here so that the session
//! module stays about the connection lifecycle.

use crate::ui::scale::px;
use gpui::prelude::*;
use gpui::{
    div, relative, Anchor, AnyElement, App, Bounds, ClickEvent, Context, DragMoveEvent, Entity,
    Focusable as _, Hsla, MouseButton, MouseDownEvent, MouseUpEvent, Pixels, Point, SharedString,
    Window,
};

use gpui_component::{
    button::{Button, ButtonVariants as _},
    dialog::{DialogAction, DialogFooter, DialogHeader, DialogTitle},
    h_flex,
    input::{Input, InputEvent, InputState},
    resizable::{h_resizable, resizable_panel, v_resizable, ResizableState},
    tooltip::Tooltip,
    v_flex, ActiveTheme as _, Icon, IconName, Sizable as _, StyledExt as _, WindowExt as _,
};

use crate::preferences::Preferences;
use crate::theme;
use crate::ui::dialog_chrome;
use crate::ui::hints;
use crate::ui::menu::{ContextMenu, ContextMenuItem};
use crate::ui::session::{
    DockEdge, LayoutNode, ServerSession, ServerSessionEvent, TermPane, TerminalTabMenu,
};
use crate::ui::terminal::view::{TabColor, TerminalEvent, TerminalView};
use gssh::ssh::shell::ShellHandle;

/// Tabs past this would not fit the header. It is also close to what a server
/// allows: OpenSSH's default `MaxSessions` is 10 and SFTP takes two of them.
const MAX_TERMINALS: usize = 8;

/// Shown in the tooltips and the command palette. Must track the bindings in
/// [`crate::ui::app::init`].
pub const NEW_TERMINAL_SHORTCUT: &str = if cfg!(target_os = "macos") {
    "\u{21E7}\u{2318}T"
} else {
    "Ctrl+Shift+N"
};
pub const TOGGLE_FILES_SHORTCUT: &str = if cfg!(target_os = "macos") {
    "\u{2318}B"
} else {
    "Ctrl+Shift+B"
};
pub const SERVER_PANEL_SHORTCUT: &str = if cfg!(target_os = "macos") {
    "\u{2318}I"
} else {
    "Ctrl+Shift+I"
};

/// Why a file cannot open in a new tab: every tab is taken, or the session is
/// not connected.
fn full_or_offline_status(terminal_count: usize, name: &str) -> String {
    if terminal_count >= MAX_TERMINALS {
        format!("Close a terminal tab to open {name}")
    } else {
        format!("Can't open {name}: not connected")
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// How long a tab name may be. Longer pastes are cut, not rejected.
const MAX_TAB_TITLE: usize = 80;

/// The name on a tab: a custom one, else the file it edits, else "Terminal"
/// or its number.
fn tab_label(index: usize, alone: bool, title: Option<&str>, edited_file: Option<&str>) -> String {
    if let Some(title) = title.map(str::trim).filter(|title| !title.is_empty()) {
        return title.to_string();
    }
    match edited_file {
        Some(path) if alone => file_name(path).to_string(),
        Some(path) => format!("{} {}", index + 1, file_name(path)),
        None if alone => "Terminal".to_string(),
        None => (index + 1).to_string(),
    }
}

/// Full name, and the file path when the label does not already show it.
fn tab_tooltip(title: Option<&str>, file: Option<&str>) -> Option<String> {
    let title_overflows = title.is_some_and(|title| title.chars().count() > 18);
    match (title, file) {
        (Some(title), Some(path)) => Some(format!("{title} — {path}")),
        (Some(title), None) if title_overflows => Some(title.to_string()),
        (None, Some(path)) => Some(path.to_string()),
        _ => None,
    }
}

/// Blank, or the same as the label the tab would have anyway, stores nothing.
fn stored_tab_title(raw: &str, default_label: &str) -> Option<String> {
    match clean_tab_title(raw) {
        Some(title) if title == default_label => None,
        other => other,
    }
}

fn clean_tab_title(raw: &str) -> Option<String> {
    let title: String = raw
        .trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_TAB_TITLE)
        .collect();
    let title = title.trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

/// A custom colour, or the usual green.
fn mark_color(color: Option<TabColor>) -> Hsla {
    color
        .map(TabColor::paint)
        .unwrap_or_else(theme::status_online)
}

fn tint(color: Hsla, alpha: f32) -> Hsla {
    Hsla { a: alpha, ..color }
}

fn color_dot(color: Hsla) -> gpui::Div {
    div().size(px(8.)).flex_none().rounded_full().bg(color)
}

/// Which tab is active after the one at `closed` is removed, leaving
/// `remaining` tabs. The active shell stays active; closing it moves to the
/// tab that slid into its place.
#[cfg(test)]
fn active_after_close(active: usize, closed: usize, remaining: usize) -> usize {
    let next = if closed < active { active - 1 } else { active };
    next.min(remaining.saturating_sub(1))
}

/// Where `index` sits after the item at `from` moves to final index `to`.
/// The dock's tab list after the shell at `closed` is removed.
/// `None` when that was the last shell in the pane.
fn dock_after_close(tabs: &[usize], active: usize, closed: usize) -> Option<(Vec<usize>, usize)> {
    let tabs: Vec<usize> = tabs
        .iter()
        .filter_map(|ix| {
            if *ix == closed {
                None
            } else if *ix > closed {
                Some(ix - 1)
            } else {
                Some(*ix)
            }
        })
        .collect();
    let first = tabs.first().copied()?;
    let shifted = if active == closed {
        first
    } else if active > closed {
        active - 1
    } else {
        active
    };
    let active = if tabs.contains(&shifted) {
        shifted
    } else {
        first
    };
    Some((tabs, active))
}

pub(crate) fn layout_contains(node: &LayoutNode, pane: usize) -> bool {
    match node {
        LayoutNode::Pane(id) => *id == pane,
        LayoutNode::Split { first, second, .. } => {
            layout_contains(first, pane) || layout_contains(second, pane)
        }
    }
}

pub(crate) fn first_pane(node: &LayoutNode) -> usize {
    match node {
        LayoutNode::Pane(id) => *id,
        LayoutNode::Split { first, .. } => first_pane(first),
    }
}

/// Where a tab goes after it has been taken out of `tabs`. `before` is the
/// tab under the pointer; `after` is that tab's right half.
pub(crate) fn tab_insert_index(tabs: &[usize], before: Option<usize>, after: bool) -> usize {
    let Some(at) = before else {
        return tabs.len();
    };
    let Some(pos) = tabs.iter().position(|tab| *tab == at) else {
        return tabs.len();
    };
    if after {
        pos + 1
    } else {
        pos
    }
}

/// The mark on the side of a tab where a dragged tab would land.
pub(crate) fn tab_insert_mark(at_left: bool) -> gpui::Div {
    let mark = div()
        .absolute()
        .top(px(4.))
        .bottom(px(4.))
        .w(px(2.))
        .rounded_full()
        .bg(theme::accent());
    if at_left {
        mark.left(px(0.))
    } else {
        mark.right(px(0.))
    }
}

fn pane_is_empty(node: &LayoutNode, panes: &[TermPane]) -> bool {
    match node {
        LayoutNode::Pane(id) => panes.get(*id).is_none_or(|pane| pane.tabs.is_empty()),
        LayoutNode::Split { .. } => false,
    }
}

/// Drop a cell whose last tab left. A split with one empty side becomes the
/// other side, so the grid closes up.
pub(crate) fn collapse_layout(node: LayoutNode, panes: &[TermPane]) -> LayoutNode {
    match node {
        LayoutNode::Pane(id) => LayoutNode::Pane(id),
        LayoutNode::Split {
            id,
            horizontal,
            state,
            first,
            second,
        } => {
            let first = collapse_layout(*first, panes);
            let second = collapse_layout(*second, panes);
            match (pane_is_empty(&first, panes), pane_is_empty(&second, panes)) {
                (true, false) => second,
                (false, true) => first,
                _ => LayoutNode::Split {
                    id,
                    horizontal,
                    state,
                    first: Box::new(first),
                    second: Box::new(second),
                },
            }
        }
    }
}

pub(crate) fn replace_leaf(
    node: &mut LayoutNode,
    pane: usize,
    replacement: &mut Option<LayoutNode>,
) -> bool {
    match node {
        LayoutNode::Pane(id) if *id == pane => {
            if let Some(next) = replacement.take() {
                *node = next;
                true
            } else {
                false
            }
        }
        LayoutNode::Split { first, second, .. } => {
            replace_leaf(first, pane, replacement) || replace_leaf(second, pane, replacement)
        }
        LayoutNode::Pane(_) => false,
    }
}

#[cfg(test)]
fn index_after_move(index: usize, from: usize, to: usize) -> usize {
    if from == to || index == from {
        return if index == from { to } else { index };
    }
    let mut index = index;
    if index > from {
        index -= 1;
    }
    if index >= to {
        index += 1;
    }
    index
}

pub(crate) fn bounds_contain(bounds: Bounds<Pixels>, point: Point<Pixels>) -> bool {
    let x = point.x - bounds.origin.x;
    let y = point.y - bounds.origin.y;
    x >= px(0.) && y >= px(0.) && x <= bounds.size.width && y <= bounds.size.height
}

/// Which dock band `point` is in, or the centre when it is not near an edge.
///
/// The bands are 22% of the terminal, and never more than 180×140px, so a
/// wide terminal keeps a centre you can drop back into without docking.
pub(crate) fn dock_edge_at(bounds: Bounds<Pixels>, point: Point<Pixels>) -> Option<DockEdge> {
    let x = (point.x - bounds.origin.x).as_f32();
    let y = (point.y - bounds.origin.y).as_f32();
    let w = bounds.size.width.as_f32();
    let h = bounds.size.height.as_f32();
    if w <= 1. || h <= 1. || x < 0. || y < 0. || x > w || y > h {
        return None;
    }
    let band_x = (w * 0.22).clamp(0., (w * 0.45).min(180.));
    let band_y = (h * 0.22).clamp(0., (h * 0.45).min(140.));
    let left = x < band_x;
    let right = x > w - band_x;
    let top = y < band_y;
    let bottom = y > h - band_y;
    let corner = |along: f32, band: f32, other: f32, other_band: f32, edge, other_edge| {
        if along / band <= other / other_band {
            edge
        } else {
            other_edge
        }
    };
    match (left, right, top, bottom) {
        (true, _, true, _) => Some(corner(x, band_x, y, band_y, DockEdge::Left, DockEdge::Top)),
        (true, _, _, true) => Some(corner(
            x,
            band_x,
            h - y,
            band_y,
            DockEdge::Left,
            DockEdge::Bottom,
        )),
        (_, true, true, _) => Some(corner(
            w - x,
            band_x,
            y,
            band_y,
            DockEdge::Right,
            DockEdge::Top,
        )),
        (_, true, _, true) => Some(corner(
            w - x,
            band_x,
            h - y,
            band_y,
            DockEdge::Right,
            DockEdge::Bottom,
        )),
        (true, _, _, _) => Some(DockEdge::Left),
        (_, true, _, _) => Some(DockEdge::Right),
        (_, _, true, _) => Some(DockEdge::Top),
        (_, _, _, true) => Some(DockEdge::Bottom),
        _ => None,
    }
}

/// The tab being dragged. The index is where it was when the drag started.
#[derive(Clone, Copy)]
struct DraggedTab {
    ix: usize,
}

struct TabDragGhost {
    label: SharedString,
    mark: Hsla,
}

impl Render for TabDragGhost {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        h_flex()
            .h(px(26.))
            .px(px(8.))
            .gap(px(6.))
            .items_center()
            .rounded(px(6.))
            .border_1()
            .border_color(theme::border_focused())
            .bg(cx.theme().popover)
            .shadow_md()
            .opacity(0.2)
            .text_size(px(12.5))
            .text_color(cx.theme().foreground)
            .child(color_dot(self.mark))
            .child(self.label.clone())
    }
}

impl ServerSession {
    /// The shell the keyboard goes to: the active tab of the cell last clicked.
    pub fn active_terminal(&self) -> Option<&Entity<TerminalView>> {
        let ix = self.focused_index()?;
        self.terminals.get(ix)
    }

    fn focused_index(&self) -> Option<usize> {
        self.shown(self.current_pane())
    }

    /// More than one cell is on screen.
    pub(crate) fn layout_has_split(&self) -> bool {
        !matches!(self.layout, LayoutNode::Pane(_))
    }

    fn current_pane(&self) -> usize {
        if layout_contains(&self.layout, self.focused_pane) {
            self.focused_pane
        } else {
            first_pane(&self.layout)
        }
    }

    fn shown(&self, pane: usize) -> Option<usize> {
        let pane = self.panes.get(pane)?;
        if pane.tabs.contains(&pane.active) {
            Some(pane.active)
        } else {
            pane.tabs.first().copied()
        }
    }

    fn pane_tabs(&self, pane: usize) -> Vec<usize> {
        self.panes
            .get(pane)
            .map(|pane| pane.tabs.clone())
            .unwrap_or_default()
    }

    fn pane_for(&self, ix: usize) -> Option<usize> {
        self.panes.iter().position(|pane| pane.tabs.contains(&ix))
    }

    /// Put a new shell in the cell that has the keyboard.
    fn adopt_terminal(&mut self, ix: usize) {
        if self.panes.is_empty() {
            self.panes.push(TermPane {
                tabs: vec![ix],
                active: ix,
            });
            self.layout = LayoutNode::Pane(0);
            self.focused_pane = 0;
            self.active_terminal = ix;
            return;
        }
        let pane = self.current_pane();
        if let Some(slot) = self.panes.get_mut(pane) {
            if !slot.tabs.contains(&ix) {
                slot.tabs.push(ix);
            }
            slot.active = ix;
        }
        self.focused_pane = pane;
        self.active_terminal = ix;
    }

    /// Wrap a freshly opened shell in a terminal tab at the end of the strip.
    pub(crate) fn add_terminal(&mut self, shell: ShellHandle, cx: &mut Context<Self>) {
        let history = self.shell_history.clone();
        let vault = self.server_panel.read(cx).vault();
        let terminal = cx.new(|cx| {
            let mut view = TerminalView::new(shell, cx);
            view.follow_agent_setting(vault, cx);
            if !history.is_empty() {
                view.set_history(history, cx);
            }
            view
        });
        cx.subscribe(
            &terminal,
            |this, terminal, event: &TerminalEvent, cx| match event {
                TerminalEvent::Exited => this.close_exited_terminal(&terminal, cx),
                TerminalEvent::AskAgent {
                    text,
                    start_line,
                    end_line,
                } => {
                    if !this.server_panel.read(cx).agent_enabled(cx) {
                        return;
                    }
                    this.open_agent_from_terminal(text.clone(), *start_line, *end_line, cx);
                }
            },
        )
        .detach();
        self.terminals.push(terminal);
        let ix = self.terminals.len() - 1;
        self.adopt_terminal(ix);
    }

    /// Replace every shell with `shells`, keeping each tab's name and colour.
    pub(crate) fn adopt_shells(&mut self, shells: Vec<ShellHandle>, cx: &mut Context<Self>) {
        let tab_looks: Vec<_> = self
            .terminals
            .iter()
            .map(|terminal| {
                let view = terminal.read(cx);
                (view.tab_title.clone(), view.tab_color)
            })
            .collect();
        let panes = self.panes.clone();
        let layout = self.layout.clone();
        let focused = self.focused_pane;
        self.terminals.clear();
        self.terminal_tab_menu = None;
        for shell in shells {
            self.add_terminal(shell, cx);
        }
        for (terminal, (title, color)) in self.terminals.iter().zip(tab_looks) {
            terminal.update(cx, |view, _| {
                view.tab_title = title;
                view.tab_color = color;
            });
        }
        // A shell the server refused to reopen may have been the active one.
        self.active_terminal = self
            .active_terminal
            .min(self.terminals.len().saturating_sub(1));
        self.restore_layout(panes, layout, focused);
        self.is_terminal_focus_pending = true;
    }

    fn can_open_terminal(&self) -> bool {
        let connected = self.browser.is_some() || self.telnet.is_some();
        connected
            && self.disconnected.is_none()
            && self.reconnecting.is_none()
            && self.terminals.len() < MAX_TERMINALS
    }

    /// Open one more shell on the live connection and show it.
    pub fn open_extra_terminal(&mut self, cx: &mut Context<Self>) {
        self.open_terminal(None, cx);
    }

    /// Edit a remote file with the editor from the preferences, in a new tab.
    /// Never in a tab that is open already: its shell may be busy, and the
    /// keys would go to whatever runs there.
    pub(crate) fn edit_in_terminal(&mut self, path: String, cx: &mut Context<Self>) {
        let name = file_name(&path).to_string();
        if !self.can_open_terminal() {
            cx.emit(ServerSessionEvent::StatusChanged(full_or_offline_status(
                self.terminals.len(),
                &name,
            )));
            return;
        }
        let command = Preferences::editor_command(cx);
        let Some(input) = gssh::ssh::shell::editor_input(&command, &path) else {
            cx.emit(ServerSessionEvent::StatusChanged(format!(
                "Can't open {name} in the terminal: the name or the editor command has a \
                 control character"
            )));
            return;
        };
        tracing::info!(
            host = %self.conn_info.display_name(),
            path,
            command,
            "editing a file in the terminal",
        );
        self.open_terminal(Some((input, path)), cx);
    }

    /// `startup` is typed into the new shell, and its path names the tab.
    fn open_terminal(&mut self, startup: Option<(Vec<u8>, String)>, cx: &mut Context<Self>) {
        if !self.can_open_terminal() {
            return;
        }
        let telnet = self.telnet.clone();
        let conn = self.connection.clone();
        if telnet.is_none() && conn.is_none() {
            return;
        }
        let generation = self.connection_generation;
        // Start at the size of the tab it will replace on screen, so the shell
        // does not draw its first prompt for a default 80x24 grid.
        let (rows, cols) = self
            .active_terminal()
            .and_then(|terminal| terminal.read(cx).grid_size())
            .unwrap_or((24, 80));

        cx.spawn(async move |this, cx| {
            let result = if let Some(telnet) = telnet {
                telnet.open_shell(rows, cols).await
            } else if let Some(conn) = conn {
                conn.open_shell(rows, cols)
                    .await
                    .map_err(|error| error.to_string())
            } else {
                Err("connection closed".to_string())
            };
            this.update(cx, |session, cx| match result {
                // A reconnect in the meantime replaced every shell. This one
                // belongs to the old connection, so it is dropped.
                Ok(_) if session.connection_generation != generation => {}
                Ok(_) if !session.can_open_terminal() => {
                    if let Some((_, path)) = startup {
                        cx.emit(ServerSessionEvent::StatusChanged(full_or_offline_status(
                            session.terminals.len(),
                            file_name(&path),
                        )));
                    }
                }
                Ok(shell) => {
                    // The shell is not ready to read yet. The keys wait in the
                    // terminal's input buffer until it is.
                    let edited_file = startup.map(|(input, path)| {
                        let shell = shell.clone();
                        cx.background_spawn(async move { shell.send_input(input).await })
                            .detach();
                        path
                    });
                    session.add_terminal(shell, cx);
                    if let Some(terminal) = session.terminals.last() {
                        terminal.update(cx, |view, _| view.edited_file = edited_file);
                    }
                    // `add_terminal` already put this shell in the cell that
                    // had the keys. Leave SFTP: the new shell is the one to see.
                    session.is_sftp_hidden = true;
                    session.is_terminal_focus_pending = true;
                    tracing::info!(
                        host = %session.conn_info.display_name(),
                        count = session.terminals.len(),
                        "extra terminal opened",
                    );
                    cx.notify();
                }
                Err(error) => {
                    tracing::warn!(
                        host = %session.conn_info.display_name(),
                        %error,
                        "could not open an extra terminal",
                    );
                    // The usual cause is the server's MaxSessions limit.
                    cx.emit(ServerSessionEvent::StatusChanged(format!(
                        "Error: could not open another terminal ({error}). \
                         The host may limit sessions per connection."
                    )));
                }
            })
            .ok();
        })
        .detach();
    }

    fn activate_terminal(&mut self, ix: usize, cx: &mut Context<Self>) {
        if ix >= self.terminals.len() {
            return;
        }
        if let Some(pane) = self.pane_for(ix) {
            if let Some(slot) = self.panes.get_mut(pane) {
                slot.active = ix;
            }
            self.focused_pane = pane;
        }
        self.active_terminal = ix;
        // A terminal tab replaces SFTP.
        self.is_sftp_hidden = true;
        self.is_terminal_focus_pending = true;
        cx.notify();
    }

    /// Close one tab. Dropping the view drops the last handle to its shell,
    /// which closes the channel. The last tab cannot be closed.
    fn close_terminal(&mut self, ix: usize, cx: &mut Context<Self>) {
        if self.terminals.len() < 2 || ix >= self.terminals.len() {
            return;
        }
        // The editor may have saved the file, so its size and date changed.
        if self.terminals[ix].read(cx).edited_file.is_some() {
            if let Some(browser) = &self.browser {
                browser.update(cx, |browser, cx| browser.list_session_pane_again(cx));
            }
        }
        let was_focused = self.focused_index() == Some(ix);
        self.forget_closed_index(ix);
        self.terminal_tab_menu = None;
        self.terminals.remove(ix);
        // One shell cannot be split.
        if self.terminals.len() < 2 {
            let only = self
                .panes
                .iter()
                .position(|pane| !pane.tabs.is_empty())
                .unwrap_or(0);
            self.layout = LayoutNode::Pane(only);
            self.focused_pane = only;
            if let Some(tab) = self.shown(only) {
                self.active_terminal = tab;
            }
        }
        if was_focused {
            self.is_terminal_focus_pending = true;
        }
        cx.notify();
    }

    /// Shift every cell's tab list after the shell at `closed` is removed.
    fn forget_closed_index(&mut self, closed: usize) {
        for pane in &mut self.panes {
            match dock_after_close(&pane.tabs, pane.active, closed) {
                Some((tabs, active)) => {
                    pane.tabs = tabs;
                    pane.active = active;
                }
                None => {
                    pane.tabs.clear();
                    pane.active = 0;
                }
            }
        }
        let layout = std::mem::replace(&mut self.layout, LayoutNode::Pane(0));
        self.layout = collapse_layout(layout, &self.panes);
        if !layout_contains(&self.layout, self.focused_pane) {
            self.focused_pane = first_pane(&self.layout);
        }
        if let Some(ix) = self.shown(self.focused_pane) {
            self.active_terminal = ix;
        }
    }

    fn end_tab_drag(&mut self) {
        self.dragging_tab = None;
        self.dock_hover = None;
        self.tab_slot = None;
    }

    /// Take `ix` out of every cell. The caller collapses the grid afterwards.
    fn detach_tab(&mut self, ix: usize) {
        for pane in &mut self.panes {
            pane.tabs.retain(|tab| *tab != ix);
            if !pane.tabs.contains(&pane.active) {
                pane.active = pane.tabs.first().copied().unwrap_or(0);
            }
        }
    }

    fn collapse_grid(&mut self) {
        let layout = std::mem::replace(&mut self.layout, LayoutNode::Pane(0));
        self.layout = collapse_layout(layout, &self.panes);
        if !layout_contains(&self.layout, self.focused_pane) {
            self.focused_pane = first_pane(&self.layout);
        }
    }

    /// Drop in the centre of a cell, or on its tab: the shell joins that
    /// cell, before the tab when `after` is false and after it when `after`
    /// is true. An edge drop splits the cell instead.
    fn move_into_pane(
        &mut self,
        ix: usize,
        target: usize,
        before: Option<usize>,
        after: bool,
        cx: &mut Context<Self>,
    ) {
        self.end_tab_drag();
        if ix >= self.terminals.len() || self.panes.get(target).is_none() {
            cx.notify();
            return;
        }
        if before == Some(ix) && self.pane_for(ix) == Some(target) {
            self.activate_terminal(ix, cx);
            return;
        }
        self.detach_tab(ix);
        self.collapse_grid();
        if !layout_contains(&self.layout, target) {
            self.adopt_terminal(ix);
            self.is_sftp_hidden = true;
            self.is_terminal_focus_pending = true;
            cx.notify();
            return;
        }
        if let Some(pane) = self.panes.get_mut(target) {
            let pos = tab_insert_index(&pane.tabs, before, after);
            pane.tabs.insert(pos, ix);
            pane.active = ix;
        }
        self.focused_pane = target;
        self.active_terminal = ix;
        self.is_sftp_hidden = true;
        self.is_terminal_focus_pending = true;
        self.terminal_tab_menu = None;
        cx.notify();
    }

    /// Split `target` along `edge` and put `ix` in the new cell. Repeating
    /// this on any cell grows the grid past two.
    fn dock_on_edge(&mut self, ix: usize, target: usize, edge: DockEdge, cx: &mut Context<Self>) {
        self.end_tab_drag();
        let alone = self
            .panes
            .get(target)
            .is_some_and(|pane| pane.tabs.len() == 1 && pane.tabs.first() == Some(&ix));
        if ix >= self.terminals.len() || self.terminals.len() < 2 || alone {
            cx.notify();
            return;
        }
        self.detach_tab(ix);
        self.collapse_grid();
        if !layout_contains(&self.layout, target) {
            self.adopt_terminal(ix);
            cx.notify();
            return;
        }
        let new_id = self.panes.len();
        self.panes.push(TermPane {
            tabs: vec![ix],
            active: ix,
        });
        let horizontal = matches!(edge, DockEdge::Left | DockEdge::Right);
        let new_first = matches!(edge, DockEdge::Left | DockEdge::Top);
        let split_id = self.next_split_id;
        self.next_split_id += 1;
        let state = cx.new(|_| ResizableState::default());
        let fresh = LayoutNode::Pane(new_id);
        let old = LayoutNode::Pane(target);
        let (first, second) = if new_first {
            (fresh, old)
        } else {
            (old, fresh)
        };
        let mut split = Some(LayoutNode::Split {
            id: split_id,
            horizontal,
            state,
            first: Box::new(first),
            second: Box::new(second),
        });
        replace_leaf(&mut self.layout, target, &mut split);
        self.focused_pane = new_id;
        self.active_terminal = ix;
        self.is_sftp_hidden = true;
        self.is_terminal_focus_pending = true;
        self.terminal_tab_menu = None;
        cx.notify();
    }

    /// After a reconnect the shells are new views in the same order, so the
    /// grid of indices still describes them.
    pub(crate) fn restore_layout(
        &mut self,
        panes: Vec<TermPane>,
        layout: LayoutNode,
        focused: usize,
    ) {
        self.dragging_tab = None;
        self.dock_hover = None;
        self.panes = if panes.is_empty() {
            vec![TermPane {
                tabs: Vec::new(),
                active: 0,
            }]
        } else {
            panes
        };
        self.layout = layout;
        self.focused_pane = focused;
        let len = self.terminals.len();
        for pane in &mut self.panes {
            pane.tabs.retain(|ix| *ix < len);
            pane.tabs.dedup();
            if !pane.tabs.contains(&pane.active) {
                pane.active = pane.tabs.first().copied().unwrap_or(0);
            }
        }
        self.collapse_grid();
        let home = if layout_contains(&self.layout, self.focused_pane) {
            self.focused_pane
        } else {
            first_pane(&self.layout)
        };
        self.focused_pane = home;
        let mut covered = Vec::new();
        self.collect_tabs(&self.layout.clone(), &mut covered);
        if let Some(pane) = self.panes.get_mut(home) {
            for ix in 0..len {
                if !covered.contains(&ix) && !pane.tabs.contains(&ix) {
                    pane.tabs.push(ix);
                }
            }
            if !pane.tabs.contains(&pane.active) {
                pane.active = pane.tabs.first().copied().unwrap_or(0);
            }
        }
        if let Some(ix) = self.shown(self.focused_pane) {
            self.active_terminal = ix;
        }
    }

    fn collect_tabs(&self, node: &LayoutNode, out: &mut Vec<usize>) {
        match node {
            LayoutNode::Pane(id) => {
                if let Some(pane) = self.panes.get(*id) {
                    out.extend(pane.tabs.iter().copied());
                }
            }
            LayoutNode::Split { first, second, .. } => {
                self.collect_tabs(first, out);
                self.collect_tabs(second, out);
            }
        }
    }

    /// The user left a shell (`exit`, Ctrl+D). Its tab closes, the session
    /// stays. The only shell is kept on screen with its last output.
    fn close_exited_terminal(&mut self, terminal: &Entity<TerminalView>, cx: &mut Context<Self>) {
        let Some(ix) = self
            .terminals
            .iter()
            .position(|candidate| candidate == terminal)
        else {
            return;
        };
        self.close_terminal(ix, cx);
    }

    fn tab_meta(&self, ix: usize, cx: &App) -> (Option<String>, Option<TabColor>, Option<String>) {
        self.terminals
            .get(ix)
            .map(|terminal| {
                let view = terminal.read(cx);
                (
                    view.tab_title.clone(),
                    view.tab_color,
                    view.edited_file.clone(),
                )
            })
            .unwrap_or((None, None, None))
    }

    fn default_tab_label(&self, ix: usize, cx: &App) -> String {
        let file = self
            .terminals
            .get(ix)
            .and_then(|terminal| terminal.read(cx).edited_file.clone());
        tab_label(ix, self.terminals.len() == 1, None, file.as_deref())
    }

    fn open_tab_menu(&mut self, ix: usize, position: Point<Pixels>, cx: &mut Context<Self>) {
        if ix >= self.terminals.len() {
            return;
        }
        if ix != self.active_terminal {
            self.activate_terminal(ix, cx);
        }
        self.terminal_tab_menu = Some(TerminalTabMenu { ix, position });
        cx.notify();
    }

    fn apply_tab_title(&mut self, ix: usize, raw: &str, cx: &mut Context<Self>) {
        if ix >= self.terminals.len() {
            return;
        }
        let stored = stored_tab_title(raw, &self.default_tab_label(ix, cx));
        self.terminals[ix].update(cx, |view, _| view.tab_title = stored);
        cx.notify();
    }

    fn set_tab_color(&mut self, ix: usize, color: Option<TabColor>, cx: &mut Context<Self>) {
        self.terminal_tab_menu = None;
        if let Some(terminal) = self.terminals.get(ix) {
            terminal.update(cx, |view, _| view.tab_color = color);
        }
        cx.notify();
    }

    fn open_rename_tab(&mut self, ix: usize, window: &mut Window, cx: &mut Context<Self>) {
        if ix >= self.terminals.len() {
            cx.notify();
            return;
        }
        let current = self
            .tab_meta(ix, cx)
            .0
            .unwrap_or_else(|| self.default_tab_label(ix, cx));
        let input = cx.new(|cx| InputState::new(window, cx).placeholder("Tab name"));
        input.update(cx, |state, cx| {
            state.set_value(current, window, cx);
        });
        cx.subscribe_in(
            &input,
            window,
            move |this, input, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    let value = input.read(cx).value().to_string();
                    this.apply_tab_title(ix, &value, cx);
                    window.close_dialog(cx);
                }
            },
        )
        .detach();

        let weak = cx.weak_entity();
        let input_for_dialog = input.clone();
        window.open_dialog(cx, move |dialog, _, _| {
            let weak = weak.clone();
            let input_for_dialog = input_for_dialog.clone();
            let save_input = input_for_dialog.clone();
            dialog_chrome(dialog).w(px(320.)).child(
                v_flex()
                    .p(px(12.))
                    .gap(px(8.))
                    .on_action(|_: &gpui_component::input::Escape, window, cx| {
                        window.close_dialog(cx);
                    })
                    .child(DialogHeader::new().child(DialogTitle::new().child("Rename tab")))
                    .child(Input::new(&input_for_dialog).small())
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(theme::text_dim())
                            .child("Leave blank to use the default name."),
                    )
                    .child(
                        DialogFooter::new().child(
                            DialogAction::new().child(
                                h_flex()
                                    .gap(px(8.))
                                    .child(
                                        Button::new("tab-rename-cancel")
                                            .ghost()
                                            .child("Cancel")
                                            .on_click(|_, window, cx| window.close_dialog(cx)),
                                    )
                                    .child(
                                        Button::new("tab-rename-save")
                                            .primary()
                                            .child("Save")
                                            .on_click(move |_, window, cx| {
                                                let value = save_input.read(cx).value().to_string();
                                                weak.update(cx, |this, cx| {
                                                    this.apply_tab_title(ix, &value, cx);
                                                })
                                                .ok();
                                                window.close_dialog(cx);
                                            }),
                                    ),
                            ),
                        ),
                    ),
            )
        });
        let to_focus = input.downgrade();
        cx.on_next_frame(window, move |_, window, cx| {
            to_focus
                .update(cx, |state, cx| state.focus(window, cx))
                .ok();
        });
        cx.notify();
    }

    fn tab_color_footer(&self, ix: usize, cx: &Context<Self>) -> AnyElement {
        let current = self.tab_meta(ix, cx).1;
        v_flex()
            .child(
                div()
                    .mx(px(4.))
                    .mt(px(2.))
                    .mb(px(3.))
                    .h(px(1.))
                    .bg(theme::border()),
            )
            .child(
                div()
                    .pl(px(24.))
                    .pr(px(8.))
                    .pb(px(2.))
                    .text_size(px(11.))
                    .text_color(theme::text_dim())
                    .child("Color"),
            )
            .child(
                h_flex()
                    .px(px(6.))
                    .pb(px(4.))
                    .gap(px(2.))
                    .items_center()
                    .children(self.color_swatches(ix, current, cx)),
            )
            .into_any_element()
    }

    fn color_swatches(
        &self,
        ix: usize,
        current: Option<TabColor>,
        cx: &Context<Self>,
    ) -> Vec<AnyElement> {
        let mut swatches = Vec::with_capacity(1 + TabColor::ALL.len());
        swatches.push(self.color_swatch(
            ix,
            0,
            None,
            "Default",
            current.is_none(),
            theme::status_online(),
            cx,
        ));
        for (slot, color) in TabColor::ALL.into_iter().enumerate() {
            swatches.push(self.color_swatch(
                ix,
                slot + 1,
                Some(color),
                color.label(),
                current == Some(color),
                color.paint(),
                cx,
            ));
        }
        swatches
    }

    fn color_swatch(
        &self,
        ix: usize,
        slot: usize,
        color: Option<TabColor>,
        name: &'static str,
        selected: bool,
        fill: Hsla,
        cx: &Context<Self>,
    ) -> AnyElement {
        let ring = cx.theme().foreground;
        div()
            .id(("terminal-tab-color", slot))
            .size(px(16.))
            .flex_none()
            .rounded_full()
            .flex()
            .items_center()
            .justify_center()
            .cursor_pointer()
            .border_2()
            .border_color(if selected {
                ring
            } else {
                Hsla { a: 0., ..ring }
            })
            .hover(|style| style.bg(theme::element_hover()))
            .tooltip(move |window, cx| Tooltip::new(name).build(window, cx))
            .on_click(cx.listener(move |this, _, _, cx| this.set_tab_color(ix, color, cx)))
            .child(div().size(px(10.)).rounded_full().bg(fill))
            .into_any_element()
    }

    /// The name on the terminal tab that has the keyboard.
    pub(crate) fn active_tab_label(&self, cx: &App) -> String {
        let Some(ix) = self.focused_index() else {
            return "Terminal".to_string();
        };
        let (title, _, file) = self.tab_meta(ix, cx);
        tab_label(
            ix,
            self.terminals.len() == 1,
            title.as_deref(),
            file.as_deref(),
        )
    }

    /// Show the agent. A non-empty `text` is attached as the terminal
    /// selection, marked with this session, the tab, and the lines.
    fn open_agent_from_terminal(
        &mut self,
        text: String,
        start_line: usize,
        end_line: usize,
        cx: &mut Context<Self>,
    ) {
        self.is_server_panel_shown = true;
        let cite = if text.trim().is_empty() {
            None
        } else {
            Some(crate::ui::session::panel::SelectionCite::new(
                &crate::ui::session::panel::session_login(
                    &self.conn_info.username,
                    &self.conn_info.host,
                ),
                &self.active_tab_label(cx),
                start_line,
                end_line,
                &text,
            ))
        };
        self.server_panel
            .update(cx, |panel, cx| panel.request_agent(cite, cx));
        cx.notify();
    }

    /// Show the agent chat, or hide the panel when that chat is already in front.
    fn toggle_agent_panel(&mut self, cx: &mut Context<Self>) {
        let showing = self.is_server_panel_shown && self.server_panel.read(cx).shows_agent();
        if showing {
            self.is_server_panel_shown = false;
            cx.notify();
            return;
        }
        self.is_server_panel_shown = true;
        self.server_panel
            .update(cx, |panel, cx| panel.request_agent(None, cx));
        cx.notify();
    }

    /// Show or hide this connection's inspector. The agent chat is a different
    /// face of the same side, so this switches to Overview and Snippets when
    /// the chat is what is open. Other hosts are left as they are.
    pub fn toggle_server_panel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let inspector_open =
            self.is_server_panel_shown && !self.server_panel.read(cx).shows_agent();
        if inspector_open {
            self.is_server_panel_shown = false;
        } else {
            self.is_server_panel_shown = true;
            self.server_panel
                .update(cx, |panel, cx| panel.show_inspector(cx));
        }
        // The click took the keys from whatever was on screen.
        if self.is_sftp_hidden {
            self.is_terminal_focus_pending = true;
        } else if let Some(browser) = &self.browser {
            browser.update(cx, |browser, cx| browser.focus_files(window, cx));
        }
        cx.notify();
    }

    /// The browser lays its panes out from the preferences, which notify
    /// nobody, so it is told to draw again.
    pub(crate) fn repaint_files(&mut self, cx: &mut Context<Self>) {
        if let Some(browser) = &self.browser {
            browser.update(cx, |_, cx| cx.notify());
        }
        cx.notify();
    }

    /// Tabs change from places that have no `Window` (a shell exiting, an
    /// async open), so the focus is moved here, on the next render.
    pub(crate) fn focus_terminal_if_pending(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        // A dialog on top keeps the keyboard. The request stays set, and the
        // terminal takes it once the dialog is gone.
        if window.has_active_dialog(cx) {
            return;
        }
        // The terminal is not on screen. Leave the request set.
        if !self.is_sftp_hidden {
            return;
        }
        if !std::mem::take(&mut self.is_terminal_focus_pending) {
            return;
        }
        if let Some(terminal) = self.active_terminal() {
            terminal.read(cx).focus_handle(cx).focus(window, cx);
        }
    }

    /// One "Terminal" tab, or numbered tabs once there are several shells,
    /// and the "+" button. The docked pane uses the same strip.
    pub(crate) fn render_terminal_tabs(&self, cx: &Context<Self>) -> AnyElement {
        self.render_pane_tabs(self.current_pane(), cx)
    }

    fn render_pane_tabs(&self, pane: usize, cx: &Context<Self>) -> AnyElement {
        // Scrolls sideways once the names no longer fit the session.
        let mut strip = h_flex()
            .id(("terminal-tab-strip", pane))
            .min_w_0()
            .overflow_x_scroll()
            .gap(px(2.))
            .items_center();
        let indices = self.pane_tabs(pane);
        if indices.len() > 1 {
            strip = strip.child(terminal_icon(theme::status_online()).ml(px(4.)).mr(px(2.)));
            for ix in indices {
                strip = strip.child(self.render_terminal_tab(ix, pane, cx));
            }
        } else if let Some(ix) = indices.first().copied() {
            strip = strip.child(self.render_single_tab(ix, pane, cx));
        }
        // A drop on the strip itself, not on a tab, puts the dragged tab at
        // the end of this cell's list.
        if self.terminals.len() >= 2 {
            strip = strip
                .on_drag_move(
                    cx.listener(|this, event: &DragMoveEvent<DraggedTab>, _, cx| {
                        // Every strip hears every move. Only the one under the
                        // pointer may clear an edge, or a later cell wipes the
                        // band the pointer is actually on.
                        if !bounds_contain(event.bounds, event.event.position) {
                            return;
                        }
                        if this.dock_hover.take().is_some() {
                            cx.notify();
                        }
                    }),
                )
                .drag_over::<DraggedTab>(|style, _, _, _| style.bg(theme::accent_soft()))
                .on_drop(cx.listener(move |this, tab: &DraggedTab, _, cx| {
                    this.move_into_pane(tab.ix, pane, None, false, cx);
                }));
        }
        if self.can_open_terminal() {
            strip = strip.child(
                header_button(("terminal-pane-add", pane), cx)
                    // The strip scrolls and would clip a corner badge, so
                    // the key takes the place of the "+" instead. Only the
                    // first cell shows it.
                    .map(|el| {
                        if pane == 0 && hints::is_shown(cx) {
                            el.child(hints::badge(hints::NEW_TERMINAL))
                        } else {
                            el.child(Icon::new(IconName::Plus).size(px(12.)))
                        }
                    })
                    .tooltip(|window, cx| {
                        Tooltip::new(format!("New terminal ({NEW_TERMINAL_SHORTCUT})"))
                            .build(window, cx)
                    })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.focused_pane = pane;
                        this.open_extra_terminal(cx);
                    })),
            );
        }
        strip.into_any_element()
    }

    fn render_terminal_tab(&self, ix: usize, pane: usize, cx: &Context<Self>) -> AnyElement {
        let is_active = self.is_sftp_hidden && self.shown(pane) == Some(ix);
        let alone = self.pane_tabs(pane).len() == 1;
        let fg = cx.theme().foreground;
        let close = div()
            .id(("terminal-tab-close", ix))
            .px(px(2.))
            .rounded(px(3.))
            .text_color(theme::text_dim())
            .hover(move |s| s.bg(theme::element_hover()).text_color(fg))
            // Mouse-down, not click: it must not reach the tab under it, which
            // would activate the tab being closed.
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    cx.stop_propagation();
                    this.close_terminal(ix, cx);
                }),
            )
            .child("\u{00D7}");

        let (title, color, file) = self.tab_meta(ix, cx);
        let label = tab_label(
            ix,
            self.terminals.len() == 1,
            title.as_deref(),
            file.as_deref(),
        );
        let tip = tab_tooltip(title.as_deref(), file.as_deref());

        let tab = header_button(("terminal-tab", ix), cx)
            .gap(px(4.))
            .when_some(tip, |el, tip| {
                el.tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
            })
            .when(is_active, |el| {
                el.text_color(cx.theme().foreground).font_semibold()
            })
            .when(is_active && color.is_none(), |el| el.bg(theme::element()))
            .when_some(color, |el, color| {
                let paint = color.paint();
                el.bg(tint(paint, if is_active { 0.32 } else { 0.16 }))
                    // One shell carries the colour on its icon. Several shells
                    // share one icon, so each tab gets a dot.
                    .when(!alone, |el| el.child(color_dot(paint)))
            })
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                    cx.stop_propagation();
                    this.open_tab_menu(ix, event.position, cx);
                }),
            )
            .on_click(cx.listener(move |this, _, _, cx| this.activate_terminal(ix, cx)))
            .on_aux_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
                if event.is_middle_click() {
                    cx.stop_propagation();
                    this.close_terminal(ix, cx);
                }
            }))
            .when(alone, |el| el.child(terminal_icon(mark_color(color))))
            .child(div().max_w(px(140.)).truncate().child(label.clone()))
            .when(self.terminals.len() > 1, |el| el.child(close));
        self.with_tab_drop(
            self.with_tab_drag(tab, ix, label.into(), mark_color(color), cx),
            ix,
            pane,
            cx,
        )
        .into_any_element()
    }

    /// The one chip shown when a pane has a single shell. It can still be
    /// dragged once another shell is open.
    fn render_single_tab(&self, ix: usize, pane: usize, cx: &Context<Self>) -> AnyElement {
        let (title, color, file) = self.tab_meta(ix, cx);
        let label = tab_label(
            ix,
            self.terminals.len() == 1,
            title.as_deref(),
            file.as_deref(),
        );
        let tip = tab_tooltip(title.as_deref(), file.as_deref());
        let mark = mark_color(color);
        let fg = cx.theme().foreground;
        let can_close = self.terminals.len() > 1;
        let close = can_close.then(|| {
            div()
                .id(("terminal-tab-close", ix))
                .px(px(2.))
                .rounded(px(3.))
                .text_color(theme::text_dim())
                .hover(move |s| s.bg(theme::element_hover()).text_color(fg))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, cx| {
                        cx.stop_propagation();
                        this.close_terminal(ix, cx);
                    }),
                )
                .child("\u{00D7}")
        });
        let live = self.is_sftp_hidden;
        let tab = h_flex()
            .id(("terminal-single-tab", pane))
            .h(px(26.))
            .px(px(9.))
            .gap(px(6.))
            .items_center()
            .rounded(px(6.))
            .when(live, |el| {
                el.bg(color
                    .map(|color| tint(color.paint(), 0.34))
                    .unwrap_or_else(theme::element))
            })
            .text_size(px(12.5))
            .text_color(if live {
                cx.theme().foreground
            } else {
                cx.theme().muted_foreground
            })
            .child(terminal_icon(mark))
            .child(div().max_w(px(140.)).truncate().child(label.clone()))
            .children(close)
            .when_some(tip, |el, tip| {
                el.tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
            })
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                    cx.stop_propagation();
                    this.open_tab_menu(ix, event.position, cx);
                }),
            )
            .on_click(cx.listener(move |this, _, _, cx| this.activate_terminal(ix, cx)))
            .on_aux_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
                if event.is_middle_click() {
                    cx.stop_propagation();
                    this.close_terminal(ix, cx);
                }
            }));
        self.with_tab_drop(
            self.with_tab_drag(tab, ix, label.into(), mark, cx),
            ix,
            pane,
            cx,
        )
        .into_any_element()
    }

    fn with_tab_drag(
        &self,
        el: gpui::Stateful<gpui::Div>,
        ix: usize,
        label: SharedString,
        mark: Hsla,
        cx: &Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        if self.terminals.len() < 2 {
            return el;
        }
        let session = cx.entity().downgrade();
        el.on_drag(DraggedTab { ix }, move |tab, _, _, cx| {
            let ix = tab.ix;
            session
                .update(cx, |this, cx| {
                    this.dragging_tab = Some(ix);
                    this.dock_hover = None;
                    this.tab_slot = None;
                    this.terminal_tab_menu = None;
                    cx.notify();
                })
                .ok();
            cx.new(|_| TabDragGhost {
                label: label.clone(),
                mark,
            })
        })
    }

    /// Drop target for a shell tab: the left half inserts before it, the
    /// right half after it. A line shows which side.
    fn with_tab_drop(
        &self,
        el: gpui::Stateful<gpui::Div>,
        ix: usize,
        pane: usize,
        cx: &Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        let before = self.tab_slot == Some((ix, false));
        let after = self.tab_slot == Some((ix, true));
        el.relative()
            .when(self.dragging_tab == Some(ix), |el| el.opacity(0.2))
            .when(before, |el| el.child(tab_insert_mark(true)))
            .when(after, |el| el.child(tab_insert_mark(false)))
            .on_drag_move(
                cx.listener(move |this, event: &DragMoveEvent<DraggedTab>, _, cx| {
                    this.track_tab_slot(ix, event.bounds, event.event.position, cx);
                }),
            )
            .on_drop(cx.listener(move |this, dragged: &DraggedTab, _, cx| {
                let after = this.tab_slot.is_some_and(|(id, after)| id == ix && after);
                this.move_into_pane(dragged.ix, pane, Some(ix), after, cx);
            }))
    }

    fn track_tab_slot(
        &mut self,
        ix: usize,
        bounds: Bounds<Pixels>,
        point: Point<Pixels>,
        cx: &mut Context<Self>,
    ) {
        if !bounds_contain(bounds, point) {
            if self.tab_slot.is_some_and(|(id, _)| id == ix) {
                self.tab_slot = None;
                cx.notify();
            }
            return;
        }
        let after = point.x >= bounds.center().x;
        if self.tab_slot == Some((ix, after)) {
            return;
        }
        self.tab_slot = Some((ix, after));
        self.dock_hover = None;
        cx.notify();
    }

    /// The right-click menu, painted over the terminal rather than inside the
    /// scrolling strip, which would clip it.
    pub(crate) fn render_terminal_tab_menu(&self, cx: &Context<Self>) -> Option<AnyElement> {
        let menu = self.terminal_tab_menu.as_ref()?;
        if menu.ix >= self.terminals.len() {
            return None;
        }
        let ix = menu.ix;
        let items = vec![ContextMenuItem::new(
            "terminal-tab-rename",
            "Rename\u{2026}",
            cx.listener(move |this, _, window, cx| {
                this.terminal_tab_menu = None;
                this.open_rename_tab(ix, window, cx);
            }),
        )
        .icon("icons/pen-line.svg")];
        Some(
            ContextMenu::new(
                "terminal-tab-menu",
                menu.position,
                Anchor::TopLeft,
                cx.listener(|this, _, _, cx| {
                    this.terminal_tab_menu = None;
                    cx.notify();
                }),
                items,
            )
            .footer(self.tab_color_footer(ix, cx))
            .into_any_element(),
        )
    }

    /// The terminal area: one cell, or a grid of them. While a tab is
    /// dragged, each cell's edges light up so it can be split again.
    pub(crate) fn render_terminal_block(&self, cx: &Context<Self>) -> AnyElement {
        let layout = self.layout.clone();
        let grid = self.render_layout_node(&layout, cx);
        let menu = if self.layout_has_split() {
            self.render_terminal_tab_menu(cx)
        } else {
            None
        };
        div()
            .relative()
            .size_full()
            .overflow_hidden()
            .child(grid)
            .children(menu)
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _: &MouseUpEvent, _, cx| {
                    if this.dragging_tab.take().is_some() {
                        this.dock_hover = None;
                        cx.notify();
                    }
                }),
            )
            .into_any_element()
    }

    fn render_layout_node(&self, node: &LayoutNode, cx: &Context<Self>) -> AnyElement {
        match node {
            LayoutNode::Pane(id) => self.render_one_pane(*id, cx),
            LayoutNode::Split {
                id,
                horizontal,
                state,
                first,
                second,
            } => {
                let leading = self.render_layout_node(first, cx);
                let trailing = self.render_layout_node(second, cx);
                self.split_pair(*id, *horizontal, state, leading, trailing)
            }
        }
    }

    /// One cell: its strip, when the grid has more than one, and its shell.
    fn render_one_pane(&self, pane: usize, cx: &Context<Self>) -> AnyElement {
        let view = self
            .shown(pane)
            .and_then(|ix| self.terminals.get(ix))
            .cloned();
        let show_tabs = self.layout_has_split();
        v_flex()
            .size_full()
            .overflow_hidden()
            .when(show_tabs, |el| {
                el.child(
                    h_flex()
                        .h(px(38.))
                        .flex_none()
                        .min_w_0()
                        .px(px(8.))
                        .items_center()
                        .border_b_1()
                        .border_color(theme::border())
                        .child(self.render_pane_tabs(pane, cx)),
                )
            })
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    if this.focused_pane != pane {
                        this.focused_pane = pane;
                        if let Some(ix) = this.shown(pane) {
                            this.active_terminal = ix;
                        }
                        this.is_terminal_focus_pending = true;
                        cx.notify();
                    }
                }),
            )
            .child(self.terminal_body(pane, view, cx))
            .into_any_element()
    }

    /// The strip above the session when the grid is a single cell. A split
    /// grid draws each cell's strip inside that cell instead.
    pub(crate) fn render_session_tabs(&self, cx: &Context<Self>) -> AnyElement {
        let tab_menu = self.render_terminal_tab_menu(cx);
        h_flex()
            .h(px(38.))
            .flex_none()
            .min_w_0()
            .px(px(8.))
            .items_center()
            .border_b_1()
            .border_color(theme::border())
            .child(self.render_terminal_tabs(cx))
            .children(tab_menu)
            .into_any_element()
    }

    /// The shell, with dock bands over it while a tab is dragged. The tab
    /// strip stays above this, so a drop there puts the tab back in the row.
    fn terminal_body(
        &self,
        slot: usize,
        view: Option<Entity<TerminalView>>,
        cx: &Context<Self>,
    ) -> AnyElement {
        div()
            .id(("terminal-body", slot))
            .relative()
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            .children(view)
            .when(self.dragging_tab.is_some(), |el| {
                el.child(self.render_dock_overlay(slot, cx))
            })
            .into_any_element()
    }

    fn split_pair(
        &self,
        id: u64,
        horizontal: bool,
        state: &Entity<ResizableState>,
        first: AnyElement,
        second: AnyElement,
    ) -> AnyElement {
        let panel = |child: AnyElement| {
            resizable_panel()
                .size(px(360.))
                .size_range(px(100.)..Pixels::MAX)
                .child(child)
        };
        let name = SharedString::from(format!("terminal-split-{id}"));
        if horizontal {
            h_resizable(name)
                .with_state(state)
                .child(panel(first))
                .child(panel(second))
                .into_any_element()
        } else {
            v_resizable(name)
                .with_state(state)
                .child(panel(first))
                .child(panel(second))
                .into_any_element()
        }
    }

    /// Four bands around the terminal. An edge docks a new split. The centre
    /// and the tab bar move the tab into the pane under the pointer.
    fn render_dock_overlay(&self, pane: usize, cx: &Context<Self>) -> AnyElement {
        let hover = self
            .dock_hover
            .and_then(|(id, edge)| (id == pane).then_some(edge));
        let from_other = self
            .dragging_tab
            .is_some_and(|ix| self.pane_for(ix) != Some(pane));
        let center_hot = self.dock_hover.is_none() && from_other;
        let band = |edge: DockEdge| {
            let hot = hover == Some(edge);
            let label = match edge {
                DockEdge::Left => "Dock left",
                DockEdge::Right => "Dock right",
                DockEdge::Top => "Dock above",
                DockEdge::Bottom => "Dock below",
            };
            div()
                .absolute()
                .map(|el| match edge {
                    DockEdge::Left => el.top(px(8.)).left(px(8.)).bottom(px(8.)).w(relative(0.2)),
                    DockEdge::Right => el.top(px(8.)).right(px(8.)).bottom(px(8.)).w(relative(0.2)),
                    DockEdge::Top => el
                        .top(px(8.))
                        .left(relative(0.22))
                        .right(relative(0.22))
                        .h(relative(0.2)),
                    DockEdge::Bottom => el
                        .bottom(px(8.))
                        .left(relative(0.22))
                        .right(relative(0.22))
                        .h(relative(0.2)),
                })
                .rounded(px(8.))
                .border_1()
                .border_color(if hot {
                    theme::accent()
                } else {
                    tint(theme::accent(), 0.45)
                })
                .bg(tint(theme::accent(), if hot { 0.34 } else { 0.14 }))
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(12.))
                .font_semibold()
                .text_color(if hot {
                    cx.theme().foreground
                } else {
                    theme::text_dim()
                })
                .child(label)
        };
        div()
            .id(("terminal-dock-overlay", pane))
            .absolute()
            .inset_0()
            .occlude()
            .child(band(DockEdge::Left))
            .child(band(DockEdge::Right))
            .child(band(DockEdge::Top))
            .child(band(DockEdge::Bottom))
            .when(center_hot, |el| {
                el.child(
                    div()
                        .absolute()
                        .top(relative(0.28))
                        .left(relative(0.28))
                        .right(relative(0.28))
                        .bottom(relative(0.28))
                        .rounded(px(8.))
                        .border_1()
                        .border_color(theme::accent())
                        .bg(tint(theme::accent(), 0.28))
                        .flex()
                        .items_center()
                        .justify_center()
                        .text_size(px(12.))
                        .font_semibold()
                        .text_color(cx.theme().foreground)
                        .child("Move here"),
                )
            })
            .on_drag_move(
                cx.listener(move |this, event: &DragMoveEvent<DraggedTab>, _, cx| {
                    // Same as the strips: a cell the pointer has left must not
                    // clear the band of the cell it is on.
                    if !bounds_contain(event.bounds, event.event.position) {
                        return;
                    }
                    let edge = dock_edge_at(event.bounds, event.event.position);
                    let next = edge.map(|edge| (pane, edge));
                    if this.dock_hover != next {
                        this.dock_hover = next;
                        cx.notify();
                    }
                }),
            )
            .on_drop(cx.listener(move |this, tab: &DraggedTab, _, cx| {
                if let Some((id, edge)) = this.dock_hover {
                    if id == pane {
                        this.dock_on_edge(tab.ix, pane, edge, cx);
                        return;
                    }
                }
                this.move_into_pane(tab.ix, pane, None, false, cx);
            }))
            .into_any_element()
    }

    pub(crate) fn render_agent_button(&self, cx: &Context<Self>) -> Option<AnyElement> {
        if !self.server_panel.read(cx).agent_enabled(cx) {
            return None;
        }
        let is_on = self.is_server_panel_shown && self.server_panel.read(cx).shows_agent();
        let button = toggle_button(
            SharedString::from(format!("agent-{}", self.server_id)),
            is_on,
            cx,
        )
        .px(px(5.))
        .child(Icon::empty().path("icons/message-square.svg").size(px(15.)))
        .tooltip(|window, cx| Tooltip::new("Agent").build(window, cx))
        .on_click(cx.listener(|this, _, _, cx| this.toggle_agent_panel(cx)))
        .into_any_element();
        Some(button)
    }

    pub(crate) fn render_server_panel_toggle(&self, cx: &Context<Self>) -> AnyElement {
        let inspector_open =
            self.is_server_panel_shown && !self.server_panel.read(cx).shows_agent();
        toggle_button(
            SharedString::from(format!("server-panel-{}", self.server_id)),
            inspector_open,
            cx,
        )
        .relative()
        .px(px(5.))
        .child(Icon::empty().path("icons/panel-right.svg").size(px(15.)))
        .when(hints::is_shown(cx), |el| {
            el.child(hints::corner_badge(hints::SERVER_PANEL))
        })
        .tooltip(|window, cx| {
            Tooltip::new(format!("Server panel ({SERVER_PANEL_SHORTCUT})")).build(window, cx)
        })
        .on_click(cx.listener(|this, _, window, cx| this.toggle_server_panel(window, cx)))
        .into_any_element()
    }
}

fn terminal_icon(color: Hsla) -> Icon {
    Icon::empty()
        .path("icons/square-terminal.svg")
        .size(px(14.))
        .text_color(color)
}

/// A small flat button sized for the session and terminal headers.
pub(crate) fn header_button(
    id: impl Into<gpui::ElementId>,
    cx: &Context<ServerSession>,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(id)
        .flex()
        .items_center()
        .h(px(26.))
        .px(px(8.))
        .rounded(px(6.))
        .text_size(px(12.5))
        .text_color(cx.theme().muted_foreground)
        .cursor_pointer()
        .hover(|s| s.bg(theme::field()))
        .active(|s| s.bg(theme::element_active()))
}

/// A header button that stays pressed while what it shows is on screen.
fn toggle_button(
    id: impl Into<gpui::ElementId>,
    is_on: bool,
    cx: &Context<ServerSession>,
) -> gpui::Stateful<gpui::Div> {
    header_button(id, cx).gap(px(6.)).when(is_on, |el| {
        el.bg(theme::element()).text_color(cx.theme().foreground)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_a_tab_before_the_active_one_keeps_the_same_shell_active() {
        // Tabs 0 1 [2] 3, close 0: the active shell is now at index 1.
        assert_eq!(active_after_close(2, 0, 3), 1);
    }

    #[test]
    fn closing_a_tab_after_the_active_one_changes_nothing() {
        assert_eq!(active_after_close(1, 3, 3), 1);
    }

    #[test]
    fn closing_the_active_tab_moves_to_the_one_that_took_its_place() {
        assert_eq!(active_after_close(1, 1, 3), 1);
    }

    #[test]
    fn closing_the_last_active_tab_moves_to_the_new_last_one() {
        assert_eq!(active_after_close(3, 3, 3), 2);
        assert_eq!(active_after_close(1, 1, 1), 0);
    }

    #[test]
    fn a_custom_name_replaces_the_number_and_the_file() {
        assert_eq!(tab_label(0, true, Some("logs"), None), "logs");
        assert_eq!(tab_label(1, false, None, None), "2");
        assert_eq!(tab_label(0, true, None, None), "Terminal");
        assert_eq!(tab_label(0, true, None, Some("/var/log/syslog")), "syslog");
        assert_eq!(
            tab_label(2, false, None, Some("/var/log/syslog")),
            "3 syslog"
        );
        assert_eq!(
            tab_label(2, false, Some("logs"), Some("/var/log/syslog")),
            "logs"
        );
    }

    #[test]
    fn a_blank_title_clears_and_the_default_is_not_stored() {
        assert_eq!(clean_tab_title("   "), None);
        assert_eq!(clean_tab_title("  logs  "), Some("logs".to_string()));
        assert_eq!(clean_tab_title("a\nb"), Some("ab".to_string()));
        assert_eq!(
            clean_tab_title(&"a".repeat(100)).unwrap().chars().count(),
            80
        );
        assert_eq!(stored_tab_title("Terminal", "Terminal"), None);
        assert_eq!(
            stored_tab_title("logs", "Terminal"),
            Some("logs".to_string())
        );
        assert_eq!(stored_tab_title("  ", "Terminal"), None);
    }

    #[test]
    fn the_tooltip_keeps_the_path_when_the_tab_was_renamed() {
        assert_eq!(
            tab_tooltip(Some("logs"), Some("/var/log/syslog")),
            Some("logs — /var/log/syslog".to_string())
        );
        assert_eq!(tab_tooltip(Some("logs"), None), None);
        assert_eq!(
            tab_tooltip(None, Some("/var/log/syslog")),
            Some("/var/log/syslog".to_string())
        );
    }

    #[test]
    fn moving_a_tab_keeps_every_other_index_unique() {
        // [A B C D], move B (1) to the end.
        assert_eq!(index_after_move(1, 1, 3), 3);
        assert_eq!(index_after_move(0, 1, 3), 0);
        assert_eq!(index_after_move(2, 1, 3), 1);
        assert_eq!(index_after_move(3, 1, 3), 2);
        // Move D (3) to the front.
        assert_eq!(index_after_move(3, 3, 0), 0);
        assert_eq!(index_after_move(0, 3, 0), 1);
        assert_eq!(index_after_move(1, 3, 0), 2);
        assert_eq!(index_after_move(2, 3, 0), 3);
    }

    #[test]
    fn closing_one_docked_tab_keeps_the_rest_of_that_list() {
        let (tabs, active) = dock_after_close(&[1, 4], 4, 1).unwrap();
        assert_eq!(tabs, vec![3]);
        assert_eq!(active, 3);
        let (tabs, active) = dock_after_close(&[1, 4], 4, 4).unwrap();
        assert_eq!(tabs, vec![1]);
        assert_eq!(active, 1);
        assert!(dock_after_close(&[2], 2, 2).is_none());
    }

    #[test]
    fn a_tab_lands_on_the_side_it_was_dropped_on() {
        // The dragged tab is already out of the list.
        assert_eq!(tab_insert_index(&[1, 2], Some(1), false), 0);
        assert_eq!(tab_insert_index(&[1, 2], Some(1), true), 1);
        assert_eq!(tab_insert_index(&[1, 2], Some(2), true), 2);
        assert_eq!(tab_insert_index(&[1, 2], None, false), 2);
        assert_eq!(tab_insert_index(&[1, 2], Some(9), true), 2);
    }

    #[test]
    fn a_point_near_an_edge_picks_that_dock() {
        use crate::ui::session::DockEdge;
        let bounds = gpui::Bounds::new(
            gpui::point(gpui::px(0.), gpui::px(0.)),
            gpui::size(gpui::px(400.), gpui::px(300.)),
        );
        assert_eq!(
            dock_edge_at(bounds, gpui::point(gpui::px(12.), gpui::px(150.))),
            Some(DockEdge::Left)
        );
        assert_eq!(
            dock_edge_at(bounds, gpui::point(gpui::px(390.), gpui::px(150.))),
            Some(DockEdge::Right)
        );
        assert_eq!(
            dock_edge_at(bounds, gpui::point(gpui::px(200.), gpui::px(8.))),
            Some(DockEdge::Top)
        );
        assert_eq!(
            dock_edge_at(bounds, gpui::point(gpui::px(200.), gpui::px(290.))),
            Some(DockEdge::Bottom)
        );
        assert_eq!(
            dock_edge_at(bounds, gpui::point(gpui::px(200.), gpui::px(150.))),
            None
        );
    }
}
