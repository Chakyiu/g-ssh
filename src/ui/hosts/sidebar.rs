use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::ui::scale::px;
use gpui::prelude::*;
use gpui::{
    div, Anchor, AnyElement, Bounds, Context, DragMoveEvent, Entity, EventEmitter, MouseButton,
    MouseDownEvent, Pixels, Point, SharedString, Window,
};

use gpui_component::{h_flex, tooltip::Tooltip, v_flex, ActiveTheme as _, Icon, IconName};
use uuid::Uuid;

use crate::theme;
use crate::ui::app::ToggleSettings;
use crate::ui::hints;
use crate::ui::hosts::sharing;
use crate::ui::menu::{ContextMenu, ContextMenuItem, PopoverMenu};
use crate::ui::sync::SyncService;
use crate::ui::VaultState;
use gssh::vault::ServerEntrySummary;

pub(crate) const SIDEBAR_WIDTH: f32 = 232.;
const ROW_HEIGHT: f32 = 28.;
const SIDEBAR_GROUP: &str = "sidebar-host-row";
/// Cap on how many closed-but-recent hosts the RECENT zone shows. The full
/// catalog lives behind the "All hosts" button, so this stays a short list.
const RECENT_LIMIT: usize = 6;

/// Live connection state of a host that has an open session. Hosts without an
/// open session are absent from the list and rendered as [`HostStatus::Offline`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    /// No open session.
    Offline,
    /// Session opened, SSH handshake in progress.
    Connecting,
    /// Live SSH connection.
    Connected,
    /// Session open but the connection dropped.
    Disconnected,
}

/// Where a dragged host would land. `after` is the lower half of the row.
struct HostDropSlot {
    id: Uuid,
    after: bool,
}

/// The host being dragged, and the folder it may be reordered inside.
/// Dropping it on a row in another folder does nothing: a drag does not
/// move a host between folders.
#[derive(Clone)]
struct DraggedHost {
    id: Uuid,
    group_key: String,
}

pub enum SidebarEvent {
    OpenServer(Uuid),
    OpenSftp(Uuid),
    CloseServer(Uuid),
    AddServerRequested,
    ShowAllServers,
    EditServerRequested(Uuid),
    DuplicateServerRequested(Uuid),
    DeleteServerRequested(Uuid),
    SettingsRequested,
}

pub struct Sidebar {
    vault_state: Entity<VaultState>,
    active_server_id: Option<String>,
    /// Open sessions in tab order. A `Vec`, not a map, so rows don't jump as
    /// sessions come and go.
    sessions: Vec<(String, HostStatus)>,
    /// Which host's "more" menu is open (at most one).
    open_menu_for: Option<Uuid>,
    /// The menu the last outside click closed, and when. `on_mouse_down_out`
    /// runs before the button's own handler and clears `open_menu_for`, so
    /// without this a click on the button of an open menu would reopen it.
    menu_dismissed_at: Option<(Uuid, Instant)>,
    /// Right-click on a host: open a terminal or SFTP tab.
    host_menu: Option<(Uuid, Point<Pixels>)>,
    /// Folder paths the user folded shut. A path absent here is open, so a
    /// new folder shows its hosts without a saved preference.
    collapsed_groups: HashSet<String>,
    /// The host being dragged, so its row can dim until the gesture ends.
    dragging_host: Option<Uuid>,
    /// The row under the pointer, and whether the host would land after it.
    drop_slot: Option<HostDropSlot>,
}

impl EventEmitter<SidebarEvent> for Sidebar {}

impl Sidebar {
    pub fn new(
        vault_state: Entity<VaultState>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        cx.observe(&vault_state, |_, _, cx| cx.notify()).detach();
        Self {
            vault_state,
            active_server_id: None,
            sessions: Vec::new(),
            open_menu_for: None,
            menu_dismissed_at: None,
            host_menu: None,
            collapsed_groups: HashSet::new(),
            dragging_host: None,
            drop_slot: None,
        }
    }

    pub fn set_active_server(&mut self, id: Option<String>, cx: &mut Context<Self>) {
        self.active_server_id = id;
        cx.notify();
    }

    /// Replace the ordered list of open sessions. The caller (app_view) owns
    /// tab order, so the OPEN zone mirrors it exactly.
    pub fn set_sessions(&mut self, sessions: Vec<(String, HostStatus)>, cx: &mut Context<Self>) {
        if self.sessions != sessions {
            self.sessions = sessions;
            cx.notify();
        }
    }

    /// One host row. `compact` rows (recent hosts) are dimmed. `show_close`
    /// adds a disconnect button, for open sessions only. `reorder_group` is
    /// the folder the row can be dragged within. `None` for rows whose order
    /// is the tab list or recency. `Some("")` is the folder of hosts that
    /// have no folder of their own.
    #[allow(clippy::too_many_arguments)]
    fn host_row(
        &self,
        ui_idx: usize,
        entry: &ServerEntrySummary,
        subtitle: SharedString,
        status: HostStatus,
        compact: bool,
        show_close: bool,
        shortcut: Option<SharedString>,
        reorder_group: Option<&str>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        // While the shortcut hints show, the tab number takes the place of the
        // subtitle and the row controls.
        let hint = shortcut.filter(|_| hints::is_shown(cx));
        let theme = cx.theme();
        let bg_element_hover = theme.list_hover;
        let bg_element_active = theme.list_active;
        let text = theme.foreground;
        let text_muted = theme.muted_foreground;
        let text_dim = theme::text_dim();
        let row_hover = theme::field();
        let row_selected = theme::accent_soft();
        let status_online = theme::status_online();
        let status_connecting = theme.warning;
        let status_down = theme.danger;

        let entry_id = entry.id;
        // An imported host can have an empty label; its address stands in.
        let label: SharedString = if entry.label.is_empty() {
            entry.host.clone()
        } else {
            entry.label.clone()
        }
        .into();
        let team_name = entry.team_name.clone();
        let entry_id_str = entry_id.to_string();
        let is_active = self.active_server_id.as_deref() == Some(entry_id_str.as_str());
        let group_id: SharedString = format!("{SIDEBAR_GROUP}-{ui_idx}").into();

        let label_color = if compact { text_muted } else { text };

        let dot_color = match status {
            HostStatus::Connected => status_online,
            HostStatus::Connecting => status_connecting,
            HostStatus::Disconnected => status_down,
            HostStatus::Offline => theme::status_off(),
        };
        let dot = div().size(px(6.)).flex_none().rounded_full().bg(dot_color);

        let row = h_flex()
            .id(("sidebar-host", ui_idx))
            .group(group_id.clone())
            .relative()
            .h(px(ROW_HEIGHT))
            .gap(px(8.))
            .px(px(8.))
            .rounded(px(6.))
            .items_center()
            .cursor_pointer()
            .when(is_active, |el| el.bg(row_selected))
            .when(!is_active, |el| {
                el.hover(|s| s.bg(row_hover))
                    .active(|s| s.bg(bg_element_active))
            })
            .child(dot)
            // The name, and right after it the mark of a host shared with a
            // team. The mark stays with the name: further right it would hang
            // in the space the subtitle leaves empty while the row is hovered.
            // The row is too narrow for the team's name, so that is a tooltip.
            .child(
                h_flex()
                    .flex_1()
                    .min_w_0()
                    .gap(px(4.))
                    .items_center()
                    .child(
                        div()
                            .min_w_0()
                            .text_color(label_color)
                            .text_size(px(13.))
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .truncate()
                            .child(label.clone()),
                    )
                    .children(team_name.map(|team| {
                        div()
                            .id(("sidebar-host-team", ui_idx))
                            .flex_none()
                            .text_color(text_dim)
                            .tooltip(move |window, cx| {
                                Tooltip::new(format!("Shared with {team}")).build(window, cx)
                            })
                            .child(Icon::new(IconName::User).size(px(10.)))
                    })),
            )
            // Trailing slot: the subtitle normally, the row controls on hover.
            // The controls sit on top so the two never fight for width.
            .child(
                div()
                    .flex_none()
                    .max_w(px(88.))
                    .min_w_0()
                    .text_color(text_dim)
                    .text_size(px(11.5))
                    .truncate()
                    .group_hover(group_id.clone(), |s| s.invisible())
                    .when(is_active || hint.is_some(), |el| el.invisible())
                    .child(subtitle),
            )
            .child(
                h_flex()
                    .absolute()
                    .right(px(4.))
                    .flex_none()
                    .gap(px(1.))
                    .items_center()
                    .when_some(hint.clone(), |row, keys| row.child(hints::badge(keys)))
                    .when(show_close && hint.is_none(), |row| {
                        row.child(
                            div()
                                .id(("sidebar-host-close", ui_idx))
                                .size(px(16.))
                                .flex()
                                .items_center()
                                .justify_center()
                                .rounded(px(3.))
                                .text_color(text_dim)
                                .invisible()
                                .when(is_active, |el| el.visible())
                                .group_hover(group_id.clone(), |s| s.visible())
                                .hover(|s| s.bg(bg_element_hover).text_color(text))
                                .active(|s| s.bg(bg_element_active).text_color(theme::red_error()))
                                .tooltip(|window, cx| {
                                    Tooltip::new("Close session").build(window, cx)
                                })
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(move |_, _: &MouseDownEvent, _, cx| {
                                        cx.stop_propagation();
                                        cx.emit(SidebarEvent::CloseServer(entry_id));
                                    }),
                                )
                                .child(Icon::new(IconName::Close).size(px(10.))),
                        )
                    })
                    .when(hint.is_none(), |row| {
                        row.child(self.host_more_menu(ui_idx, entry_id, show_close, cx))
                    }),
            )
            .on_click(cx.listener(move |_, _, _, cx| {
                cx.emit(SidebarEvent::OpenServer(entry_id));
            }))
            .on_mouse_down(
                MouseButton::Right,
                cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                    cx.stop_propagation();
                    this.host_menu = Some((entry_id, event.position));
                    cx.notify();
                }),
            );
        match reorder_group {
            Some(group_key) => self.with_host_reorder(row, entry_id, group_key, label, cx),
            None => row,
        }
        .into_any_element()
    }

    /// The "more" trigger and its dropdown for a host row. The [`PopoverMenu`]
    /// drops below the trigger and never covers it, so a second click on the
    /// trigger closes the menu.
    fn host_more_menu(
        &self,
        ui_idx: usize,
        entry_id: Uuid,
        has_session: bool,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let theme = cx.theme();
        let bg_element_hover = theme.list_hover;
        let bg_element_active = theme.list_active;
        let text = theme.foreground;
        let text_dim = theme::text_dim();

        let is_menu_open = self.open_menu_for == Some(entry_id);
        let is_active = self.active_server_id.as_deref() == Some(entry_id.to_string().as_str());
        let group_id: SharedString = format!("{SIDEBAR_GROUP}-{ui_idx}").into();

        // The trigger button. Open/pressed both get a solid highlight so the
        // control clearly reacts; the row owns hover/visibility reveal.
        let trigger = div()
            .id(("sidebar-host-more-btn", ui_idx))
            .size(px(16.))
            .flex()
            .items_center()
            .justify_center()
            .rounded(px(3.))
            .text_color(if is_menu_open { text } else { text_dim })
            .when(is_menu_open, |el| el.bg(bg_element_active).visible())
            .when(!is_menu_open, |el| {
                el.invisible()
                    .when(is_active, |el| el.visible())
                    .group_hover(group_id.clone(), |s| s.visible())
                    .hover(|s| s.bg(bg_element_hover).text_color(text))
                    // Pressed feedback before the menu paints.
                    .active(|s| s.bg(bg_element_active).text_color(text))
            })
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _: &MouseDownEvent, _, cx| {
                    cx.stop_propagation();
                    // The menu's outside-click dismiss fires in the capture phase,
                    // before this bubble-phase handler, and clears `open_menu_for`.
                    // If it just closed *this* row's menu, treat the click as a
                    // toggle-off and stay closed; otherwise open this row's menu
                    // (covers both first-open and switching between rows).
                    let toggled_off = this.menu_dismissed_at.take().is_some_and(|(id, at)| {
                        id == entry_id && at.elapsed() < Duration::from_millis(200)
                    });
                    if toggled_off || this.open_menu_for == Some(entry_id) {
                        this.open_menu_for = None;
                    } else {
                        this.open_menu_for = Some(entry_id);
                    }
                    cx.notify();
                }),
            )
            .child(Icon::new(IconName::Ellipsis).size(px(12.)));

        let sharing_items: Vec<ContextMenuItem> =
            sharing::menu_choices(&self.vault_state, entry_id, cx)
                .into_iter()
                .enumerate()
                .map(|(choice_ix, (label, target))| {
                    ContextMenuItem::new(
                        ("sidebar-menu-share", choice_ix),
                        label,
                        cx.listener(move |this, _, _, cx| {
                            this.open_menu_for = None;
                            sharing::set_shared(&this.vault_state, entry_id, target, cx);
                            cx.notify();
                        }),
                    )
                })
                .collect();

        let mut menu = PopoverMenu::new(("sidebar-host-more", ui_idx), is_menu_open, trigger)
            .anchor(Anchor::TopRight)
            .item(
                ContextMenuItem::new(
                    "sidebar-menu-sftp",
                    "Open SFTP",
                    cx.listener(move |this, _, _, cx| {
                        this.open_menu_for = None;
                        cx.emit(SidebarEvent::OpenSftp(entry_id));
                        cx.notify();
                    }),
                )
                .icon("icons/folder-open.svg"),
            )
            .item(
                ContextMenuItem::new(
                    "sidebar-menu-edit",
                    "Edit",
                    cx.listener(move |this, _, _, cx| {
                        this.open_menu_for = None;
                        cx.emit(SidebarEvent::EditServerRequested(entry_id));
                        cx.notify();
                    }),
                )
                .icon("icons/pen-line.svg"),
            )
            .item(
                ContextMenuItem::new(
                    "sidebar-menu-duplicate",
                    "Duplicate",
                    cx.listener(move |this, _, _, cx| {
                        this.open_menu_for = None;
                        cx.emit(SidebarEvent::DuplicateServerRequested(entry_id));
                        cx.notify();
                    }),
                )
                .icon("icons/clipboard-copy.svg"),
            );

        if has_session {
            menu = menu.item(
                ContextMenuItem::new(
                    "sidebar-menu-close",
                    "Close session",
                    cx.listener(move |this, _, _, cx| {
                        this.open_menu_for = None;
                        cx.emit(SidebarEvent::CloseServer(entry_id));
                        cx.notify();
                    }),
                )
                .icon("icons/x.svg"),
            );
        }

        menu.items(sharing_items)
            .item(
                ContextMenuItem::new(
                    "sidebar-menu-delete",
                    "Delete",
                    cx.listener(move |this, _, _, cx| {
                        this.open_menu_for = None;
                        cx.emit(SidebarEvent::DeleteServerRequested(entry_id));
                        cx.notify();
                    }),
                )
                .icon("icons/trash.svg")
                .danger(),
            )
            .on_dismiss(cx.listener(move |this, _, _, cx| {
                // Record which menu we just closed so the trigger's bubble-phase
                // handler can tell a toggle-off from a row switch (see trigger).
                this.menu_dismissed_at = Some((entry_id, Instant::now()));
                this.open_menu_for = None;
                cx.notify();
            }))
    }
}

/// The name a host row shows: the label, or the address when the label is empty.
fn host_display_name(entry: &ServerEntrySummary) -> &str {
    if entry.label.is_empty() {
        &entry.host
    } else {
        &entry.label
    }
}

/// The same separator [`gssh::vault`] uses when it joins a folder path, so
/// "Work / EU" is the group EU inside the group Work.
const GROUP_PATH_SEP: &str = " / ";

/// One group in the sidebar tree. `path` is the full "parent / child" key.
/// Hosts on this node sit in this group itself; hosts in a child group sit
/// on that child.
struct GroupNode<'a> {
    name: String,
    path: String,
    hosts: Vec<&'a ServerEntrySummary>,
    children: Vec<GroupNode<'a>>,
}

/// Hosts nested by each segment of their group path. A host with no group
/// lands in the ungrouped list, which the sidebar paints after the tree.
fn group_tree<'a>(
    entries: impl IntoIterator<Item = &'a ServerEntrySummary>,
) -> (Vec<GroupNode<'a>>, Vec<&'a ServerEntrySummary>) {
    let mut roots = Vec::new();
    let mut ungrouped = Vec::new();
    for entry in entries {
        let Some(path) = entry.group_name.as_deref().filter(|name| !name.is_empty()) else {
            ungrouped.push(entry);
            continue;
        };
        let segments: Vec<&str> = path
            .split(GROUP_PATH_SEP)
            .filter(|segment| !segment.is_empty())
            .collect();
        if segments.is_empty() {
            ungrouped.push(entry);
            continue;
        }
        insert_host(&mut roots, "", &segments, entry);
    }
    sort_nodes(&mut roots);
    ungrouped.sort_by_key(|entry| host_order_key(entry));
    (roots, ungrouped)
}

fn insert_host<'a>(
    nodes: &mut Vec<GroupNode<'a>>,
    parent_path: &str,
    segments: &[&str],
    entry: &'a ServerEntrySummary,
) {
    let Some((name, rest)) = segments.split_first() else {
        return;
    };
    let path = if parent_path.is_empty() {
        (*name).to_string()
    } else {
        format!("{parent_path}{GROUP_PATH_SEP}{name}")
    };
    if !nodes.iter().any(|node| node.name == *name) {
        nodes.push(GroupNode {
            name: (*name).to_string(),
            path: path.clone(),
            hosts: Vec::new(),
            children: Vec::new(),
        });
    }
    let Some(node) = nodes.iter_mut().find(|node| node.name == *name) else {
        return;
    };
    if rest.is_empty() {
        node.hosts.push(entry);
    } else {
        insert_host(&mut node.children, &path, rest, entry);
    }
}

fn sort_nodes(nodes: &mut [GroupNode<'_>]) {
    nodes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    for node in nodes {
        node.hosts.sort_by_key(|entry| host_order_key(entry));
        sort_nodes(&mut node.children);
    }
}

/// Hosts in this group and in every group under it.
/// Ids and saved places for one folder, in the order the sidebar shows them.
/// `group_key` is empty for hosts that have no folder.
fn group_orders(entries: &[ServerEntrySummary], group_key: &str) -> Vec<(Uuid, i64)> {
    let (roots, ungrouped) = group_tree(entries.iter());
    let hosts = if group_key.is_empty() {
        ungrouped
    } else {
        hosts_on_path(&roots, group_key)
    };
    hosts
        .into_iter()
        .map(|entry| (entry.id, entry.sort_order))
        .collect()
}

fn hosts_on_path<'a>(nodes: &[GroupNode<'a>], path: &str) -> Vec<&'a ServerEntrySummary> {
    for node in nodes {
        if node.path == path {
            return node.hosts.clone();
        }
        if node.children.iter().any(|child| path_contains(child, path)) {
            return hosts_on_path(&node.children, path);
        }
    }
    Vec::new()
}

fn path_contains(node: &GroupNode<'_>, path: &str) -> bool {
    node.path == path || node.children.iter().any(|child| path_contains(child, path))
}

fn host_count(node: &GroupNode<'_>) -> usize {
    node.hosts.len() + node.children.iter().map(host_count).sum::<usize>()
}

/// Placed hosts first, in the order the user dragged them. A host that has
/// never been placed (`0`) follows them, by name.
pub(crate) fn host_order_key(entry: &ServerEntrySummary) -> (u8, i64, String, Uuid) {
    let name = host_display_name(entry).to_lowercase();
    if entry.sort_order > 0 {
        (0, entry.sort_order, name, entry.id)
    } else {
        (1, 0, name, entry.id)
    }
}

/// Gap between two saved places, so a later drag can land between them
/// without rewriting the rest of the folder.
const ORDER_GAP: i64 = 1024;

/// Move `dragged` to the `target` row. `after` lands it on the lower half.
/// `None` when that is already where it sits.
fn place_host(ids: &[Uuid], dragged: Uuid, target: Uuid, after: bool) -> Option<Vec<Uuid>> {
    if dragged == target {
        return None;
    }
    let from = ids.iter().position(|id| *id == dragged)?;
    let mut next = ids.to_vec();
    next.remove(from);
    let mut index = next.iter().position(|id| *id == target)?;
    if after {
        index += 1;
    }
    next.insert(index, dragged);
    (next != ids).then_some(next)
}

/// Ranks to write after a drag. One host when a single rank puts it between
/// its new neighbors. The whole folder when a host that was never placed has
/// to sit where a single rank cannot describe, because an unset host always
/// sorts after every placed one.
fn orders_after_move(
    current: &[(Uuid, i64)],
    dragged: Uuid,
    target: Uuid,
    after: bool,
) -> Option<Vec<(Uuid, i64)>> {
    let ids: Vec<Uuid> = current.iter().map(|(id, _)| *id).collect();
    let next = place_host(&ids, dragged, target, after)?;
    let order_of = |id: Uuid| -> i64 {
        current
            .iter()
            .find(|(candidate, _)| *candidate == id)
            .map(|(_, order)| *order)
            .unwrap_or(0)
    };
    let index = next.iter().position(|id| *id == dragged)?;
    let placed = |id: Uuid| order_of(id) > 0;
    let before_placed = next[..index].iter().copied().all(placed);
    let rest = &next[index + 1..];
    let placed_run = rest.iter().copied().take_while(|id| placed(*id)).count();
    // Unset hosts form a tail. A rank can land in front of that tail. It
    // cannot land inside it: an unset host would still sort after the rank.
    let tail_is_unset = rest[placed_run..].iter().copied().all(|id| !placed(id));
    if before_placed && tail_is_unset {
        let left = next[..index].last().copied().map(order_of);
        let right = (placed_run > 0).then(|| order_of(rest[0]));
        if let Some(rank) = rank_between(left, right) {
            if rank != order_of(dragged) {
                return Some(vec![(dragged, rank)]);
            }
        }
    }
    Some(spaced(&next))
}

fn rank_between(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    let rank = match (left, right) {
        (Some(left), Some(right)) if right > left + 1 => left + (right - left) / 2,
        (Some(left), None) => left.checked_add(ORDER_GAP)?,
        (None, Some(right)) => right / 2,
        _ => return None,
    };
    (rank > 0).then_some(rank)
}

fn spaced(ids: &[Uuid]) -> Vec<(Uuid, i64)> {
    ids.iter()
        .enumerate()
        .map(|(index, id)| (*id, (index as i64 + 1) * ORDER_GAP))
        .collect()
}

fn pointer_over(bounds: Bounds<Pixels>, point: Point<Pixels>) -> bool {
    let x = point.x - bounds.origin.x;
    let y = point.y - bounds.origin.y;
    x >= px(0.) && y >= px(0.) && x <= bounds.size.width && y <= bounds.size.height
}

fn order_mark(at_top: bool) -> gpui::Div {
    let mark = div()
        .absolute()
        .left(px(8.))
        .right(px(8.))
        .h(px(2.))
        .rounded_full()
        .bg(theme::accent());
    if at_top {
        mark.top(px(0.))
    } else {
        mark.bottom(px(0.))
    }
}

struct HostDragGhost {
    label: SharedString,
}

impl Render for HostDragGhost {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        h_flex()
            .h(px(ROW_HEIGHT))
            .px(px(8.))
            .gap(px(8.))
            .items_center()
            .rounded(px(6.))
            .border_1()
            .border_color(theme::border_focused())
            .bg(cx.theme().popover)
            .shadow_md()
            .text_size(px(13.))
            .text_color(cx.theme().foreground)
            .child(div().max_w(px(180.)).truncate().child(self.label.clone()))
    }
}

impl Sidebar {
    fn with_host_reorder(
        &self,
        row: gpui::Stateful<gpui::Div>,
        entry_id: Uuid,
        group_key: &str,
        label: SharedString,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        let show_before = self
            .drop_slot
            .as_ref()
            .is_some_and(|slot| slot.id == entry_id && !slot.after);
        let show_after = self
            .drop_slot
            .as_ref()
            .is_some_and(|slot| slot.id == entry_id && slot.after);
        let dragging = self.dragging_host == Some(entry_id);
        let sidebar = cx.entity().downgrade();
        let move_group = group_key.to_string();
        let drop_group = move_group.clone();

        row.when(dragging, |row| row.opacity(0.45))
            .when(show_before, |row| row.child(order_mark(true)))
            .when(show_after, |row| row.child(order_mark(false)))
            .on_drag(
                DraggedHost {
                    id: entry_id,
                    group_key: move_group.clone(),
                },
                move |_, _, _, cx| {
                    sidebar
                        .update(cx, |this, cx| {
                            this.dragging_host = Some(entry_id);
                            this.drop_slot = None;
                            this.host_menu = None;
                            this.open_menu_for = None;
                            cx.notify();
                        })
                        .ok();
                    cx.new(|_| HostDragGhost {
                        label: label.clone(),
                    })
                },
            )
            .on_drag_move(
                cx.listener(move |this, event: &DragMoveEvent<DraggedHost>, _, cx| {
                    let same_group = event.drag(cx).group_key == move_group;
                    let inside = pointer_over(event.bounds, event.event.position);
                    if !same_group || !inside {
                        if this
                            .drop_slot
                            .as_ref()
                            .is_some_and(|slot| slot.id == entry_id)
                        {
                            this.drop_slot = None;
                            cx.notify();
                        }
                        return;
                    }
                    let after = event.event.position.y >= event.bounds.center().y;
                    if this
                        .drop_slot
                        .as_ref()
                        .is_some_and(|slot| slot.id == entry_id && slot.after == after)
                    {
                        return;
                    }
                    this.drop_slot = Some(HostDropSlot {
                        id: entry_id,
                        after,
                    });
                    cx.notify();
                }),
            )
            .on_drop(cx.listener(move |this, dragged: &DraggedHost, _, cx| {
                if dragged.group_key != drop_group {
                    this.dragging_host = None;
                    this.drop_slot = None;
                    cx.notify();
                    return;
                }
                let after = this
                    .drop_slot
                    .as_ref()
                    .is_some_and(|slot| slot.id == entry_id && slot.after);
                this.reorder_host(dragged.id, entry_id, &drop_group, after, cx);
            }))
    }

    fn reorder_host(
        &mut self,
        dragged: Uuid,
        target: Uuid,
        group_key: &str,
        after: bool,
        cx: &mut Context<Self>,
    ) {
        self.dragging_host = None;
        self.drop_slot = None;
        let entries = self
            .vault_state
            .read(cx)
            .manager()
            .and_then(|vm| vm.list_entries().ok())
            .unwrap_or_default();
        let current = group_orders(&entries, group_key);
        let Some(updates) = orders_after_move(&current, dragged, target, after) else {
            cx.notify();
            return;
        };
        let saved = self.vault_state.update(cx, |state, cx| {
            let Some(vault) = state.manager_mut() else {
                return false;
            };
            match vault.set_host_order(&updates) {
                Ok(changed) => {
                    if changed {
                        cx.notify();
                    }
                    changed
                }
                Err(error) => {
                    tracing::error!(?error, "failed to save host order");
                    false
                }
            }
        });
        cx.notify();
        if saved {
            SyncService::global(cx).update(cx, |service, cx| service.sync_now(cx));
        }
    }
}

/// A group row. Click folds everything under it shut, or opens it again.
/// `label` is this group's own name; `key` is the full path, so two groups
/// with the same name under different parents stay apart.
fn folder_header(
    collapsed: &HashSet<String>,
    label: &str,
    key: &str,
    depth: usize,
    count: usize,
    cx: &mut Context<Sidebar>,
) -> AnyElement {
    let is_collapsed = collapsed.contains(key);
    let title = label.to_string();
    let path = key.to_string();
    let chevron = if is_collapsed {
        IconName::ChevronRight
    } else {
        IconName::ChevronDown
    };
    h_flex()
        .id(SharedString::from(format!("sidebar-folder-{path}")))
        .h(px(26.))
        .mt(px(if depth == 0 { 6. } else { 0. }))
        .pr(px(4.))
        .pl(px(4. + depth as f32 * 14.))
        .gap(px(4.))
        .items_center()
        .rounded(px(6.))
        .cursor_pointer()
        .hover(|style| style.bg(theme::field()))
        .child(
            Icon::new(chevron)
                .size(px(12.))
                .text_color(theme::text_dim()),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .truncate()
                .text_size(px(11.5))
                .font_weight(gpui::FontWeight::MEDIUM)
                .text_color(theme::text_dim())
                .child(title.clone()),
        )
        .child(
            div()
                .text_size(px(11.))
                .text_color(theme::text_dim())
                .child(count.to_string()),
        )
        .on_click(cx.listener(move |this, _, _, cx| {
            if !this.collapsed_groups.remove(&path) {
                this.collapsed_groups.insert(path.clone());
            }
            cx.notify();
        }))
        .into_any_element()
}

/// Small heading over a group of sidebar rows.
fn section_label(text: &'static str) -> AnyElement {
    div()
        .flex_none()
        .h(px(26.))
        .px(px(8.))
        .pb(px(4.))
        .flex()
        .items_end()
        .text_size(px(11.5))
        .font_weight(gpui::FontWeight::MEDIUM)
        .text_color(theme::text_dim())
        .child(text)
        .into_any_element()
}

impl Sidebar {
    /// The open session for this host, if it has one: its place in the tab
    /// order, and whether the connection is up.
    fn open_session(&self, id: &Uuid) -> Option<(usize, HostStatus)> {
        let key = id.to_string();
        self.sessions
            .iter()
            .enumerate()
            .find_map(|(index, (session_id, status))| {
                (session_id == &key).then_some((index, *status))
            })
    }

    /// One host under its group. An open session keeps its status, its close
    /// button, and its tab shortcut here, so opening it does not pull it out
    /// of the group.
    fn folder_host(
        &self,
        ui_idx: usize,
        entry: &ServerEntrySummary,
        now: i64,
        depth: usize,
        group_key: &str,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let opened = self.open_session(&entry.id);
        let status = opened
            .map(|(_, status)| status)
            .unwrap_or(HostStatus::Offline);
        let sub: SharedString = match status {
            HostStatus::Connecting => "connecting…".into(),
            HostStatus::Disconnected => "disconnected".into(),
            HostStatus::Connected => SharedString::default(),
            HostStatus::Offline => entry
                .last_opened_at
                .map(|opened_at| relative_time(opened_at, now))
                .unwrap_or_default()
                .into(),
        };
        let shortcut = opened.and_then(|(index, _)| hints::tab_key(index));
        div()
            .pl(px(4. + (depth as f32 + 1.) * 14.))
            .child(self.host_row(
                ui_idx,
                entry,
                sub,
                status,
                opened.is_none(),
                opened.is_some(),
                shortcut,
                Some(group_key),
                cx,
            ))
            .into_any_element()
    }

    /// Groups, then the groups inside them, then the hosts that belong to
    /// this group itself. A folded group hides its children and its hosts.
    fn push_group_nodes(
        &self,
        nodes: &[GroupNode<'_>],
        depth: usize,
        now: i64,
        ui_idx: &mut usize,
        content: &mut Vec<AnyElement>,
        cx: &mut Context<Self>,
    ) {
        for node in nodes {
            content.push(folder_header(
                &self.collapsed_groups,
                &node.name,
                &node.path,
                depth,
                host_count(node),
                cx,
            ));
            if self.collapsed_groups.contains(&node.path) {
                continue;
            }
            self.push_group_nodes(&node.children, depth + 1, now, ui_idx, content, cx);
            for entry in &node.hosts {
                content.push(self.folder_host(*ui_idx, entry, now, depth, &node.path, cx));
                *ui_idx += 1;
            }
        }
    }

    /// The way back to the full list of hosts. Selected while no session is
    /// in front.
    fn all_hosts_row(&self, host_count: usize, cx: &mut Context<Self>) -> AnyElement {
        let is_active = self.active_server_id.is_none();
        let text = cx.theme().foreground;
        let icon_color = if is_active {
            theme::accent()
        } else {
            cx.theme().muted_foreground
        };
        h_flex()
            .id("sidebar-all-hosts")
            .h(px(ROW_HEIGHT))
            .gap(px(8.))
            .px(px(8.))
            .rounded(px(6.))
            .items_center()
            .cursor_pointer()
            .text_size(px(13.))
            .text_color(text)
            .when(is_active, |el| el.bg(theme::accent_soft()))
            .when(!is_active, |el| {
                el.hover(|s| s.bg(theme::field()))
                    .active(|s| s.bg(theme::element_active()))
            })
            .child(
                Icon::empty()
                    .path("icons/servers.svg")
                    .size(px(14.))
                    .text_color(icon_color),
            )
            .child(div().flex_1().child("All hosts"))
            // On the selected fill the dim colour falls below AA contrast.
            .child(
                div()
                    .text_size(px(11.5))
                    .text_color(if is_active {
                        cx.theme().muted_foreground
                    } else {
                        theme::text_dim()
                    })
                    .child(host_count.to_string()),
            )
            .on_click(cx.listener(|_, _, _, cx| cx.emit(SidebarEvent::ShowAllServers)))
            .into_any_element()
    }

    /// A square, quiet icon button for the footer. With `action` the tooltip
    /// also shows that action's shortcut.
    fn footer_icon_button(
        &self,
        id: &'static str,
        icon: Icon,
        tooltip: &'static str,
        action: Option<&'static dyn gpui::Action>,
        hint: Option<&'static str>,
        event: fn() -> SidebarEvent,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let hint = hint.filter(|_| hints::is_shown(cx));
        let muted = cx.theme().muted_foreground;
        let text = cx.theme().foreground;
        div()
            .id(id)
            .relative()
            .flex_none()
            .size(px(30.))
            .flex()
            .items_center()
            .justify_center()
            .rounded(px(7.))
            .text_color(muted)
            .cursor_pointer()
            .hover(move |s| s.bg(theme::field()).text_color(text))
            .active(|s| s.bg(theme::element_active()))
            .tooltip(move |window, cx| {
                let tip = Tooltip::new(tooltip);
                match action {
                    Some(action) => tip.action(action, None),
                    None => tip,
                }
                .build(window, cx)
            })
            .child(icon.size(px(15.)))
            .when_some(hint, |el, keys| el.child(hints::corner_badge(keys)))
            .on_click(cx.listener(move |_, _, _, cx| cx.emit(event())))
    }
}

impl Render for Sidebar {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // The drag flag is set when the gesture starts and cleared on drop.
        // A drop outside a row never calls that, so the next frame, once gpui
        // has dropped the drag, takes the mark down.
        if self.dragging_host.is_some() && !cx.has_active_drag() {
            self.dragging_host = None;
            self.drop_slot = None;
        }
        let theme = cx.theme();
        let bg = theme.sidebar;
        let text = theme.foreground;
        let text_dim = theme::text_dim();

        let entries = self
            .vault_state
            .read(cx)
            .manager()
            .and_then(|vm| vm.list_entries().ok())
            .unwrap_or_default();
        let now = unix_now();

        let by_id: HashMap<String, &ServerEntrySummary> =
            entries.iter().map(|e| (e.id.to_string(), e)).collect();
        let open_ids: HashSet<&str> = self.sessions.iter().map(|(id, _)| id.as_str()).collect();

        let mut recents: Vec<&ServerEntrySummary> = entries
            .iter()
            .filter(|e| e.last_opened_at.is_some() && !open_ids.contains(e.id.to_string().as_str()))
            .collect();
        recents.sort_by_key(|e| std::cmp::Reverse(e.last_opened_at));
        recents.truncate(RECENT_LIMIT);

        let mut content: Vec<AnyElement> = vec![self.all_hosts_row(entries.len(), cx)];
        let mut ui_idx = 0usize;

        // With groups, every host stays in its group, including one that is
        // open. A flat Open list would hide that. With no groups, Open and
        // Recent stay as the short list.
        let has_groups = entries.iter().any(|entry| {
            entry
                .group_name
                .as_deref()
                .is_some_and(|name| !name.is_empty())
        });
        if has_groups {
            let (roots, ungrouped) = group_tree(entries.iter());
            self.push_group_nodes(&roots, 0, now, &mut ui_idx, &mut content, cx);
            if !ungrouped.is_empty() {
                content.push(folder_header(
                    &self.collapsed_groups,
                    "Ungrouped",
                    "Ungrouped",
                    0,
                    ungrouped.len(),
                    cx,
                ));
                if !self.collapsed_groups.contains("Ungrouped") {
                    for entry in ungrouped {
                        content.push(self.folder_host(ui_idx, entry, now, 0, "", cx));
                        ui_idx += 1;
                    }
                }
            }
        } else {
            if !self.sessions.is_empty() {
                content.push(section_label("Open"));
            }
            // Cmd+1 to Cmd+9 follow this order: it is the tab order.
            for (tab_index, (id, status)) in self.sessions.iter().enumerate() {
                let Some(entry) = by_id.get(id) else { continue };
                let sub: SharedString = match status {
                    HostStatus::Connected => "",
                    HostStatus::Connecting => "connecting…",
                    HostStatus::Disconnected => "disconnected",
                    HostStatus::Offline => "offline",
                }
                .into();
                let shortcut = hints::tab_key(tab_index);
                content.push(
                    self.host_row(ui_idx, entry, sub, *status, false, true, shortcut, None, cx),
                );
                ui_idx += 1;
            }
            if !recents.is_empty() {
                content.push(section_label("Recent"));
            }
            for entry in &recents {
                let sub: SharedString = entry
                    .last_opened_at
                    .map(|t| relative_time(t, now))
                    .unwrap_or_default()
                    .into();
                content.push(self.host_row(
                    ui_idx,
                    entry,
                    sub,
                    HostStatus::Offline,
                    true,
                    false,
                    None,
                    None,
                    cx,
                ));
                ui_idx += 1;
            }
        }

        // Nothing open and nothing recent: a quiet hint, never the full catalog.
        // Folders already list every host, so they need no hint.
        if !has_groups && self.sessions.is_empty() && recents.is_empty() && !entries.is_empty() {
            content.push(
                div()
                    .h(px(ROW_HEIGHT))
                    .px(px(8.))
                    .mt(px(6.))
                    .flex()
                    .items_center()
                    .text_size(px(12.))
                    .text_color(text_dim)
                    .child("No recent hosts")
                    .into_any_element(),
            );
        }

        v_flex()
            .w(px(SIDEBAR_WIDTH))
            .flex_none()
            .h_full()
            .bg(bg)
            .child(
                v_flex()
                    .id("sidebar-list")
                    .flex_1()
                    .overflow_y_scroll()
                    .pb(px(4.))
                    .px(px(8.))
                    .children(content),
            )
            .child(
                h_flex()
                    .h(px(46.))
                    .px(px(8.))
                    .gap(px(4.))
                    .items_center()
                    .child(
                        h_flex()
                            .id("sb-btn-new-host")
                            .relative()
                            .flex_1()
                            .h(px(30.))
                            .px(px(10.))
                            .gap(px(6.))
                            .items_center()
                            .justify_center()
                            .rounded(px(7.))
                            .bg(theme::field())
                            .text_size(px(13.))
                            .text_color(text)
                            .cursor_pointer()
                            .hover(|s| s.bg(theme::element()))
                            .active(|s| s.bg(theme::element_active()))
                            .child(Icon::new(IconName::Plus).size(px(13.)))
                            .child(div().child("New host"))
                            .when(hints::is_shown(cx), |el| {
                                el.child(hints::corner_badge(hints::NEW_HOST))
                            })
                            .on_click(
                                cx.listener(|_, _, _, cx| {
                                    cx.emit(SidebarEvent::AddServerRequested)
                                }),
                            ),
                    )
                    .child(self.footer_icon_button(
                        "sb-btn-settings",
                        Icon::new(IconName::Settings),
                        "Settings",
                        Some(&ToggleSettings),
                        Some(hints::SETTINGS),
                        || SidebarEvent::SettingsRequested,
                        cx,
                    )),
            )
            .children(self.render_host_menu(cx))
    }
}

impl Sidebar {
    fn render_host_menu(&self, cx: &Context<Self>) -> Option<AnyElement> {
        let (entry_id, position) = self.host_menu?;
        let items = vec![
            ContextMenuItem::new(
                "host-menu-terminal",
                "Open terminal",
                cx.listener(move |this, _, _, cx| {
                    this.host_menu = None;
                    cx.emit(SidebarEvent::OpenServer(entry_id));
                    cx.notify();
                }),
            )
            .icon("icons/square-terminal.svg"),
            ContextMenuItem::new(
                "host-menu-sftp",
                "Open SFTP",
                cx.listener(move |this, _, _, cx| {
                    this.host_menu = None;
                    cx.emit(SidebarEvent::OpenSftp(entry_id));
                    cx.notify();
                }),
            )
            .icon("icons/folder-open.svg"),
            ContextMenuItem::new(
                "host-menu-duplicate",
                "Duplicate",
                cx.listener(move |this, _, _, cx| {
                    this.host_menu = None;
                    cx.emit(SidebarEvent::DuplicateServerRequested(entry_id));
                    cx.notify();
                }),
            )
            .icon("icons/clipboard-copy.svg"),
        ];
        Some(
            ContextMenu::new(
                "sidebar-host-menu",
                position,
                Anchor::TopLeft,
                cx.listener(|this, _, _, cx| {
                    this.host_menu = None;
                    cx.notify();
                }),
                items,
            )
            .into_any_element(),
        )
    }
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Compact relative-time label ("just now", "5m ago", "yesterday", "3d ago").
pub(crate) fn relative_time(ts: i64, now: i64) -> String {
    let d = (now - ts).max(0);
    if d < 60 {
        "just now".to_string()
    } else if d < 3_600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3_600)
    } else if d < 172_800 {
        "yesterday".to_string()
    } else if d < 604_800 {
        format!("{}d ago", d / 86_400)
    } else {
        format!("{}w ago", d / 604_800)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(label: &str, group: Option<&str>) -> ServerEntrySummary {
        ServerEntrySummary {
            id: Uuid::new_v4(),
            label: label.to_string(),
            host: "example".to_string(),
            port: 22,
            username: "me".to_string(),
            os: None,
            last_opened_at: None,
            sort_order: 0,
            group_name: group.map(str::to_string),
            tag_names: Vec::new(),
            team_name: None,
            proxy: gssh::vault::ProxyChoice::Default,
        }
    }

    fn host_names<'a>(entries: &[&'a ServerEntrySummary]) -> Vec<&'a str> {
        entries
            .iter()
            .map(|entry| host_display_name(entry))
            .collect()
    }

    #[test]
    fn hosts_nest_under_each_group_in_the_path() {
        let mut by_address = entry("", Some("Work"));
        by_address.host = "aaa".to_string();
        let entries = vec![
            entry("zeta", Some("Work")),
            entry("web", Some("Work / EU")),
            entry("alpha", None),
            by_address,
            entry("beta", Some("Personal")),
            entry("api", Some("Work / EU")),
            entry("gamma", Some("")),
        ];
        let (roots, ungrouped) = group_tree(entries.iter());
        let names: Vec<&str> = roots.iter().map(|node| node.name.as_str()).collect();
        assert_eq!(names, ["Personal", "Work"]);

        let personal = &roots[0];
        assert!(personal.children.is_empty());
        assert_eq!(host_names(&personal.hosts), ["beta"]);

        let work = &roots[1];
        assert_eq!(work.path, "Work");
        // An empty label sorts by the address, ahead of "zeta".
        assert_eq!(host_names(&work.hosts), ["aaa", "zeta"]);
        assert_eq!(work.children.len(), 1);
        let eu = &work.children[0];
        assert_eq!(eu.name, "EU");
        assert_eq!(eu.path, "Work / EU");
        assert_eq!(host_names(&eu.hosts), ["api", "web"]);
        assert_eq!(host_count(work), 4);

        assert_eq!(host_names(&ungrouped), ["alpha", "gamma"]);
    }

    #[test]
    fn a_placed_host_leads_its_folder_and_an_unset_one_follows_by_name() {
        let mut first = entry("zeta", Some("Work"));
        first.sort_order = 1;
        let mut second = entry("alpha", Some("Work"));
        second.sort_order = 2;
        let third = entry("mid", Some("Work"));
        let entries = vec![third, second, first];
        let (roots, _) = group_tree(entries.iter());
        assert_eq!(host_names(&roots[0].hosts), ["zeta", "alpha", "mid"]);
    }

    fn uid(n: u8) -> Uuid {
        Uuid::from_u128(n as u128)
    }

    #[test]
    fn a_drag_lands_on_the_half_of_the_row_it_was_dropped_on() {
        let (a, b, c) = (uid(1), uid(2), uid(3));
        let ids = [a, b, c];
        assert_eq!(place_host(&ids, a, b, true).unwrap(), vec![b, a, c]);
        assert!(place_host(&ids, a, b, false).is_none());
        assert_eq!(place_host(&ids, c, a, false).unwrap(), vec![c, a, b]);
        assert_eq!(place_host(&ids, c, a, true).unwrap(), vec![a, c, b]);
        assert!(place_host(&ids, a, a, true).is_none());
    }

    #[test]
    fn a_drag_rewrites_only_the_moved_host_when_a_gap_can_hold_it() {
        let (a, b, c) = (uid(1), uid(2), uid(3));
        let placed = [(a, 1024), (b, 2048), (c, 3072)];
        assert_eq!(
            orders_after_move(&placed, a, b, true).unwrap(),
            vec![(a, 2560)]
        );
        assert_eq!(
            orders_after_move(&placed, c, a, false).unwrap(),
            vec![(c, 512)]
        );

        // The unset host stays at the end, so the moved host only needs a
        // rank after its new neighbor.
        let with_unset = [(a, 1024), (b, 2048), (c, 0)];
        assert_eq!(
            orders_after_move(&with_unset, a, b, true).unwrap(),
            vec![(a, 3072)]
        );
        // An unset host dropped above a placed one only needs its own rank.
        assert_eq!(
            orders_after_move(&with_unset, c, a, false).unwrap(),
            vec![(c, 512)]
        );

        // Past an unset host, one rank cannot say "after the unnamed tail".
        let full = orders_after_move(&with_unset, a, c, true).unwrap();
        assert_eq!(full, vec![(b, 1024), (c, 2048), (a, 3072)]);
    }

    #[test]
    fn the_first_drag_in_a_folder_gives_every_host_a_place() {
        let (a, b, c) = (uid(1), uid(2), uid(3));
        let unset = [(a, 0), (b, 0), (c, 0)];
        assert_eq!(
            orders_after_move(&unset, c, a, false).unwrap(),
            vec![(c, 1024), (a, 2048), (b, 3072)]
        );
    }
}
