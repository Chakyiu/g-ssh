//! Tabs for open connections. Each tab is one host's terminal or its SFTP
//! browser. Dropping a tab on another tab reorders the strip. Dropping it on
//! an edge splits that cell, so two different connections can sit side by side.

use gpui::prelude::*;
use gpui::{
    div, px, relative, AnyElement, App, Bounds, Context, DragMoveEvent, Entity, EventEmitter, Hsla,
    MouseButton, Pixels, Point, SharedString, Window,
};
use gpui_component::{
    h_flex,
    resizable::{h_resizable, resizable_panel, v_resizable, ResizableState},
    v_flex, ActiveTheme as _, Icon, StyledExt as _,
};

use crate::theme;
use crate::ui::session::{DockEdge, LayoutNode, ServerSession, TermPane};
use crate::ui::terminal::tabs::{
    bounds_contain, collapse_layout, dock_edge_at, first_pane, layout_contains, replace_leaf,
    tab_insert_index, tab_insert_mark,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkKind {
    Terminal,
    Sftp,
}

pub(crate) enum WorkspaceEvent {
    /// The tab in front belongs to this host.
    Activated(String),
    /// The last tab for this connection was closed.
    SessionUnused(Entity<ServerSession>),
    /// Connections in visual tab order, left to right across the grid.
    OrderChanged(Vec<Entity<ServerSession>>),
}

struct WorkDoc {
    session: Entity<ServerSession>,
    kind: WorkKind,
    surface: Entity<SurfaceView>,
}

/// Draws one connection as either its terminal or its file browser.
struct SurfaceView {
    session: Entity<ServerSession>,
    files: bool,
}

impl SurfaceView {
    fn new(session: Entity<ServerSession>, files: bool, cx: &mut Context<Self>) -> Self {
        cx.observe(&session, |_, _, cx| cx.notify()).detach();
        Self { session, files }
    }
}

impl Render for SurfaceView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let files = self.files;
        self.session
            .update(cx, |session, cx| session.render_surface(files, window, cx))
    }
}

pub(crate) struct Workspace {
    docs: Vec<WorkDoc>,
    panes: Vec<TermPane>,
    layout: LayoutNode,
    focused_pane: usize,
    next_split_id: u64,
    dragging: Option<usize>,
    hover: Option<(usize, DockEdge)>,
    /// The tab under the pointer, and whether the drop lands on its right half.
    tab_slot: Option<(usize, bool)>,
    show_hosts: bool,
}

impl EventEmitter<WorkspaceEvent> for Workspace {}

impl Workspace {
    pub(crate) fn new(_cx: &mut Context<Self>) -> Self {
        Self {
            docs: Vec::new(),
            panes: vec![TermPane {
                tabs: Vec::new(),
                active: 0,
            }],
            layout: LayoutNode::Pane(0),
            focused_pane: 0,
            next_split_id: 1,
            dragging: None,
            hover: None,
            tab_slot: None,
            show_hosts: true,
        }
    }

    pub(crate) fn is_showing_hosts(&self) -> bool {
        self.show_hosts || self.docs.is_empty()
    }

    /// The host of the tab in front, when a connection is on screen.
    pub(crate) fn focused_host(&self, cx: &App) -> Option<String> {
        let ix = self.shown(self.current_pane())?;
        Some(self.docs.get(ix)?.session.read(cx).server_id.clone())
    }

    pub(crate) fn show_hosts(&mut self, cx: &mut Context<Self>) {
        self.show_hosts = true;
        cx.notify();
    }

    /// Add a terminal or SFTP tab for this connection. An existing one of the
    /// same kind comes forward instead of a second copy.
    pub(crate) fn open_doc(
        &mut self,
        session: Entity<ServerSession>,
        kind: WorkKind,
        cx: &mut Context<Self>,
    ) {
        self.show_hosts = false;
        if let Some(ix) = self.find_doc(&session, kind) {
            self.activate_doc(ix, cx);
            return;
        }
        let files = kind == WorkKind::Sftp;
        let surface = cx.new(|cx| SurfaceView::new(session.clone(), files, cx));
        let ix = self.docs.len();
        self.docs.push(WorkDoc {
            session: session.clone(),
            kind,
            surface,
        });
        let pane = self.current_pane();
        if let Some(slot) = self.panes.get_mut(pane) {
            slot.tabs.push(ix);
            slot.active = ix;
        }
        self.focused_pane = pane;
        self.emit_activated(ix, cx);
        cx.notify();
    }

    pub(crate) fn remove_session(
        &mut self,
        session: &Entity<ServerSession>,
        cx: &mut Context<Self>,
    ) {
        let indexes: Vec<usize> = self
            .docs
            .iter()
            .enumerate()
            .filter(|(_, doc)| &doc.session == session)
            .map(|(ix, _)| ix)
            .collect();
        for ix in indexes.into_iter().rev() {
            self.close_doc(ix, false, cx);
        }
    }

    fn find_doc(&self, session: &Entity<ServerSession>, kind: WorkKind) -> Option<usize> {
        self.docs
            .iter()
            .position(|doc| &doc.session == session && doc.kind == kind)
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

    fn pane_for(&self, doc: usize) -> Option<usize> {
        self.panes.iter().position(|pane| pane.tabs.contains(&doc))
    }

    fn activate_doc(&mut self, ix: usize, cx: &mut Context<Self>) {
        let Some(pane) = self.pane_for(ix) else {
            return;
        };
        if let Some(slot) = self.panes.get_mut(pane) {
            slot.active = ix;
        }
        self.focused_pane = pane;
        self.show_hosts = false;
        self.emit_activated(ix, cx);
        cx.notify();
    }

    fn emit_activated(&mut self, ix: usize, cx: &mut Context<Self>) {
        let Some(doc) = self.docs.get(ix) else {
            return;
        };
        let id = doc.session.read(cx).server_id.clone();
        cx.emit(WorkspaceEvent::Activated(id));
    }

    fn close_doc(&mut self, ix: usize, tell_app: bool, cx: &mut Context<Self>) {
        if ix >= self.docs.len() {
            return;
        }
        let session = self.docs[ix].session.clone();
        self.forget_doc_index(ix);
        self.docs.remove(ix);
        if self.docs.is_empty() {
            self.show_hosts = true;
        }
        if tell_app && !self.docs.iter().any(|doc| doc.session == session) {
            cx.emit(WorkspaceEvent::SessionUnused(session));
        }
        cx.notify();
    }

    fn forget_doc_index(&mut self, closed: usize) {
        for pane in &mut self.panes {
            pane.tabs = pane
                .tabs
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
            if !pane.tabs.contains(&pane.active) {
                pane.active = pane.tabs.first().copied().unwrap_or(0);
            }
        }
        let layout = std::mem::replace(&mut self.layout, LayoutNode::Pane(0));
        self.layout = collapse_layout(layout, &self.panes);
        if !layout_contains(&self.layout, self.focused_pane) {
            self.focused_pane = first_pane(&self.layout);
        }
    }

    fn detach_doc(&mut self, ix: usize) {
        for pane in &mut self.panes {
            pane.tabs.retain(|tab| *tab != ix);
            if !pane.tabs.contains(&pane.active) {
                pane.active = pane.tabs.first().copied().unwrap_or(0);
            }
        }
    }

    fn collapse(&mut self) {
        let layout = std::mem::replace(&mut self.layout, LayoutNode::Pane(0));
        self.layout = collapse_layout(layout, &self.panes);
        if !layout_contains(&self.layout, self.focused_pane) {
            self.focused_pane = first_pane(&self.layout);
        }
    }

    /// `at` is the tab under the pointer and whether the drop is on its right
    /// half. `None` puts the tab at the end of the cell.
    fn move_into(
        &mut self,
        ix: usize,
        target: usize,
        at: Option<(usize, bool)>,
        cx: &mut Context<Self>,
    ) {
        self.dragging = None;
        self.hover = None;
        self.tab_slot = None;
        if ix >= self.docs.len() || self.panes.get(target).is_none() {
            cx.notify();
            return;
        }
        // A drop on the strip's empty space, or on the tab being dragged,
        // only brings that tab forward.
        if at.is_some_and(|(at_ix, _)| at_ix == ix)
            || (at.is_none() && self.pane_for(ix) == Some(target))
        {
            self.activate_doc(ix, cx);
            return;
        }
        self.detach_doc(ix);
        self.collapse();
        if !layout_contains(&self.layout, target) {
            self.adopt(ix);
            self.show_hosts = false;
            self.emit_order(cx);
            self.emit_activated(ix, cx);
            cx.notify();
            return;
        }
        if let Some(pane) = self.panes.get_mut(target) {
            let (before, after) = match at {
                Some((id, after)) => (Some(id), after),
                None => (None, false),
            };
            let pos = tab_insert_index(&pane.tabs, before, after);
            pane.tabs.insert(pos, ix);
            pane.active = ix;
        }
        self.focused_pane = target;
        self.show_hosts = false;
        self.emit_order(cx);
        self.emit_activated(ix, cx);
        cx.notify();
    }

    fn emit_order(&self, cx: &mut Context<Self>) {
        cx.emit(WorkspaceEvent::OrderChanged(self.session_order()));
    }

    /// Connections in the order the tab strips read, first cell first.
    fn session_order(&self) -> Vec<Entity<ServerSession>> {
        let mut docs = Vec::new();
        walk_docs(&self.layout, &self.panes, &mut docs);
        let mut sessions = Vec::new();
        for ix in docs {
            let Some(session) = self.docs.get(ix).map(|doc| doc.session.clone()) else {
                continue;
            };
            if !sessions.contains(&session) {
                sessions.push(session);
            }
        }
        sessions
    }

    fn adopt(&mut self, ix: usize) {
        let pane = self.current_pane();
        if let Some(slot) = self.panes.get_mut(pane) {
            if !slot.tabs.contains(&ix) {
                slot.tabs.push(ix);
            }
            slot.active = ix;
        }
        self.focused_pane = pane;
    }

    fn dock_on_edge(&mut self, ix: usize, target: usize, edge: DockEdge, cx: &mut Context<Self>) {
        self.dragging = None;
        self.hover = None;
        self.tab_slot = None;
        let alone = self
            .panes
            .get(target)
            .is_some_and(|pane| pane.tabs.len() == 1 && pane.tabs.first() == Some(&ix));
        if ix >= self.docs.len() || self.docs.len() < 2 || alone {
            cx.notify();
            return;
        }
        self.detach_doc(ix);
        self.collapse();
        if !layout_contains(&self.layout, target) {
            self.adopt(ix);
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
        self.show_hosts = false;
        self.emit_order(cx);
        self.emit_activated(ix, cx);
        cx.notify();
    }

    fn doc_label(&self, ix: usize, cx: &App) -> String {
        let Some(doc) = self.docs.get(ix) else {
            return String::new();
        };
        let name = doc.session.read(cx).conn_info.display_name().to_string();
        match doc.kind {
            WorkKind::Terminal => name,
            WorkKind::Sftp => format!("{name} SFTP"),
        }
    }
}

fn walk_docs(node: &LayoutNode, panes: &[TermPane], out: &mut Vec<usize>) {
    match node {
        LayoutNode::Pane(id) => {
            if let Some(pane) = panes.get(*id) {
                out.extend(pane.tabs.iter().copied());
            }
        }
        LayoutNode::Split { first, second, .. } => {
            walk_docs(first, panes, out);
            walk_docs(second, panes, out);
        }
    }
}

#[derive(Clone)]
struct DraggedDoc {
    ix: usize,
}

struct DocGhost {
    label: SharedString,
}

impl Render for DocGhost {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        h_flex()
            .h(px(26.))
            .px(px(8.))
            .items_center()
            .rounded(px(6.))
            .border_1()
            .border_color(theme::border_focused())
            .bg(cx.theme().popover)
            .shadow_md()
            .text_size(px(12.5))
            .child(self.label.clone())
    }
}

impl Workspace {
    fn render_strip(&self, pane: usize, cx: &mut Context<Self>) -> AnyElement {
        let tabs = self
            .panes
            .get(pane)
            .map(|p| p.tabs.clone())
            .unwrap_or_default();
        let active = self.shown(pane);
        let mut strip = h_flex()
            .id(("work-strip", pane))
            .flex_1()
            .min_w_0()
            .px(px(8.))
            .gap(px(2.))
            .items_center()
            .overflow_x_scroll();
        for ix in tabs {
            strip = strip.child(self.render_tab(ix, pane, active == Some(ix), cx));
        }
        if self.docs.len() >= 2 {
            strip = strip
                .on_drag_move(
                    cx.listener(|this, event: &DragMoveEvent<DraggedDoc>, _, cx| {
                        if !bounds_contain(event.bounds, event.event.position) {
                            return;
                        }
                        if this.hover.take().is_some() {
                            cx.notify();
                        }
                    }),
                )
                .on_drop(cx.listener(move |this, doc: &DraggedDoc, _, cx| {
                    this.move_into(doc.ix, pane, None, cx);
                }));
        }
        h_flex()
            .h(px(38.))
            .w_full()
            .items_center()
            .border_b_1()
            .border_color(theme::border())
            .child(strip)
            .child(self.render_pane_controls(pane, cx))
            .into_any_element()
    }

    /// Transfers, forwards, and the inspector, on the tab row of the
    /// connection in front. The host name already lives on the tab.
    fn render_pane_controls(&self, pane: usize, cx: &mut Context<Self>) -> AnyElement {
        let Some(doc) = self.shown(pane).and_then(|ix| self.docs.get(ix)) else {
            return div().into_any_element();
        };
        doc.session.update(cx, |session, cx| {
            h_flex()
                .flex_none()
                .gap(px(4.))
                .pr(px(8.))
                .items_center()
                .when_some(session.render_forward_chip(cx), |el, chip| el.child(chip))
                .when_some(session.render_task_pills(cx), |el, pills| el.child(pills))
                .child(session.render_server_panel_toggle(cx))
                .into_any_element()
        })
    }

    fn render_tab(&self, ix: usize, pane: usize, active: bool, cx: &Context<Self>) -> AnyElement {
        let label = self.doc_label(ix, cx);
        let kind = self.docs.get(ix).map(|doc| doc.kind);
        let icon = match kind {
            Some(WorkKind::Sftp) => "icons/folder-open.svg",
            _ => "icons/square-terminal.svg",
        };
        let ghost = SharedString::from(label.clone());
        let session = cx.entity().downgrade();
        let fg = cx.theme().foreground;
        let before = self.tab_slot == Some((ix, false));
        let after = self.tab_slot == Some((ix, true));
        h_flex()
            .id(("work-tab", ix))
            .relative()
            .h(px(26.))
            .px(px(8.))
            .gap(px(6.))
            .items_center()
            .rounded(px(6.))
            .when(active, |el| el.bg(theme::element()).text_color(fg))
            .when(!active, |el| {
                el.text_color(cx.theme().muted_foreground)
                    .hover(|s| s.bg(theme::field()))
            })
            .when(before, |el| el.child(tab_insert_mark(true)))
            .when(after, |el| el.child(tab_insert_mark(false)))
            .cursor_pointer()
            .child(Icon::empty().path(icon).size(px(14.)))
            .child(
                div()
                    .max_w(px(160.))
                    .truncate()
                    .text_size(px(12.5))
                    .child(label),
            )
            .child(
                div()
                    .id(("work-tab-close", ix))
                    .px(px(2.))
                    .rounded(px(3.))
                    .text_color(theme::text_dim())
                    .hover(move |s| s.bg(theme::element_hover()).text_color(fg))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            cx.stop_propagation();
                            this.close_doc(ix, true, cx);
                        }),
                    )
                    .child("\u{00D7}"),
            )
            .on_click(cx.listener(move |this, _, _, cx| this.activate_doc(ix, cx)))
            .when(self.docs.len() >= 2, |el| {
                el.on_drag(DraggedDoc { ix }, move |doc, _, _, cx| {
                    let ix = doc.ix;
                    session
                        .update(cx, |this, cx| {
                            this.dragging = Some(ix);
                            this.hover = None;
                            this.tab_slot = None;
                            cx.notify();
                        })
                        .ok();
                    cx.new(|_| DocGhost {
                        label: ghost.clone(),
                    })
                })
                .on_drag_move(
                    cx.listener(move |this, event: &DragMoveEvent<DraggedDoc>, _, cx| {
                        this.track_tab_slot(ix, event.bounds, event.event.position, cx);
                    }),
                )
                .on_drop(cx.listener(move |this, doc: &DraggedDoc, _, cx| {
                    let after = this.tab_slot.is_some_and(|(id, after)| id == ix && after);
                    this.move_into(doc.ix, pane, Some((ix, after)), cx);
                }))
            })
            .into_any_element()
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
        self.hover = None;
        cx.notify();
    }

    fn render_node(&self, node: &LayoutNode, cx: &mut Context<Self>) -> AnyElement {
        match node {
            LayoutNode::Pane(id) => self.render_cell(*id, cx),
            LayoutNode::Split {
                id,
                horizontal,
                state,
                first,
                second,
            } => {
                let leading = self.render_node(first, cx);
                let trailing = self.render_node(second, cx);
                let panel = |child: AnyElement| {
                    resizable_panel()
                        .size(px(360.))
                        .size_range(px(160.)..Pixels::MAX)
                        .child(child)
                };
                let name = SharedString::from(format!("work-split-{id}"));
                if *horizontal {
                    h_resizable(name)
                        .with_state(state)
                        .child(panel(leading))
                        .child(panel(trailing))
                        .into_any_element()
                } else {
                    v_resizable(name)
                        .with_state(state)
                        .child(panel(leading))
                        .child(panel(trailing))
                        .into_any_element()
                }
            }
        }
    }

    fn render_cell(&self, pane: usize, cx: &mut Context<Self>) -> AnyElement {
        let doc = self
            .shown(pane)
            .and_then(|ix| self.docs.get(ix))
            .map(|doc| doc.surface.clone());
        v_flex()
            .size_full()
            .overflow_hidden()
            .child(self.render_strip(pane, cx))
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .overflow_hidden()
                    .children(doc)
                    .when(self.dragging.is_some(), |el| {
                        el.child(self.render_overlay(pane, cx))
                    }),
            )
            .into_any_element()
    }

    fn render_overlay(&self, pane: usize, cx: &mut Context<Self>) -> AnyElement {
        let hover = self
            .hover
            .and_then(|(id, edge)| (id == pane).then_some(edge));
        let from_other = self
            .dragging
            .is_some_and(|ix| self.pane_for(ix) != Some(pane));
        let center_hot = self.hover.is_none() && from_other;
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
            .id(("work-dock", pane))
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
                        .child("Move here"),
                )
            })
            .on_drag_move(
                cx.listener(move |this, event: &DragMoveEvent<DraggedDoc>, _, cx| {
                    if !bounds_contain(event.bounds, event.event.position) {
                        return;
                    }
                    let edge = dock_edge_at(event.bounds, event.event.position);
                    let next = edge.map(|edge| (pane, edge));
                    if this.hover != next {
                        this.hover = next;
                        cx.notify();
                    }
                }),
            )
            .on_drop(cx.listener(move |this, doc: &DraggedDoc, _, cx| {
                if let Some((id, edge)) = this.hover {
                    if id == pane {
                        this.dock_on_edge(doc.ix, pane, edge, cx);
                        return;
                    }
                }
                this.move_into(doc.ix, pane, None, cx);
            }))
            .into_any_element()
    }
}

fn tint(color: Hsla, alpha: f32) -> Hsla {
    Hsla { a: alpha, ..color }
}

impl Render for Workspace {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.dragging.is_some() && !cx.has_active_drag() {
            self.dragging = None;
            self.hover = None;
            self.tab_slot = None;
        }
        let layout = self.layout.clone();
        self.render_node(&layout, cx)
    }
}
