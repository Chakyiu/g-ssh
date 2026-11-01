//! A terminal on this computer. It uses the same emulator as an SSH session,
//! so a local shell (and `ssh` typed into it) gets the same grid, scrollback,
//! and keys.

use crate::ui::scale::px;
use gpui::prelude::*;
use gpui::{
    div, AnyElement, ClickEvent, Context, DragMoveEvent, Entity, EventEmitter, Focusable as _,
    MouseButton, StyleRefinement, Window,
};

use gpui_component::{
    h_flex, tooltip::Tooltip, v_flex, ActiveTheme as _, Icon, IconName, WindowExt as _,
};
use gssh::ssh::shell::ShellHandle;
use gssh::vault::SnippetBody;

use crate::theme;
use crate::ui::hints;
use crate::ui::session::panel::{
    panel_resize_handle, PanelHost, PanelResize, SelectionCite, ServerPanel, ServerPanelEvent,
};
use crate::ui::terminal::tabs::{NEW_TERMINAL_SHORTCUT, SERVER_PANEL_SHORTCUT};
use crate::ui::terminal::view::{TerminalEvent, TerminalView};
use crate::ui::VaultState;

pub enum LocalTerminalEvent {
    /// Open Settings on the agent endpoint page.
    OpenAgentSettings,
}

impl EventEmitter<LocalTerminalEvent> for LocalTerminal {}

/// Shells past this stop fitting the header, same cap as a remote session.
const MAX_SHELLS: usize = 8;

struct LocalShell {
    view: Entity<TerminalView>,
    exited: bool,
}

pub struct LocalTerminal {
    shells: Vec<LocalShell>,
    active: usize,
    spawn_error: Option<String>,
    /// The active shell should take the keyboard on the next render.
    focus_pending: bool,
    vault_state: Entity<VaultState>,
    panel: Entity<ServerPanel>,
    /// Overview, snippets, or the agent chat, on the right of the terminal.
    panel_shown: bool,
    /// `user@hostname`, for the agent and a snippet's record of where it ran.
    machine_label: String,
}

impl LocalTerminal {
    pub fn new(vault_state: Entity<VaultState>, cx: &mut Context<Self>) -> Self {
        let local = cx.entity().downgrade();
        let panel = cx.new(|cx| ServerPanel::new(PanelHost::Local(local), vault_state.clone(), cx));
        cx.subscribe(&panel, |this, _, event, cx| this.on_panel(event, cx))
            .detach();
        Self {
            shells: Vec::new(),
            active: 0,
            spawn_error: None,
            focus_pending: false,
            vault_state,
            panel,
            panel_shown: false,
            machine_label: machine_label(),
        }
    }

    pub(crate) fn machine_label(&self) -> String {
        self.machine_label.clone()
    }

    /// The shell in front, when it is still running.
    pub(crate) fn active_shell(&self, cx: &gpui::App) -> Option<ShellHandle> {
        let shell = self.shells.get(self.active)?;
        if shell.exited {
            return None;
        }
        Some(shell.view.read(cx).shell.clone())
    }

    pub(crate) fn focus_shell(&mut self, cx: &mut Context<Self>) {
        self.focus_pending = true;
        cx.notify();
    }

    fn on_panel(&mut self, event: &ServerPanelEvent, cx: &mut Context<Self>) {
        match event {
            ServerPanelEvent::RunSnippet(id) => self.run_snippet(*id, cx),
            ServerPanelEvent::OpenAgentSettings => cx.emit(LocalTerminalEvent::OpenAgentSettings),
            ServerPanelEvent::WidthChanged => cx.notify(),
        }
    }

    fn run_snippet(&mut self, id: uuid::Uuid, cx: &mut Context<Self>) {
        let script = self.vault_state.read(cx).manager().and_then(|vault| {
            let SnippetBody::Script { content } = &vault.get_snippet(id).ok()?.body;
            Some(content.clone())
        });
        let Some(script) = script else {
            return;
        };
        let Some(shell) = self.active_shell(cx) else {
            return;
        };
        let mut bytes = script.into_bytes();
        bytes.push(b'\r');
        cx.spawn(async move |_, _| {
            shell.send_input(bytes).await;
        })
        .detach();
        self.focus_shell(cx);
    }

    fn ask_agent(
        &mut self,
        text: &str,
        start_line: usize,
        end_line: usize,
        cx: &mut Context<Self>,
    ) {
        if !self.vault_state.read(cx).agent_enabled() {
            return;
        }
        let cite = (!text.trim().is_empty()).then(|| {
            SelectionCite::new(
                &self.machine_label,
                &self.active_label(),
                start_line,
                end_line,
                text,
            )
        });
        self.panel_shown = true;
        self.panel
            .update(cx, |panel, cx| panel.request_agent(cite, cx));
        self.focus_shell(cx);
    }

    fn active_label(&self) -> String {
        if self.shells.len() <= 1 {
            "Local".to_string()
        } else {
            (self.active + 1).to_string()
        }
    }

    fn toggle_agent(&mut self, cx: &mut Context<Self>) {
        let showing = self.panel_shown && self.panel.read(cx).shows_agent();
        if showing {
            self.panel_shown = false;
        } else {
            self.panel_shown = true;
            self.panel
                .update(cx, |panel, cx| panel.request_agent(None, cx));
        }
        self.focus_shell(cx);
    }

    pub(crate) fn toggle_panel(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let inspector = self.panel_shown && !self.panel.read(cx).shows_agent();
        if inspector {
            self.panel_shown = false;
        } else {
            self.panel_shown = true;
            self.panel.update(cx, |panel, cx| panel.show_inspector(cx));
        }
        self.focus_shell(cx);
    }

    pub fn shell_count(&self) -> usize {
        self.shells.len()
    }

    /// Start the first shell. Later visits keep the one that is already running.
    pub fn ensure_started(&mut self, cx: &mut Context<Self>) {
        if self.shells.is_empty() {
            self.open_shell(cx);
        }
    }

    pub fn focus_handle(&self, cx: &gpui::App) -> Option<gpui::FocusHandle> {
        self.shells
            .get(self.active)
            .map(|shell| shell.view.read(cx).focus_handle(cx))
    }

    /// One more shell. No-op once the header is full.
    pub fn open_shell(&mut self, cx: &mut Context<Self>) {
        if self.shells.len() >= MAX_SHELLS {
            return;
        }
        let size = self.grid_size(cx);
        self.insert_shell(self.shells.len(), size, cx);
    }

    /// Replace the shell in front after it has exited.
    pub fn restart_active(&mut self, cx: &mut Context<Self>) {
        if self
            .shells
            .get(self.active)
            .is_some_and(|shell| !shell.exited)
        {
            return;
        }
        let size = self.grid_size(cx);
        let index = self.active.min(self.shells.len());
        if index < self.shells.len() {
            self.shells.remove(index);
        }
        self.insert_shell(index, size, cx);
    }

    /// Close the shell in front. The last one stays: closing the view is the
    /// caller's choice, and the shell should still be there on the way back.
    pub fn close_active(&mut self, cx: &mut Context<Self>) {
        if self.shells.len() <= 1 {
            return;
        }
        self.close_shell(self.active, cx);
    }

    fn grid_size(&self, cx: &gpui::App) -> (u16, u16) {
        self.shells
            .get(self.active)
            .and_then(|shell| shell.view.read(cx).grid_size())
            .unwrap_or((24, 80))
    }

    fn insert_shell(&mut self, index: usize, size: (u16, u16), cx: &mut Context<Self>) {
        let shell = match gssh::ssh::local::spawn_local_shell(size.0, size.1) {
            Ok(shell) => shell,
            Err(err) => {
                tracing::error!(%err, "failed to open a local shell");
                self.spawn_error = Some(err);
                if self.active >= self.shells.len() {
                    self.active = self.shells.len().saturating_sub(1);
                }
                cx.notify();
                return;
            }
        };
        self.spawn_error = None;
        let vault = self.vault_state.clone();
        let view = cx.new(|cx| {
            let mut view = TerminalView::new(shell, cx);
            view.follow_agent_setting(vault, cx);
            // The view focuses itself the first time it is drawn. A shell opened
            // and then left before that frame would take the keys from whatever
            // is on screen now. Focus is requested below, and only while this
            // terminal is the one being drawn.
            view.suppress_auto_focus();
            view
        });
        cx.subscribe(&view, |this, view, event: &TerminalEvent, cx| match event {
            TerminalEvent::Exited => this.mark_exited(&view, cx),
            TerminalEvent::AskAgent {
                text,
                start_line,
                end_line,
            } => this.ask_agent(text, *start_line, *end_line, cx),
        })
        .detach();
        let index = index.min(self.shells.len());
        self.shells.insert(
            index,
            LocalShell {
                view,
                exited: false,
            },
        );
        self.active = index;
        self.focus_pending = true;
        cx.notify();
    }

    fn mark_exited(&mut self, view: &Entity<TerminalView>, cx: &mut Context<Self>) {
        let id = view.entity_id();
        let Some(shell) = self
            .shells
            .iter_mut()
            .find(|shell| shell.view.entity_id() == id)
        else {
            return;
        };
        if shell.exited {
            return;
        }
        shell.exited = true;
        cx.notify();
    }

    fn activate(&mut self, index: usize, cx: &mut Context<Self>) {
        if index >= self.shells.len() || index == self.active {
            return;
        }
        self.active = index;
        self.focus_pending = true;
        cx.notify();
    }

    fn close_shell(&mut self, index: usize, cx: &mut Context<Self>) {
        if self.shells.len() <= 1 || index >= self.shells.len() {
            return;
        }
        self.shells.remove(index);
        if self.active > index {
            self.active -= 1;
        } else if self.active >= self.shells.len() {
            self.active = self.shells.len() - 1;
        }
        self.focus_pending = true;
        cx.notify();
    }

    fn take_focus(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.focus_pending || window.has_active_dialog(cx) {
            return;
        }
        self.focus_pending = false;
        if let Some(handle) = self.focus_handle(cx) {
            handle.focus(window, cx);
        }
    }

    fn header_button(
        &self,
        id: impl Into<gpui::ElementId>,
        cx: &Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        div()
            .id(id)
            .flex()
            .items_center()
            .h(px(26.))
            .px(px(8.))
            .gap(px(4.))
            .rounded(px(6.))
            .text_size(px(12.5))
            .text_color(cx.theme().muted_foreground)
            .cursor_pointer()
            .hover(|style| style.bg(theme::field()))
            .active(|style| style.bg(theme::element_active()))
    }

    fn render_add_button(&self, cx: &mut Context<Self>) -> AnyElement {
        let show_hint = hints::is_shown(cx);
        self.header_button("local-new-shell", cx)
            .tooltip(|window, cx| {
                Tooltip::new(format!("New terminal ({NEW_TERMINAL_SHORTCUT})")).build(window, cx)
            })
            .when(show_hint, |el| el.child(hints::badge(hints::NEW_TERMINAL)))
            .when(!show_hint, |el| {
                el.child(Icon::new(IconName::Plus).size(px(12.)))
            })
            .on_click(cx.listener(|this, _, _, cx| this.open_shell(cx)))
            .into_any_element()
    }

    fn render_restart(&self, cx: &mut Context<Self>) -> AnyElement {
        self.header_button("local-restart", cx)
            .text_color(cx.theme().foreground)
            .child("New shell")
            .on_click(cx.listener(|this, _, _, cx| this.restart_active(cx)))
            .into_any_element()
    }

    fn render_tab(&self, index: usize, cx: &mut Context<Self>) -> AnyElement {
        let is_active = index == self.active;
        let exited = self.shells.get(index).is_some_and(|shell| shell.exited);
        let label = if self.shells.len() == 1 {
            "Local".to_string()
        } else {
            (index + 1).to_string()
        };
        let fg = cx.theme().foreground;
        let close = (self.shells.len() > 1).then(|| {
            div()
                .id(("local-tab-close", index))
                .px(px(2.))
                .rounded(px(3.))
                .text_color(theme::text_dim())
                .hover(move |style| style.bg(theme::element_hover()).text_color(fg))
                // Mouse-down, not click: it must not reach the tab under it.
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, cx| {
                        cx.stop_propagation();
                        this.close_shell(index, cx);
                    }),
                )
                .child("\u{00D7}")
        });
        self.header_button(("local-tab", index), cx)
            .when(is_active, |el| {
                el.bg(theme::element())
                    .text_color(fg)
                    .font_weight(gpui::FontWeight::SEMIBOLD)
            })
            .when(self.shells.len() == 1, |el| {
                el.child(status_dot(if exited {
                    cx.theme().danger
                } else {
                    theme::status_online()
                }))
            })
            .child(label)
            .children(close)
            .on_click(cx.listener(move |this, _, _, cx| this.activate(index, cx)))
            .on_aux_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
                if event.is_middle_click() {
                    cx.stop_propagation();
                    this.close_shell(index, cx);
                }
            }))
            .into_any_element()
    }

    fn render_header(&self, cx: &mut Context<Self>) -> AnyElement {
        let active_exited = self
            .shells
            .get(self.active)
            .is_some_and(|shell| shell.exited);
        let mut strip = h_flex()
            .h(px(38.))
            .flex_none()
            .min_w_0()
            .px(px(8.))
            .gap(px(2.))
            .items_center()
            .border_b_1()
            .border_color(theme::border());
        for index in 0..self.shells.len() {
            strip = strip.child(self.render_tab(index, cx));
        }
        if self.shells.len() < MAX_SHELLS {
            strip = strip.child(self.render_add_button(cx));
        }
        strip = strip.child(div().flex_1());
        if active_exited {
            strip = strip
                .child(
                    div()
                        .pr(px(6.))
                        .text_size(px(12.))
                        .text_color(cx.theme().muted_foreground)
                        .child("Shell exited"),
                )
                .child(self.render_restart(cx));
        }
        if let Some(err) = self
            .spawn_error
            .as_ref()
            .filter(|_| !self.shells.is_empty())
        {
            strip = strip.child(
                div()
                    .pl(px(8.))
                    .max_w(px(240.))
                    .truncate()
                    .text_size(px(12.))
                    .text_color(cx.theme().danger)
                    .child(err.clone()),
            );
        }
        strip.child(self.render_tools(cx)).into_any_element()
    }

    fn render_tools(&self, cx: &mut Context<Self>) -> AnyElement {
        let agent_on = self.panel_shown && self.panel.read(cx).shows_agent();
        let inspector_on = self.panel_shown && !self.panel.read(cx).shows_agent();
        h_flex()
            .flex_none()
            .gap(px(2.))
            .when(self.vault_state.read(cx).agent_enabled(), |row| {
                row.child(
                    self.tool_button("local-agent", agent_on, cx)
                        .child(Icon::empty().path("icons/message-square.svg").size(px(15.)))
                        .tooltip(|window, cx| Tooltip::new("Agent").build(window, cx))
                        .on_click(cx.listener(|this, _, _, cx| this.toggle_agent(cx))),
                )
            })
            .child(
                self.tool_button("local-panel", inspector_on, cx)
                    .relative()
                    .child(Icon::empty().path("icons/panel-right.svg").size(px(15.)))
                    .when(hints::is_shown(cx), |el| {
                        el.child(hints::corner_badge(hints::SERVER_PANEL))
                    })
                    .tooltip(|window, cx| {
                        Tooltip::new(format!("Overview ({SERVER_PANEL_SHORTCUT})"))
                            .build(window, cx)
                    })
                    .on_click(cx.listener(|this, _, window, cx| this.toggle_panel(window, cx))),
            )
            .into_any_element()
    }

    fn tool_button(
        &self,
        id: &'static str,
        is_on: bool,
        cx: &Context<Self>,
    ) -> gpui::Stateful<gpui::Div> {
        self.header_button(id, cx).px(px(5.)).when(is_on, |el| {
            el.bg(theme::element()).text_color(cx.theme().foreground)
        })
    }

    fn render_side_panel(&self, window: &Window, cx: &mut Context<Self>) -> AnyElement {
        let width = self.panel.read(cx).laid_out_width(window, cx);
        let panel_id = self.panel.entity_id();
        let style = StyleRefinement::default().w(px(width)).flex_none().h_full();
        div()
            .id(("local-panel-frame", panel_id.as_u64()))
            .relative()
            .flex_none()
            .w(px(width))
            .h_full()
            .on_drag_move(cx.listener(
                move |this, event: &DragMoveEvent<PanelResize>, window, cx| {
                    let drag = event.drag(cx);
                    if !drag.is_for(panel_id) {
                        return;
                    }
                    let width = drag.width_at(event.event.position.x.as_f32());
                    this.panel
                        .update(cx, |panel, cx| panel.resize_to(width, window, cx));
                },
            ))
            .child(self.panel.clone().cached(style))
            .child(panel_resize_handle(panel_id, width))
            .into_any_element()
    }

    fn render_failure(&self, message: &str, cx: &mut Context<Self>) -> AnyElement {
        v_flex()
            .flex_1()
            .min_h_0()
            .items_center()
            .justify_center()
            .gap(px(8.))
            .child(
                div()
                    .text_size(px(15.))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(cx.theme().foreground)
                    .child("Couldn't open a local shell"),
            )
            .child(
                div()
                    .max_w(px(420.))
                    .text_size(px(13.))
                    .text_center()
                    .text_color(cx.theme().muted_foreground)
                    .child(message.to_string()),
            )
            .child(
                self.header_button("local-retry", cx)
                    .text_color(cx.theme().foreground)
                    .bg(theme::field())
                    .child("Try again")
                    .on_click(cx.listener(|this, _, _, cx| this.open_shell(cx))),
            )
            .into_any_element()
    }
}

fn status_dot(color: gpui::Hsla) -> gpui::Div {
    div().size(px(6.)).flex_none().rounded_full().bg(color)
}

fn machine_label() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default();
    let host = machine_name().filter(|host| !host.is_empty());
    match (user.is_empty(), host) {
        (false, Some(host)) => format!("{user}@{host}"),
        (true, Some(host)) => host,
        (false, None) => user,
        (true, None) => "Local".to_string(),
    }
}

fn machine_name() -> Option<String> {
    #[cfg(unix)]
    {
        let mut host = [0u8; 256];
        let ok = unsafe { libc::gethostname(host.as_mut_ptr().cast(), host.len()) } == 0;
        if !ok {
            return None;
        }
        let end = host
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(host.len());
        return Some(String::from_utf8_lossy(&host[..end]).trim().to_string());
    }
    #[cfg(not(unix))]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

impl Render for LocalTerminal {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.take_focus(window, cx);
        let body = if self.shells.is_empty() {
            let message = self
                .spawn_error
                .clone()
                .unwrap_or_else(|| "The shell did not start.".to_string());
            self.render_failure(&message, cx)
        } else {
            let terminal = self.shells[self.active].view.clone();
            div()
                .flex_1()
                .min_h_0()
                .overflow_hidden()
                .child(terminal)
                .into_any_element()
        };
        let main = v_flex()
            .size_full()
            .overflow_hidden()
            .child(self.render_header(cx))
            .child(body)
            .into_any_element();
        let panel = self.panel_shown.then(|| self.render_side_panel(window, cx));
        h_flex()
            .size_full()
            .overflow_hidden()
            .child(div().flex_1().min_w_0().h_full().child(main))
            .children(panel)
    }
}
