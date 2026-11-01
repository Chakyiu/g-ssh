//! A terminal on this computer. It uses the same emulator as an SSH session,
//! so a local shell (and `ssh` typed into it) gets the same grid, scrollback,
//! and keys.

use crate::ui::scale::px;
use gpui::prelude::*;
use gpui::{div, AnyElement, Context, Entity, Focusable as _, MouseButton, Window};

use gpui_component::{
    h_flex, tooltip::Tooltip, v_flex, ActiveTheme as _, Icon, IconName, WindowExt as _,
};

use crate::theme;
use crate::ui::hints;
use crate::ui::terminal::tabs::NEW_TERMINAL_SHORTCUT;
use crate::ui::terminal::view::{TerminalEvent, TerminalView};

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
}

impl LocalTerminal {
    pub fn new() -> Self {
        Self {
            shells: Vec::new(),
            active: 0,
            spawn_error: None,
            focus_pending: false,
        }
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
        let view = cx.new(|cx| {
            let mut view = TerminalView::new(shell, cx);
            // The view focuses itself the first time it is drawn. A shell opened
            // and then left before that frame would take the keys from whatever
            // is on screen now. Focus is requested below, and only while this
            // terminal is the one being drawn.
            view.suppress_auto_focus();
            view
        });
        cx.subscribe(&view, |this, view, event: &TerminalEvent, cx| {
            if matches!(event, TerminalEvent::Exited) {
                this.mark_exited(&view, cx);
            }
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
        strip.into_any_element()
    }

    fn render_failure(&self, message: &str, cx: &mut Context<Self>) -> AnyElement {
        v_flex()
            .size_full()
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

impl Render for LocalTerminal {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.take_focus(window, cx);
        if self.shells.is_empty() {
            let message = self
                .spawn_error
                .clone()
                .unwrap_or_else(|| "The shell did not start.".to_string());
            self.render_failure(&message, cx)
        } else {
            let body = self.shells[self.active].view.clone();
            v_flex()
                .size_full()
                .overflow_hidden()
                .child(self.render_header(cx))
                .child(div().flex_1().min_h_0().overflow_hidden().child(body))
                .into_any_element()
        }
    }
}
