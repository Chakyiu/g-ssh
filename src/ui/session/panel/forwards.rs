//! The Forwards tab: the host's saved port forwards, started and stopped here.
//!
//! Each row names the forward, what it routes, and how it is doing right now,
//! with a Start/Stop button. This page only runs forwards; they are defined in
//! the server form, so there is nothing to add or edit here.

use crate::ui::scale::px;
use gpui::prelude::*;
use gpui::{div, AnyElement, Context, SharedString};

use gpui_component::{
    button::{Button, ButtonVariants as _},
    h_flex,
    tooltip::Tooltip,
    v_flex, ActiveTheme as _, Disableable as _, Sizable as _, StyledExt as _,
};

use super::{note, section_title, ServerPanel};
use crate::theme;
use crate::ui::session::{ForwardRuntime, ServerSession};
use gssh::ssh::connection::{is_loopback_bind, ForwardKind};
use gssh::ssh::ForwardState;

impl ServerPanel {
    pub(super) fn render_forwards(&self, cx: &Context<Self>) -> Vec<AnyElement> {
        let Some(session) = self.remote() else {
            return vec![note("This computer has no port forwards.").into_any_element()];
        };
        let forwards = session.read(cx).forwards.clone();
        if forwards.is_empty() {
            return vec![
                note("No forwards on this host. Add one in the server form.").into_any_element(),
            ];
        }

        let is_live = session.read(cx).connection.is_some();
        let mut children = vec![section_title("Port forwarding").into_any_element()];
        for (index, forward) in forwards.iter().enumerate() {
            children.push(render_forward_row(index, forward, &session, is_live, cx));
        }
        children
    }
}

fn render_forward_row(
    index: usize,
    forward: &ForwardRuntime,
    session: &gpui::Entity<ServerSession>,
    is_live: bool,
    cx: &Context<ServerPanel>,
) -> AnyElement {
    let is_bound = forward.is_bound();
    let id = forward.spec.id.clone();
    let session = session.clone();

    v_flex()
        .id(("panel-forward", index))
        .gap(px(4.))
        .p(px(8.))
        .rounded(px(5.))
        .border_1()
        .border_color(theme::border())
        .child(
            h_flex()
                .gap(px(6.))
                .items_center()
                .child(forward_kind_pill(forward.spec.kind))
                .child(
                    div()
                        .min_w_0()
                        .flex_1()
                        .truncate()
                        .text_size(px(12.))
                        .font_semibold()
                        .text_color(cx.theme().foreground)
                        .child(SharedString::from(forward.name.clone())),
                )
                .when(!is_loopback_bind(&forward.spec.bind_address), |el| {
                    el.child(
                        div()
                            .flex_shrink_0()
                            .text_size(px(9.5))
                            .font_semibold()
                            .text_color(theme::warning())
                            .child("PUBLIC"),
                    )
                })
                .child(
                    Button::new(SharedString::from(format!("panel-forward-toggle-{id}")))
                        .ghost()
                        .xsmall()
                        .child(if is_bound { "Stop" } else { "Start" })
                        .when(!is_live, |button| button.disabled(true))
                        .on_click(cx.listener({
                            let id = id.clone();
                            move |_, _, _, cx| {
                                session.update(cx, |session, cx| {
                                    session.toggle_forward(id.clone(), cx)
                                })
                            }
                        })),
                ),
        )
        .child(
            div()
                .text_size(px(10.5))
                .text_color(cx.theme().muted_foreground)
                .truncate()
                .child(SharedString::from(forward.spec.route_label())),
        )
        .child({
            let label = SharedString::from(state_label(&forward.state, forward.spec.bind_port));
            let tip = label.clone();
            div()
                .id(("panel-forward-state", index))
                .text_size(px(10.5))
                .truncate()
                .text_color(state_color(&forward.state))
                // A stop reason can be long; the tooltip keeps it readable.
                .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                .child(label)
        })
        .into_any_element()
}

/// What the forward is doing, in one short line.
fn state_label(state: &ForwardState, bind_port: u16) -> String {
    match state {
        // A remote forward on port 0 gets its port from the server, so the
        // route line does not show it.
        ForwardState::Bound { bound_port, active } if *bound_port != bind_port => {
            format!("port {bound_port} \u{00b7} {}", activity_label(*active))
        }
        ForwardState::Bound { active, .. } => activity_label(*active),
        ForwardState::Stopped { reason: None } => "stopped".to_string(),
        ForwardState::Stopped {
            reason: Some(reason),
        } => reason.clone(),
    }
}

fn activity_label(active: u32) -> String {
    match active {
        0 => "listening".to_string(),
        1 => "1 connection".to_string(),
        n => format!("{n} connections"),
    }
}

fn state_color(state: &ForwardState) -> gpui::Hsla {
    match state {
        ForwardState::Bound { .. } => theme::status_online(),
        ForwardState::Stopped { reason: None } => theme::text_dim(),
        ForwardState::Stopped { reason: Some(_) } => theme::run_red(),
    }
}

/// Small neutral pill showing a forward's kind (Local / Remote / SOCKS5).
fn forward_kind_pill(kind: ForwardKind) -> impl IntoElement {
    div()
        .flex_none()
        .h(px(16.))
        .px(px(4.))
        .flex()
        .items_center()
        .rounded(px(3.))
        .bg(theme::element())
        .text_size(px(9.5))
        .text_color(theme::muted_gray())
        .child(kind.display_label())
}
