//! The Tasks tab: the transfers running for this host, and what has finished.
//!
//! A transfer is the same row the file pane draws under its panes; the rows
//! come from [`crate::ui::session::tasks`] so the two never drift apart. Only
//! the entity behind the buttons differs: here they report back to the session
//! that owns the transfers.

use std::time::Instant;

use crate::ui::scale::px;
use gpui::prelude::*;
use gpui::{div, AnyElement, Context, Entity};

use gpui_component::h_flex;

use super::{note, section_title, ServerPanel};
use crate::theme;
use crate::ui::session::tasks::{
    render_active_transfer_row, render_finished_transfer_row, TaskActions,
};
use crate::ui::session::ServerSession;

impl ServerPanel {
    pub(super) fn render_tasks(&self, cx: &Context<Self>) -> Vec<AnyElement> {
        let Some(session_entity) = self.remote() else {
            return vec![note("This computer has no transfers.").into_any_element()];
        };
        let actions = TaskActions::for_panel(&session_entity);
        // The rows borrow the transfers, so the read guard has to outlive the
        // walk over them; the whole page is built inside it.
        let session = session_entity.read(cx);
        let transfers = &session.transfers;
        let history = &session.transfer_history;
        if transfers.is_empty() && history.is_empty() {
            return vec![note(
                "Nothing has moved this connection. Uploads and downloads appear here.",
            )
            .into_any_element()];
        }

        let now = Instant::now();
        let mut children = Vec::new();

        if !transfers.is_empty() {
            children.push(section_title("Running").into_any_element());
            for transfer in transfers {
                children.push(render_active_transfer_row(
                    transfer, 0, now, true, &actions, cx,
                ));
            }
        }
        if !history.is_empty() {
            let clear = clear_finished_button(cx);
            children.push(
                h_flex()
                    .items_center()
                    .gap(px(8.))
                    .child(section_title("Earlier"))
                    .child(div().flex_1())
                    .child(clear)
                    .into_any_element(),
            );
            for transfer in history {
                children.push(render_finished_transfer_row(
                    transfer, 0, true, &actions, cx,
                ));
            }
        }
        children
    }

    /// The session this page reports back to, for a button that cannot hold a
    /// read guard while it runs.
    fn remote_entity(&self) -> Option<Entity<ServerSession>> {
        self.remote()
    }
}

/// Drop every finished transfer from the history. The session owns the list,
/// so the panel asks it rather than editing a copy.
fn clear_finished_button(cx: &Context<ServerPanel>) -> AnyElement {
    let session = cx.entity().downgrade();
    div()
        .id("panel-tasks-clear")
        .flex_none()
        .h(px(18.))
        .px(px(6.))
        .flex()
        .items_center()
        .rounded(px(3.))
        .text_size(px(10.5))
        .text_color(theme::text_dim())
        .cursor_pointer()
        .hover(|style| style.bg(theme::element_hover()).text_color(theme::text()))
        .active(|style| style.bg(theme::element_active()))
        .on_click({
            let session = session.clone();
            move |_, _, cx| {
                cx.stop_propagation();
                session
                    .update(cx, |panel, cx| {
                        if let Some(session) = panel.remote_entity() {
                            session.update(cx, |session, cx| session.clear_finished_tasks(cx));
                        }
                    })
                    .ok();
            }
        })
        .child("Clear")
        .into_any_element()
}
