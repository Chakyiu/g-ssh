//! Port transfers for a server: the live list, its history, and the actions
//! that manage them.
//!
//! The rows are drawn in two places, from one implementation: the transfer list
//! under the file panes, and the inspector's Tasks page. Each caller supplies
//! its own [`TaskActions`], since the buttons act on different entities.
//!
//! This is part of `impl ServerSession`, kept out of the session module so
//! that module stays about the connection lifecycle.

use std::rc::Rc;
use std::time::Instant;

use crate::ui::scale::px;
use gpui::prelude::*;
use gpui::{div, AnyElement, App, Context, Entity, Hsla, SharedString, Window};

use gpui_component::{
    button::{Button, ButtonVariants as _},
    h_flex,
    progress::Progress,
    v_flex, ActiveTheme as _, Icon, IconName, Sizable as _, StyledExt as _,
};

use crate::theme;
use crate::ui::session::{ServerSession, TransferTask};
use crate::ui::sftp::browser::TransferKind;
use crate::ui::sftp::pane::fmt_size;
use gssh::ssh::TransferOutcome;

impl ServerSession {
    /// Drop one finished transfer from history, so a failure the user has read
    /// can go away without losing the others.
    pub(crate) fn dismiss_finished_task(&mut self, id: u64, cx: &mut Context<Self>) {
        let before = self.transfer_history.len();
        self.transfer_history.retain(|t| t.id != id);
        if self.transfer_history.len() == before {
            return;
        }
        if self.transfers.is_empty() && self.transfer_history.is_empty() {
            self.transfer_panel_collapsed = true;
        }
        self.refresh_tasks(cx);
        cx.notify();
    }

    /// Drop all finished transfers from history.
    pub(crate) fn clear_finished_tasks(&mut self, cx: &mut Context<Self>) {
        self.transfer_history.clear();
        self.refresh_tasks(cx);
        cx.notify();
    }

    /// Flag a transfer for cancellation. The worker notices between chunks and
    /// reports back via `TransferFinished`, which moves the row to history.
    pub(crate) fn cancel_transfer(&mut self, id: u64, cx: &mut Context<Self>) {
        if let Some(t) = self.transfers.iter().find(|t| t.id == id) {
            t.request_cancel();
            cx.notify();
        }
    }

    pub(crate) fn toggle_transfer_expand(&mut self, id: u64, cx: &mut Context<Self>) {
        if let Some(t) = self
            .transfers
            .iter_mut()
            .chain(self.transfer_history.iter_mut())
            .find(|t| t.id == id)
        {
            t.expanded = !t.expanded;
            self.refresh_tasks(cx);
            cx.notify();
        }
    }

    /// The count the inspector strip shows beside the Tasks icon: transfers
    /// still running, which is status rather than a label. Zero shows nothing.
    pub fn running_transfers(&self) -> usize {
        self.transfers.len()
    }

    /// Whether there is anything in the finished list. The strip's tooltip
    /// says so, since no text sits beside the icon.
    pub fn has_transfer_history(&self) -> bool {
        !self.transfer_history.is_empty()
    }

    /// A forward row's state changed, or the list did. The panel is drawn from
    /// a cache keyed on its own entity, so the page that shows these rows has
    /// to be told to draw again; this session's notify only repaints the shell
    /// around it.
    pub(crate) fn refresh_tasks(&self, cx: &mut Context<Self>) {
        self.server_panel.update(cx, |_, cx| cx.notify());
    }

    /// Live uploads and downloads under the file panes. Hidden when nothing
    /// has been transferred this connection. Folds to one row once the last
    /// transfer ends, so the file list gets its height back.
    pub fn render_sftp_transfer_panel(&self, cx: &Context<Self>) -> Option<AnyElement> {
        if self.transfers.is_empty() && self.transfer_history.is_empty() {
            return None;
        }
        let now = Instant::now();
        let body = if self.transfer_panel_collapsed {
            self.render_collapsed_transfer(now, cx)
        } else {
            self.render_transfer_panel_list(now, cx)
        };

        Some(
            v_flex()
                .id("sftp-transfer-panel")
                .occlude()
                .flex_none()
                .w_full()
                .overflow_hidden()
                .border_t_1()
                .border_color(theme::border())
                .bg(cx.theme().background)
                .child(self.render_transfer_panel_head(cx))
                .child(body)
                .into_any_element(),
        )
    }

    fn toggle_transfer_panel(&mut self, cx: &mut Context<Self>) {
        self.transfer_panel_collapsed = !self.transfer_panel_collapsed;
        cx.notify();
    }

    fn render_transfer_panel_head(&self, cx: &Context<Self>) -> AnyElement {
        let active = self.transfers.len();
        let can_clear = !self.transfer_history.is_empty();

        h_flex()
            .id("sftp-transfer-head")
            .h(px(28.))
            .w_full()
            .pl(px(2.))
            .pr(px(6.))
            .gap(px(2.))
            .items_center()
            .bg(theme::sunken_soft())
            .border_b_1()
            .border_color(theme::border())
            .child(self.transfer_panel_toggle(cx))
            .child(
                div()
                    .text_size(px(12.))
                    .font_semibold()
                    .text_color(cx.theme().foreground)
                    .child("Transfers"),
            )
            .when(active > 0, |el| {
                el.child(
                    div()
                        .text_size(px(12.))
                        .text_color(theme::text_dim())
                        .child(SharedString::from(active.to_string())),
                )
            })
            .child(div().flex_1())
            .when(can_clear, |el| el.child(self.transfer_clear_button(cx)))
            .into_any_element()
    }

    fn transfer_panel_toggle(&self, cx: &Context<Self>) -> AnyElement {
        let icon = if self.transfer_panel_collapsed {
            IconName::ChevronRight
        } else {
            IconName::ChevronDown
        };
        Button::new("sftp-transfer-toggle")
            .ghost()
            .icon(icon)
            .xsmall()
            .tooltip(if self.transfer_panel_collapsed {
                "Show transfers"
            } else {
                "Hide transfers"
            })
            .on_click(cx.listener(|this, _, _, cx| {
                cx.stop_propagation();
                this.toggle_transfer_panel(cx);
            }))
            .into_any_element()
    }

    fn transfer_clear_button(&self, cx: &Context<Self>) -> AnyElement {
        div()
            .id("sftp-transfer-clear")
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
            .on_click(cx.listener(|this, _, _, cx| {
                cx.stop_propagation();
                this.clear_finished_tasks(cx);
            }))
            .child("Clear")
            .into_any_element()
    }

    fn render_collapsed_transfer(&self, now: Instant, cx: &Context<Self>) -> AnyElement {
        let actions = TaskActions::for_session(cx);
        if let Some(transfer) = featured_transfer(&self.transfers) {
            let extra = self.transfers.len().saturating_sub(1);
            return render_active_transfer_row(transfer, extra, now, false, &actions, cx);
        }
        let Some(transfer) = self.transfer_history.first() else {
            return div().into_any_element();
        };
        let extra = self.transfer_history.len().saturating_sub(1);
        render_finished_transfer_row(transfer, extra, false, &actions, cx)
    }

    fn render_transfer_panel_list(&self, now: Instant, cx: &Context<Self>) -> AnyElement {
        let actions = TaskActions::for_session(cx);
        let mut rows = Vec::new();
        for transfer in &self.transfers {
            rows.push(render_active_transfer_row(
                transfer, 0, now, true, &actions, cx,
            ));
        }
        for transfer in &self.transfer_history {
            rows.push(render_finished_transfer_row(
                transfer, 0, true, &actions, cx,
            ));
        }

        div()
            .id("sftp-transfer-list")
            .w_full()
            .max_h(px(280.))
            .overflow_y_scroll()
            .child(v_flex().w_full().children(rows))
            .into_any_element()
    }
}

pub(crate) fn render_active_transfer_row(
    transfer: &TransferTask,
    extra: usize,
    now: Instant,
    details: bool,
    actions: &TaskActions,
    cx: &App,
) -> AnyElement {
    let id = transfer.id;
    let value = with_extra(transfer_value_text(transfer), extra);
    let pace = if transfer.is_queued {
        None
    } else {
        live_pace_text(transfer, now)
    };
    let show_bar = !transfer.is_queued;

    v_flex()
        .w_full()
        .px(px(8.))
        .pt(px(6.))
        .pb(px(7.))
        .gap(px(5.))
        .border_b_1()
        .border_color(theme::border())
        .child(
            h_flex()
                .w_full()
                .gap(px(8.))
                .items_center()
                .child(expand_chevron(
                    ("xfer-expand", id as usize),
                    transfer.expanded,
                    {
                        let expand = actions.expand.clone();
                        move |_, window, cx| expand(id, window, cx)
                    },
                ))
                .child(direction_icon(transfer.kind))
                .child(transfer_name(transfer.name.clone(), cx))
                .child(
                    div()
                        .flex_none()
                        .whitespace_nowrap()
                        .text_size(px(11.))
                        .font_semibold()
                        .text_color(cx.theme().foreground)
                        .child(SharedString::from(value)),
                )
                .child(transfer_stop_button(id, actions)),
        )
        .when(show_bar, |el| {
            el.child(transfer_progress_line(transfer, pace))
        })
        // `details` says this list may show detail at all; the row's own
        // `expanded` says whether this one does, so the chevron means something.
        .when(details && transfer.expanded, |el| {
            el.child(transfer_detail_panel(transfer, "sftp-xfer-detail", cx))
        })
        .into_any_element()
}

pub(crate) fn render_finished_transfer_row(
    transfer: &TransferTask,
    extra: usize,
    details: bool,
    actions: &TaskActions,
    cx: &App,
) -> AnyElement {
    let (icon, color, label) = match &transfer.outcome {
        Some(TransferOutcome::Done { skipped_links }) => (
            IconName::Check,
            theme::status_online(),
            done_text(transfer.done, *skipped_links),
        ),
        Some(TransferOutcome::Canceled) => {
            (IconName::Close, theme::text_dim(), "Canceled".to_string())
        }
        Some(TransferOutcome::Failed(error)) => (
            IconName::TriangleAlert,
            theme::run_red(),
            failed_label(error),
        ),
        None => (IconName::Close, theme::text_dim(), String::new()),
    };
    let label = with_extra(label, extra);

    v_flex()
        .w_full()
        .border_b_1()
        .border_color(theme::border())
        .child(
            h_flex()
                .w_full()
                .h(px(28.))
                .px(px(8.))
                .gap(px(8.))
                .items_center()
                .child(expand_chevron(
                    ("xfer-h-expand", transfer.id as usize),
                    transfer.expanded,
                    {
                        let expand = actions.expand.clone();
                        let id = transfer.id;
                        move |_, window, cx| expand(id, window, cx)
                    },
                ))
                .child(
                    div()
                        .w(px(12.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .flex_none()
                        .text_color(color)
                        .child(Icon::new(icon).size(px(12.))),
                )
                .child(transfer_name(transfer.name.clone(), cx))
                .child(
                    div()
                        .flex_none()
                        .max_w(px(200.))
                        .truncate()
                        .whitespace_nowrap()
                        .text_size(px(11.))
                        .text_color(color)
                        .child(SharedString::from(label)),
                )
                .child(transfer_dismiss_button(transfer.id, actions)),
        )
        // `details` says this list may show detail at all; the row's own
        // `expanded` says whether this one does, so the chevron means something.
        .when(details && transfer.expanded, |el| {
            el.child(transfer_detail_panel(transfer, "sftp-xfer-detail", cx))
        })
        .into_any_element()
}

/// The row actions a transfer row needs. Both callers hand in handlers already
/// bound to whatever entity owns them: the session itself for the list under
/// the file panes, the panel for the inspector's Tasks page.
#[derive(Clone)]
pub(crate) struct TaskActions {
    pub(crate) cancel: Rc<dyn Fn(u64, &mut Window, &mut App)>,
    pub(crate) dismiss: Rc<dyn Fn(u64, &mut Window, &mut App)>,
    pub(crate) expand: Rc<dyn Fn(u64, &mut Window, &mut App)>,
}

impl TaskActions {
    /// Rows drawn by the session itself: the transfer list under the file
    /// panes, where the handlers run against the session.
    pub(crate) fn for_session(cx: &Context<ServerSession>) -> Self {
        let view = cx.entity().downgrade();
        let cancel_view = view.clone();
        let dismiss_view = view.clone();
        let expand_view = view;
        Self {
            cancel: Rc::new(move |id, _, cx| {
                cancel_view
                    .update(cx, |session, cx| session.cancel_transfer(id, cx))
                    .ok();
            }),
            dismiss: Rc::new(move |id, _, cx| {
                dismiss_view
                    .update(cx, |session, cx| session.dismiss_finished_task(id, cx))
                    .ok();
            }),
            expand: Rc::new(move |id, _, cx| {
                expand_view
                    .update(cx, |session, cx| session.toggle_transfer_expand(id, cx))
                    .ok();
            }),
        }
    }

    /// Rows drawn by the inspector's Tasks page, which reports back to the
    /// session that owns the transfers.
    pub(crate) fn for_panel(session: &Entity<ServerSession>) -> Self {
        let view = session.downgrade();
        let cancel_view = view.clone();
        let dismiss_view = view.clone();
        let expand_view = view;
        Self {
            cancel: Rc::new(move |id, _, cx| {
                cancel_view
                    .update(cx, |session, cx| session.cancel_transfer(id, cx))
                    .ok();
            }),
            dismiss: Rc::new(move |id, _, cx| {
                dismiss_view
                    .update(cx, |session, cx| session.dismiss_finished_task(id, cx))
                    .ok();
            }),
            expand: Rc::new(move |id, _, cx| {
                expand_view
                    .update(cx, |session, cx| session.toggle_transfer_expand(id, cx))
                    .ok();
            }),
        }
    }
}

/// The close button of a finished row: dismissing it is not a cancel, but it
/// reads the same and sits in the same corner as the stop button.
fn transfer_dismiss_button(id: u64, actions: &TaskActions) -> AnyElement {
    div()
        .id(("sftp-xfer-dismiss", id as usize))
        .flex_none()
        .w(px(18.))
        .h(px(18.))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(3.))
        .text_color(theme::text_dim())
        .cursor_pointer()
        .hover(|style| style.bg(theme::element_hover()).text_color(theme::text()))
        .active(|style| style.bg(theme::element_active()))
        .on_click({
            let dismiss = actions.dismiss.clone();
            move |_, window, cx| dismiss(id, window, cx)
        })
        .child(Icon::new(IconName::Close).size(px(12.)))
        .into_any_element()
}

fn transfer_stop_button(id: u64, actions: &TaskActions) -> AnyElement {
    div()
        .id(("sftp-xfer-stop", id as usize))
        .flex_none()
        .w(px(18.))
        .h(px(18.))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(3.))
        .text_color(theme::text_dim())
        .cursor_pointer()
        .hover(|style| {
            style
                .bg(theme::element_hover())
                .text_color(theme::run_red())
        })
        .active(|style| {
            style
                .bg(theme::element_active())
                .text_color(theme::run_red())
        })
        .on_click({
            let cancel = actions.cancel.clone();
            move |_, window, cx| {
                cx.stop_propagation();
                cancel(id, window, cx);
            }
        })
        .child(Icon::new(IconName::Close).size(px(12.)))
        .into_any_element()
}

/// Compact duration: "8s", "1m04s", "2h13m".
fn elapsed_compact(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Interactive expand/collapse chevron for rows that carry their own buttons
/// (so the whole row isn't a single click target).
fn expand_chevron(
    id: impl Into<gpui::ElementId>,
    expanded: bool,
    on_click: impl Fn(&gpui::ClickEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> impl IntoElement {
    div()
        .id(id)
        .w(px(12.))
        .h(px(16.))
        .flex()
        .items_center()
        .justify_center()
        .text_color(theme::text_dim())
        .cursor_pointer()
        .hover(|s| s.text_color(theme::text()))
        .on_click(move |ev, window, cx| on_click(ev, window, cx))
        .child(chevron_icon(expanded))
}

fn direction_icon(kind: TransferKind) -> Icon {
    let icon = match kind {
        TransferKind::Upload => IconName::ArrowUp,
        TransferKind::Download => IconName::ArrowDown,
        TransferKind::Copy => IconName::ArrowRight,
    };
    Icon::new(icon).size(px(12.)).text_color(theme::text_dim())
}

fn chevron_icon(expanded: bool) -> Icon {
    let icon = if expanded {
        IconName::ChevronDown
    } else {
        IconName::ChevronRight
    };
    Icon::new(icon).size(px(10.))
}

/// Expanded detail for a single SFTP transfer: direction, size, %, speed, time.
fn transfer_detail_panel(t: &TransferTask, id: &'static str, cx: &App) -> impl IntoElement {
    let dim = theme::text_dim();
    let fg = cx.theme().foreground;

    let dur = match t.finished_at {
        Some(end) => end.saturating_duration_since(t.started),
        None => t.started.elapsed(),
    };
    let now = std::time::Instant::now();
    let is_running = t.outcome.is_none() && !t.is_queued;
    let secs = dur.as_secs_f64();
    // A running transfer shows what it does now, a finished one its average.
    let speed = if is_running {
        t.rate.bytes_per_sec(now).map(speed_text)
    } else if secs > 0.5 && !t.is_queued {
        Some(speed_text((t.done as f64 / secs) as u64))
    } else {
        None
    };
    let time_left = if is_running {
        seconds_left(t, now)
    } else {
        None
    };
    let error = match &t.outcome {
        Some(TransferOutcome::Failed(error)) => Some(error.clone()),
        _ => None,
    };
    let size = if t.total > 0 {
        format!(
            "{} / {} ({}%)",
            fmt_size(t.done),
            fmt_size(t.total),
            t.pct()
        )
    } else {
        fmt_size(t.done)
    };
    let direction = direction_text(t.kind, t.route.as_deref());
    let elapsed = if t.is_queued {
        "waiting for a free slot".to_string()
    } else {
        elapsed_compact(dur.as_secs())
    };

    let kv = |label: &'static str, value: String| {
        h_flex()
            .gap(px(8.))
            .items_baseline()
            .text_size(px(10.5))
            .child(div().w(px(58.)).flex_none().text_color(dim).child(label))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.))
                    .truncate()
                    .text_ellipsis_middle()
                    .text_color(fg)
                    .child(SharedString::from(value)),
            )
    };

    div()
        .id((id, t.id as usize))
        .mx(px(2.))
        .mb(px(3.))
        .p(px(7.))
        .rounded(px(3.))
        .bg(theme::sunken())
        .child(
            v_flex()
                .gap(px(3.))
                .child(kv("Direction", direction))
                .child(kv("Transferred", size))
                .children(speed.map(|speed| kv("Speed", speed)))
                .child(kv("Elapsed", elapsed))
                .children(time_left.map(|secs| kv("Time left", elapsed_compact(secs))))
                .children(error.map(|error| error_row(error, dim))),
        )
}

/// The full reason a transfer failed. It wraps, unlike the other detail rows:
/// the end of the message is often the part that explains it.
fn error_row(error: String, label_color: Hsla) -> impl IntoElement {
    h_flex()
        .gap(px(8.))
        .items_start()
        .text_size(px(10.5))
        .child(
            div()
                .w(px(58.))
                .flex_none()
                .text_color(label_color)
                .child("Error"),
        )
        .child(
            div()
                .flex_1()
                .min_w(px(0.))
                .text_color(theme::run_red())
                .child(SharedString::from(error)),
        )
}

fn speed_text(bytes_per_sec: u64) -> String {
    format!("{}/s", fmt_size(bytes_per_sec))
}

/// The direction line of a transfer's detail. A copy names both servers; an
/// upload or a download names the left server when it is the one in use.
fn direction_text(kind: TransferKind, route: Option<&str>) -> String {
    let verb = match kind {
        TransferKind::Copy => "Copy",
        TransferKind::Upload => "Upload",
        TransferKind::Download => "Download",
    };
    match (kind, route) {
        (TransferKind::Copy, Some(route)) => format!("{verb} {route}"),
        (_, Some(route)) => format!("{verb} via {route}"),
        (_, None) => verb.to_string(),
    }
}

/// Seconds a running transfer still needs, once its size and speed are known.
fn seconds_left(t: &TransferTask, now: std::time::Instant) -> Option<u64> {
    if t.total == 0 {
        return None;
    }
    t.rate.seconds_left(now, t.total.saturating_sub(t.done))
}

/// "11.2 MB/s · 40s left" for a running transfer; only the speed while the
/// time left is unknown, and `None` until there is a speed.
fn live_pace_text(t: &TransferTask, now: std::time::Instant) -> Option<String> {
    let speed = speed_text(t.rate.bytes_per_sec(now)?);
    Some(match seconds_left(t, now) {
        Some(secs) => format!("{speed} \u{00b7} {} left", elapsed_compact(secs)),
        None => speed,
    })
}

/// The short figure next to a running transfer: percent, or bytes so far when
/// the size is unknown, or that it still waits for a free slot.
fn transfer_value_text(t: &TransferTask) -> String {
    if t.is_queued {
        return "queued".to_string();
    }
    if t.total > 0 {
        return format!("{}%", t.pct());
    }
    fmt_size(t.done)
}

/// The transfer a folded panel shows: one that is already moving, or the
/// first in line when every one of them is still waiting for a slot.
fn featured_transfer(transfers: &[TransferTask]) -> Option<&TransferTask> {
    transfers
        .iter()
        .find(|transfer| !transfer.is_queued)
        .or_else(|| transfers.first())
}

/// Appends a count of the transfers the folded row does not name.
fn with_extra(label: String, extra: usize) -> String {
    if extra == 0 {
        label
    } else {
        format!("{label} \u{00b7} +{extra}")
    }
}

/// Whether the inspector strip shows a count beside the Tasks icon: only while
/// something is running. With nothing moving, the clock stands alone and the
/// tooltip explains it.
pub(crate) fn running_count_label(running: usize) -> Option<String> {
    (running > 0).then(|| running.to_string())
}

fn failed_label(error: &str) -> String {
    if error.is_empty() {
        "Failed".to_string()
    } else {
        format!("Failed \u{00b7} {error}")
    }
}

fn transfer_name(name: String, cx: &App) -> impl IntoElement {
    div()
        .flex_1()
        .min_w(px(0.))
        .truncate()
        .text_ellipsis_middle()
        .text_size(px(12.))
        .font_semibold()
        .text_color(cx.theme().foreground)
        .child(name)
}

fn transfer_progress_line(transfer: &TransferTask, pace: Option<String>) -> impl IntoElement {
    let indeterminate = transfer.total == 0;
    let bar = Progress::new(("sftp-xfer", transfer.id as usize))
        .value(transfer.pct() as f32)
        .loading(indeterminate)
        .color(theme::accent())
        .xsmall()
        .w_full()
        .accessibility_label(SharedString::from(format!(
            "{} {}",
            direction_text(transfer.kind, None),
            transfer.name
        )));

    h_flex()
        .w_full()
        .gap(px(8.))
        .items_center()
        .child(div().flex_1().min_w(px(48.)).child(bar))
        .when_some(pace, |el, pace| {
            el.child(
                div()
                    .flex_none()
                    .max_w(px(168.))
                    .truncate()
                    .whitespace_nowrap()
                    .text_size(px(10.5))
                    .text_color(theme::text_dim())
                    .child(SharedString::from(pace)),
            )
        })
}

/// Meta text of a finished transfer: its size, plus the symlinks a folder
/// transfer left out, so a missing link in the copy is not a silent surprise.
fn done_text(bytes: u64, skipped_links: usize) -> String {
    let size = fmt_size(bytes);
    match skipped_links {
        0 => size,
        1 => format!("{size} \u{00b7} 1 link skipped"),
        n => format!("{size} \u{00b7} {n} links skipped"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_text_names_both_servers_of_a_copy() {
        assert_eq!(direction_text(TransferKind::Upload, None), "Upload");
        assert_eq!(direction_text(TransferKind::Download, None), "Download");
        assert_eq!(direction_text(TransferKind::Copy, None), "Copy");
        assert_eq!(
            direction_text(TransferKind::Copy, Some("from web-02 to web-01")),
            "Copy from web-02 to web-01"
        );
    }

    #[test]
    fn direction_text_names_the_left_server_of_an_upload_or_download() {
        assert_eq!(
            direction_text(TransferKind::Upload, Some("web-02")),
            "Upload via web-02"
        );
        assert_eq!(
            direction_text(TransferKind::Download, Some("web-02")),
            "Download via web-02"
        );
    }

    #[test]
    fn with_extra_names_the_transfers_a_folded_row_hides() {
        assert_eq!(with_extra("64%".to_string(), 0), "64%");
        assert_eq!(with_extra("64%".to_string(), 2), "64% \u{00b7} +2");
    }

    #[test]
    fn failed_label_keeps_the_reason() {
        assert_eq!(failed_label(""), "Failed");
        assert_eq!(
            failed_label("connection reset"),
            "Failed \u{00b7} connection reset"
        );
    }

    #[test]
    fn done_text_mentions_skipped_links_only_when_there_are_some() {
        assert_eq!(done_text(0, 0), fmt_size(0));
        assert!(done_text(10, 1).ends_with("1 link skipped"));
        assert!(done_text(10, 3).ends_with("3 links skipped"));
    }

    #[test]
    fn the_strip_shows_no_count_when_nothing_is_running() {
        // "history" used to sit here, but it is a label, not status: the
        // tooltip carries it instead.
        assert_eq!(running_count_label(0), None);
    }

    #[test]
    fn the_strip_counts_what_is_running() {
        assert_eq!(running_count_label(1).unwrap(), "1");
        assert_eq!(running_count_label(3).unwrap(), "3");
    }
}
