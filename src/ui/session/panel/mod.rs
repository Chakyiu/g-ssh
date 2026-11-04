//! The panel on the right of a session: what the server is and how busy it
//! is, what the vault keeps for it, and an agent that asks before it runs
//! a command. Metrics are read over an exec channel every two seconds, and
//! only while the panel is on screen.

mod agent;
mod agent_store;
mod forwards;
mod metrics;
mod snippets;
mod tasks;

use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use crate::ui::scale::px;
use futures::channel::mpsc;
use futures::future::Either;
use futures::StreamExt as _;
use gpui::prelude::*;
use gpui::{
    div, AnyElement, Axis, BackgroundExecutor, ClipboardItem, Context, Div, ElementId, Entity,
    EntityId, EventEmitter, SharedString, Task, WeakEntity, Window,
};

use gpui_component::{
    h_flex, resizable::HandleEdge, resize_handle, tooltip::Tooltip, v_flex, ActiveTheme as _, Icon,
    StyledExt as _,
};

use crate::host_stats::{self, Sample, SystemInfo};
use crate::preferences::Preferences;
use crate::theme;
use crate::ui::local::LocalTerminal;
use crate::ui::session::tasks::running_count_label;
use crate::ui::session::ServerSession;
use crate::ui::VaultState;
use gssh::ssh::shell::ShellHandle;
use gssh::ssh::SshConnection;

/// Where the panel's shell, chats, and metrics come from.
pub(crate) enum PanelHost {
    Remote(WeakEntity<ServerSession>),
    Local(WeakEntity<LocalTerminal>),
}

pub const PANEL_WIDTH: f32 = 320.;
/// The agent review box holds terminal text, so the panel grows while the
/// chat is open and a listing line can stay on one row.
pub const AGENT_PANEL_WIDTH: f32 = 480.;
/// Dragging the left edge cannot go below this.
const PANEL_MIN_WIDTH: f32 = 260.;
/// Or above this.
const PANEL_MAX_WIDTH: f32 = 720.;
/// Sidebar, window padding, and a shell that can still be typed in.
const PANEL_RESERVED: f32 = 520.;
const TICK: Duration = Duration::from_secs(2);
/// The first two readings come this fast, so the numbers and the graphs show
/// within a second of opening: each reading needs the sample before it.
const FIRST_READINGS_DELAY: Duration = Duration::from_millis(500);
/// How often to look again while the session is still connecting.
const CONNECT_RETRY: Duration = Duration::from_millis(500);
/// Two minutes of points.
const HISTORY_LEN: usize = 60;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// Pages of the inspector. The agent chat is a different panel, opened from
/// its own button, so it is not a third page here.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Forwards,
    Tasks,
    Snippets,
}

pub enum ServerPanelEvent {
    RunSnippet(uuid::Uuid),
    /// Open Settings on the agent endpoint page.
    OpenAgentSettings,
    /// The panel changed width. The agent chat is wider than the inspector.
    /// The session lays the panel out again; the panel itself already redraws
    /// on `notify`.
    WidthChanged,
}

pub use agent_store::{
    clear_host_sessions, clear_session_records, list_session_records, remove_session, SessionRecord,
};

pub(crate) use agent::{
    allow_entry, canonical_base as canonical_agent_base, list_models as list_agent_models,
    requires_key as agent_base_needs_key, session_login, SelectionCite,
    DEFAULT_BASE as DEFAULT_AGENT_BASE, SYSTEM_PROMPT as AGENT_SYSTEM_PROMPT,
};

/// One point of the graphs.
#[derive(Clone, Copy)]
struct Reading {
    cpu: f64,
    memory: f64,
    rx: f64,
    tx: f64,
}

pub struct ServerPanel {
    host: PanelHost,
    vault_state: Entity<VaultState>,
    /// Overview or Snippets. Kept while the agent chat is in front, so the
    /// inspector opens on the same page.
    tab: Tab,
    /// The agent chat fills this panel. Overview and snippets are the other
    /// face, and the two do not share a tab strip.
    showing_agent: bool,
    info: Option<SystemInfo>,
    /// Telnet and RDP have no exec channel. The overview names the host
    /// with this instead of waiting for a probe.
    idle_label: Option<&'static str>,
    /// The host printed no `/proc/stat`: only the system info shows.
    is_unsupported: bool,
    last_sample: Option<Sample>,
    history: VecDeque<Reading>,
    snippet_editor: Option<snippets::SnippetEditor>,
    agent: Option<agent::Agent>,
    /// Applied on the next frame, which has a window for the text fields.
    agent_open: Option<agent::AgentOpen>,
    /// Polling stops when the panel is off screen: hidden, or its tab is not
    /// in front. Every poll ends in a redraw, which keeps this fresh. `None`
    /// until the first render.
    last_rendered: Option<Instant>,
    /// Wakes the poll loop when the panel comes back on screen.
    wake: mpsc::UnboundedSender<()>,
    _poll_task: Task<()>,
    /// Last seen generation of saved agent chats. Settings bumps it when a
    /// record is removed, and the next frame drops that chat here too.
    chat_epoch: u64,
    /// A save ran while the vault was locked. Seal the file once it unlocks.
    chats_need_seal: bool,
}

enum NextStep {
    Read(Poll),
    /// Stats from this computer, not an SSH exec.
    ReadLocal {
        needs_info: bool,
        needs_sample: bool,
    },
    Wait(Duration),
}

struct Poll {
    connection: SshConnection,
    needs_info: bool,
    needs_sample: bool,
}

impl EventEmitter<ServerPanelEvent> for ServerPanel {}

impl ServerPanel {
    pub fn new(
        host: PanelHost,
        idle_label: Option<&'static str>,
        vault_state: Entity<VaultState>,
        cx: &mut Context<Self>,
    ) -> Self {
        // The snippets and the connection rows show what the vault holds.
        cx.observe(&vault_state, |this, vault, cx| {
            // The chat has no button once the agent is turned off, so close it.
            if !vault.read(cx).agent_enabled() && this.showing_agent {
                this.showing_agent = false;
                cx.emit(ServerPanelEvent::WidthChanged);
            }
            if this.chats_need_seal && vault.read(cx).manager().is_some() {
                this.persist_chats(cx);
            }
            cx.notify();
        })
        .detach();
        let (wake, mut woken) = mpsc::unbounded();
        let poll_task = cx.spawn(async move |this, cx| {
            let mut delay = Duration::ZERO;
            loop {
                // A wake from `render` cuts the wait short.
                let timer = cx.background_executor().timer(delay);
                futures::future::select(timer, woken.next()).await;
                while woken.try_recv().is_ok() {}
                let Ok(step) = this.update(cx, |panel, cx| panel.next_step(cx)) else {
                    break;
                };
                let executor = cx.background_executor().clone();
                let (info, sample) = match step {
                    NextStep::Wait(wait) => {
                        delay = wait;
                        continue;
                    }
                    NextStep::Read(poll) => read_host(&poll, &executor).await,
                    NextStep::ReadLocal {
                        needs_info,
                        needs_sample,
                    } => {
                        executor
                            .spawn(async move { host_stats::read_local(needs_info, needs_sample) })
                            .await
                    }
                };
                let Ok(next) = this.update(cx, |panel, cx| {
                    panel.take_output(info, sample, cx);
                    panel.delay_after_poll()
                }) else {
                    break;
                };
                delay = next;
            }
        });
        Self {
            host,
            vault_state,
            tab: Tab::Overview,
            showing_agent: false,
            info: None,
            idle_label,
            is_unsupported: idle_label.is_some(),
            last_sample: None,
            history: VecDeque::with_capacity(HISTORY_LEN),
            snippet_editor: None,
            agent: None,
            agent_open: None,
            last_rendered: None,
            wake,
            _poll_task: poll_task,
            chat_epoch: agent_store::chat_record_epoch(),
            chats_need_seal: false,
        }
    }

    fn is_on_screen(&self) -> bool {
        self.last_rendered
            .is_some_and(|rendered| rendered.elapsed() <= TICK * 2)
    }

    fn next_step(&self, cx: &Context<Self>) -> NextStep {
        // Off screen, the next render wakes the loop.
        if !self.is_on_screen() {
            return NextStep::Wait(TICK);
        }
        // Telnet has no exec channel. A host marked unsupported stays that way.
        if self.is_unsupported && !self.is_local() {
            return NextStep::Wait(TICK);
        }
        if matches!(self.host, PanelHost::Local(_)) {
            let needs_info = self.info.is_none();
            let needs_sample = !self.is_unsupported;
            if !needs_info && !needs_sample {
                return NextStep::Wait(TICK);
            }
            return NextStep::ReadLocal {
                needs_info,
                needs_sample,
            };
        }
        let connection = self
            .remote()
            .and_then(|session| session.read(cx).connection.clone());
        let Some(connection) = connection else {
            return NextStep::Wait(CONNECT_RETRY);
        };
        let needs_info = self.info.is_none();
        let needs_sample = !self.is_unsupported;
        if !needs_info && !needs_sample {
            return NextStep::Wait(TICK);
        }
        NextStep::Read(Poll {
            connection,
            needs_info,
            needs_sample,
        })
    }

    /// Wakes the poll loop, which waits while the panel is off screen. After
    /// a long while the graphs start over, as the old line would join the new.
    fn come_back_on_screen(&mut self) {
        let is_long_gone = self
            .last_rendered
            .is_none_or(|rendered| rendered.elapsed() > TICK * 5);
        if is_long_gone {
            self.history.clear();
        }
        self.wake.unbounded_send(()).ok();
    }

    fn delay_after_poll(&self) -> Duration {
        if self.last_sample.is_some() && self.history.len() < 2 {
            FIRST_READINGS_DELAY
        } else {
            TICK
        }
    }

    fn take_output(
        &mut self,
        info: Option<String>,
        sample: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if let Some(info) = info.filter(|info| !info.trim().is_empty()) {
            let info = host_stats::parse_info(&info);
            tracing::debug!(host = %info.hostname, os = ?info.os_name, "server panel read the system info");
            self.info = Some(info);
        }
        // Empty output is a failed read, such as a channel refused for now.
        if let Some(output) = sample.filter(|output| !output.trim().is_empty()) {
            match host_stats::parse_sample(&output) {
                Some(sample) => self.add_sample(sample),
                None => {
                    tracing::info!(
                        "the host has no /proc/stat, so the server panel shows no metrics"
                    );
                    self.is_unsupported = true;
                }
            }
        }
        cx.notify();
    }

    fn add_sample(&mut self, sample: Sample) {
        if let Some(previous) = &self.last_sample {
            // The host's own clock: the time on the wire would make the rates jump.
            let elapsed = sample.uptime.saturating_sub(previous.uptime);
            // Off screen for a while: rates over the whole gap would not be
            // what the host does now.
            if elapsed > TICK * 5 {
                self.history.clear();
                self.last_sample = Some(sample);
                return;
            }
            if self.history.len() == HISTORY_LEN {
                self.history.pop_front();
            }
            self.history.push_back(Reading {
                cpu: host_stats::cpu_percent(&previous.cpu, &sample.cpu) as f64,
                memory: share(sample.memory.used(), sample.memory.total),
                rx: host_stats::bytes_per_second(previous.net_rx, sample.net_rx, elapsed),
                tx: host_stats::bytes_per_second(previous.net_tx, sample.net_tx, elapsed),
            });
        }
        self.last_sample = Some(sample);
    }

    fn set_tab(&mut self, tab: Tab, cx: &mut Context<Self>) {
        if self.tab == tab {
            return;
        }
        self.tab = tab;
        cx.notify();
    }

    /// Leave the agent chat and show Overview or Snippets, whichever was open last.
    pub(crate) fn show_inspector(&mut self, cx: &mut Context<Self>) {
        if !self.showing_agent {
            return;
        }
        self.showing_agent = false;
        cx.emit(ServerPanelEvent::WidthChanged);
        cx.notify();
    }

    pub(super) fn panel_width(&self, cx: &gpui::App) -> f32 {
        let saved = if self.showing_agent {
            Preferences::agent_panel_width(cx)
        } else {
            Preferences::server_panel_width(cx)
        };
        saved.unwrap_or(if self.showing_agent {
            AGENT_PANEL_WIDTH
        } else {
            PANEL_WIDTH
        })
    }

    /// Width for this frame: the saved drag, or the face's default, clamped
    /// so the shell beside the panel keeps room.
    pub(crate) fn laid_out_width(&self, window: &Window, cx: &gpui::App) -> f32 {
        clamp_panel_width(self.panel_width(cx), window.viewport_size().width.as_f32())
    }

    pub(crate) fn resize_to(&mut self, width: f32, window: &Window, cx: &mut Context<Self>) {
        let width = clamp_panel_width(width, window.viewport_size().width.as_f32());
        if self.panel_width(cx) == width {
            return;
        }
        Preferences::set_dragged_panel_width(self.showing_agent, width, cx);
        cx.emit(ServerPanelEvent::WidthChanged);
        cx.notify();
    }

    /// The strip above the body. Page tabs are icons with hover labels: at
    /// 320px wide, "Overview" and "Snippets" spelled out leave no room for the
    /// rest of the row.
    fn render_tabs(&self, cx: &Context<Self>) -> impl IntoElement {
        let option = |id: &'static str, tab: Tab, icon: &'static str, label: &'static str| {
            let is_active = self.tab == tab;
            tab_icon(id, is_active, cx)
                .child(Icon::empty().path(icon).size(px(14.)))
                .tooltip(move |window, cx| Tooltip::new(label).build(window, cx))
                .on_click(cx.listener(move |this, _, _, cx| this.set_tab(tab, cx)))
        };

        let mut row = h_flex()
            .p(px(2.))
            .gap(px(2.))
            .rounded(px(7.))
            .bg(theme::field())
            .child(option(
                "server-panel-overview",
                Tab::Overview,
                "icons/gauge.svg",
                "Overview",
            ));

        // Forwards and transfers belong to a connection, so a local shell has
        // no pages for them at all. A connection keeps both, empty or not: a
        // missing icon would leave no way to reach the page.
        if self.remote().is_some() {
            row = row.child(self.render_forwards_tab(cx));
        }

        row = row.child(option(
            "server-panel-snippets",
            Tab::Snippets,
            "icons/file-code.svg",
            "Snippets",
        ));

        if self.remote().is_some() {
            row = row.child(self.render_tasks_tab(cx));
        }
        row
    }

    /// The Forwards page tab. The count stays beside the icon because it is
    /// status, not a label: `0/1` says at a glance that nothing is bound.
    fn render_forwards_tab(&self, cx: &Context<Self>) -> AnyElement {
        let entry = self
            .remote()
            .and_then(|session| session.read(cx).forwards_menu_entry());
        let (count, failed) = match entry {
            Some(entry) => (Some(entry.count), entry.failed),
            None => (None, false),
        };
        // A forward that died by itself keeps the red it had as a chip.
        let count_color = if failed {
            theme::run_red()
        } else {
            theme::text_dim()
        };
        let tip = match &count {
            Some(count) => format!("Forwards {count}"),
            None => "Forwards".to_string(),
        };
        let is_active = self.tab == Tab::Forwards;
        tab_icon("server-panel-forwards", is_active, cx)
            .child(
                Icon::empty()
                    .path("icons/arrow-right-left.svg")
                    .size(px(14.)),
            )
            .children(count.map(|count| {
                div()
                    .text_size(px(9.5))
                    .text_color(count_color)
                    .child(SharedString::from(count))
            }))
            .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
            .on_click(cx.listener(|this, _, _, cx| this.set_tab(Tab::Forwards, cx)))
            .into_any_element()
    }

    /// The Tasks page tab. No text sits beside the clock: with nothing running
    /// the old one read "history", which is a label rather than status, and
    /// the tooltip says it. A running count still shows, since that changes.
    fn render_tasks_tab(&self, cx: &Context<Self>) -> AnyElement {
        let (running, has_history) = match self.remote() {
            Some(session) => {
                let session = session.read(cx);
                (session.running_transfers(), session.has_transfer_history())
            }
            None => (0, false),
        };
        let tip = match (running, has_history) {
            (0, true) => "Tasks history".to_string(),
            (0, false) => "Tasks".to_string(),
            (running, false) => format!("Tasks, {running} running"),
            (running, true) => format!("Tasks, {running} running and history"),
        };
        let is_active = self.tab == Tab::Tasks;
        tab_icon("server-panel-tasks", is_active, cx)
            .child(Icon::empty().path("icons/clock.svg").size(px(14.)))
            .children(running_count_label(running).map(|count| {
                div()
                    .text_size(px(9.5))
                    .text_color(theme::text_dim())
                    .child(SharedString::from(count))
            }))
            .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
            .on_click(cx.listener(|this, _, _, cx| this.set_tab(Tab::Tasks, cx)))
            .into_any_element()
    }

    pub(crate) fn vault(&self) -> Entity<VaultState> {
        self.vault_state.clone()
    }

    pub(crate) fn agent_enabled(&self, cx: &gpui::App) -> bool {
        self.vault_state.read(cx).agent_enabled()
    }

    fn is_local(&self) -> bool {
        matches!(self.host, PanelHost::Local(_))
    }

    fn remote(&self) -> Option<Entity<ServerSession>> {
        match &self.host {
            PanelHost::Remote(session) => session.upgrade(),
            PanelHost::Local(_) => None,
        }
    }

    /// The vault entry of the session's host. A local terminal has none.
    fn server_id(&self, cx: &gpui::App) -> Option<uuid::Uuid> {
        let session = self.remote()?;
        uuid::Uuid::parse_str(&session.read(cx).server_id).ok()
    }

    pub(super) fn host_key(&self, cx: &gpui::App) -> String {
        match &self.host {
            PanelHost::Remote(session) => session
                .upgrade()
                .map(|session| session.read(cx).server_id.clone())
                .unwrap_or_default(),
            PanelHost::Local(_) => "local".to_string(),
        }
    }

    pub(super) fn host_label(&self, cx: &gpui::App) -> String {
        match &self.host {
            PanelHost::Remote(_) => String::new(),
            PanelHost::Local(local) => local
                .upgrade()
                .map(|local| local.read(cx).machine_label())
                .unwrap_or_else(|| "Local".to_string()),
        }
    }

    pub(super) fn active_shell(&self, cx: &gpui::App) -> Option<ShellHandle> {
        match &self.host {
            PanelHost::Remote(session) => {
                let session = session.upgrade()?;
                let terminal = session.read(cx).active_terminal()?.clone();
                Some(terminal.read(cx).shell.clone())
            }
            PanelHost::Local(local) => local.upgrade()?.read(cx).active_shell(cx),
        }
    }

    pub(super) fn show_terminal(&self, cx: &mut Context<Self>) {
        match &self.host {
            PanelHost::Remote(session) => {
                let Some(session) = session.upgrade() else {
                    return;
                };
                session.update(cx, |session, cx| {
                    session.is_sftp_hidden = true;
                    session.is_terminal_focus_pending = true;
                    cx.notify();
                });
            }
            PanelHost::Local(local) => {
                let Some(local) = local.upgrade() else {
                    return;
                };
                local.update(cx, |local, cx| local.focus_shell(cx));
            }
        }
    }

    fn scroll_body(&self, content: Vec<gpui::AnyElement>) -> gpui::AnyElement {
        v_flex()
            .id("server-panel-scroll")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .px(px(12.))
            .pt(px(6.))
            .pb(px(12.))
            .gap(px(10.))
            .children(content)
            .into_any_element()
    }
}

impl Render for ServerPanel {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if !self.is_on_screen() {
            self.come_back_on_screen();
        }
        self.last_rendered = Some(Instant::now());
        let showing_agent = self.showing_agent;
        let body = if showing_agent {
            self.render_agent(window, cx)
        } else {
            match self.tab {
                Tab::Overview => self.scroll_body(self.render_overview(cx)),
                Tab::Forwards => self.scroll_body(self.render_forwards(cx)),
                Tab::Tasks => self.scroll_body(self.render_tasks(cx)),
                Tab::Snippets => self.scroll_body(self.render_snippets(cx)),
            }
        };
        // The session sizes this and draws the resize handle. A fixed width
        // here would fight that drag.
        v_flex()
            .size_full()
            .when(!showing_agent, |el| {
                el.child(
                    div()
                        .flex_none()
                        .px(px(12.))
                        .pt(px(10.))
                        .pb(px(6.))
                        .child(self.render_tabs(cx)),
                )
            })
            .child(body)
    }
}

/// The system info and a sample, as far as `poll` asks for them: the output
/// for each, which is one and the same when both are read at once.
async fn read_host(poll: &Poll, executor: &BackgroundExecutor) -> (Option<String>, Option<String>) {
    let connection = &poll.connection;
    match (poll.needs_info, poll.needs_sample) {
        (true, true) => {
            let command = host_stats::info_and_sample_command();
            let output = run_command(connection, command, executor).await;
            (output.clone(), output)
        }
        (true, false) => {
            let output = run_command(connection, host_stats::info_command(), executor).await;
            (output, None)
        }
        (false, true) => {
            let output = run_command(connection, host_stats::sample_command(), executor).await;
            (None, output)
        }
        (false, false) => (None, None),
    }
}

/// Run `command` on the host and collect what it prints. `None` when no
/// channel could be opened or the command did not finish in time.
async fn run_command(
    connection: &SshConnection,
    command: String,
    executor: &BackgroundExecutor,
) -> Option<String> {
    let reading = async {
        let exec = connection.open_exec(command).await.ok()?;
        let output = exec.subscribe();
        let mut bytes = Vec::new();
        while let Ok(chunk) = output.recv().await {
            bytes.extend_from_slice(&chunk);
        }
        Some(String::from_utf8_lossy(&bytes).into_owned())
    };
    let limit = executor.timer(COMMAND_TIMEOUT);
    match futures::future::select(Box::pin(reading), Box::pin(limit)).await {
        Either::Left((output, _)) => output,
        Either::Right(_) => None,
    }
}

/// One control on the panel's strip: a square that takes the pressed look
/// while its page is in front. `flex_1` is deliberately absent: the tabs size
/// to their icons so a long row can still fit four of them.
fn tab_icon(
    id: impl Into<ElementId>,
    is_active: bool,
    cx: &Context<ServerPanel>,
) -> gpui::Stateful<Div> {
    div()
        .id(id)
        .h(px(24.))
        .min_w(px(28.))
        .px(px(6.))
        .flex()
        .items_center()
        .justify_center()
        .gap(px(3.))
        .rounded(px(5.))
        .cursor_pointer()
        .text_color(if is_active {
            cx.theme().foreground
        } else {
            theme::text_dim()
        })
        .when(is_active, |el| el.bg(theme::element()))
        .when(!is_active, |el| {
            el.hover(|style| style.bg(theme::element_hover()))
        })
}

fn section_title(text: &'static str) -> Div {
    div()
        .pt(px(6.))
        .text_size(px(11.5))
        .font_medium()
        .text_color(theme::text_dim())
        .child(text)
}

fn note(text: &'static str) -> Div {
    div()
        .py(px(8.))
        .text_size(px(12.))
        .text_color(theme::text_dim())
        .child(text)
}

/// A click copies the value.
fn info_row(
    ix: usize,
    key: &'static str,
    value: String,
    cx: &Context<ServerPanel>,
) -> impl IntoElement {
    let copied = value.clone();
    h_flex()
        .id(("server-info", ix))
        .gap(px(12.))
        .px(px(6.))
        .mx(px(-6.))
        .py(px(3.))
        .rounded(px(5.))
        .cursor_pointer()
        .hover(|s| s.bg(theme::field()))
        .active(|s| s.bg(theme::element_active()))
        .child(
            div()
                .flex_none()
                .text_size(px(11.5))
                .text_color(cx.theme().muted_foreground)
                .child(key),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .truncate()
                .text_right()
                .text_size(px(12.))
                .text_color(cx.theme().foreground)
                .child(value),
        )
        .tooltip(|window, cx| Tooltip::new("Copy").build(window, cx))
        .on_click(move |_, _, cx| cx.write_to_clipboard(ClipboardItem::new_string(copied.clone())))
}

/// The drag of this panel's left edge. The session hears it anywhere in the
/// window; the handle only starts it.
pub(crate) struct PanelResize {
    panel: EntityId,
    /// Set when the drag starts. `None` until then, so the first move can
    /// still lock the origin if the start hook has not run.
    start_x: Rc<Cell<Option<f32>>>,
    start_width: f32,
}

impl PanelResize {
    pub(crate) fn is_for(&self, panel: EntityId) -> bool {
        self.panel == panel
    }

    /// Width with the pointer at `x`. Dragging left grows the panel.
    ///
    /// `x` is a window pixel. The saved width is a designed pixel, the size
    /// at zoom 1, so the drag is divided by the current zoom.
    pub(crate) fn width_at(&self, x: f32) -> f32 {
        let start_x = match self.start_x.get() {
            Some(start) => start,
            None => {
                self.start_x.set(Some(x));
                x
            }
        };
        let delta = (x - start_x) / crate::ui::scale::factor();
        self.start_width - delta
    }
}

struct PanelResizeGhost;

impl Render for PanelResizeGhost {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div().size(px(0.))
    }
}

/// The band on the panel's left edge. It hugs that edge so the parent clip
/// does not eat the grab.
pub(crate) fn panel_resize_handle(panel: EntityId, start_width: f32) -> impl IntoElement {
    let drag = PanelResize {
        panel,
        start_x: Rc::new(Cell::new(None)),
        start_width,
    };
    resize_handle(
        SharedString::from(format!("server-panel-resize-{}", panel.as_u64())),
        Axis::Horizontal,
    )
    .inside(HandleEdge::Leading)
    .on_drag(drag, |drag, _, window, cx| {
        drag.start_x.set(Some(window.mouse_position().x.as_f32()));
        cx.stop_propagation();
        cx.new(|_| PanelResizeGhost)
    })
}

fn clamp_panel_width(width: f32, window_width: f32) -> f32 {
    // `window_width` is window pixels. The limits and `width` are designed
    // pixels, so the window is measured in the same unit as the panel.
    let window_width = window_width / crate::ui::scale::factor();
    let max = (window_width - PANEL_RESERVED).clamp(PANEL_MIN_WIDTH, PANEL_MAX_WIDTH);
    if !width.is_finite() {
        return PANEL_WIDTH;
    }
    width.round().clamp(PANEL_MIN_WIDTH, max)
}

/// `part` as a share of `whole`, 0 to 100.
fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 / whole as f64 * 100.0
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 || value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dragging_the_left_edge_left_widens_the_panel() {
        let drag = PanelResize {
            panel: EntityId::from(1),
            start_x: Rc::new(Cell::new(Some(500.))),
            start_width: 320.,
        };
        assert_eq!(drag.width_at(460.), 360.);
        assert_eq!(drag.width_at(540.), 280.);
    }

    #[test]
    fn panel_width_stays_between_the_shell_and_the_cap() {
        assert_eq!(clamp_panel_width(100., 1600.), PANEL_MIN_WIDTH);
        assert_eq!(clamp_panel_width(2000., 1600.), PANEL_MAX_WIDTH);
        assert_eq!(clamp_panel_width(400., 1600.), 400.);
        assert_eq!(clamp_panel_width(700., 1100.), 580.);
        assert_eq!(clamp_panel_width(400., 400.), PANEL_MIN_WIDTH);
        assert_eq!(clamp_panel_width(f32::NAN, 1600.), PANEL_WIDTH);
    }

    #[test]
    fn sizes_keep_three_figures_at_most() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(3_300_000_000), "3.1 GB");
        assert_eq!(format_bytes(150 * 1024 * 1024), "150 MB");
    }
}
