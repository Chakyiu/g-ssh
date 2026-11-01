//! A Telnet session on the same terminal emulator as an SSH shell.
//!
//! Telnet is one TCP connection per terminal, not a multiplexed session. The
//! bytes on the wire follow RFC 854: commands are marked with IAC, and the
//! options we answer are echo, suppress-go-ahead, terminal type and window size.

use std::time::Duration;

use async_channel::{Receiver, Sender};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::ssh::connection::ResolvedProxy;
use crate::ssh::shell::{
    apply_shell_cmd, subscribe_window_visible, ShellCmd, ShellCmdEffect, ShellEvent, ShellHandle,
    SNAPSHOT_INTERVAL,
};
use crate::ssh::terminal::TermEmulator;
use crate::ssh::AuthError;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;
const NOP: u8 = 241;
const AYT: u8 = 246;

const BINARY: u8 = 0;
const ECHO: u8 = 1;
const SGA: u8 = 3;
const TTYPE: u8 = 24;
const NAWS: u8 = 31;

const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;
const TERMINAL_TYPE: &[u8] = b"xterm-256color";

/// Where a Telnet session dials. The proxy is the same SOCKS5 or HTTP proxy an
/// SSH host would use.
#[derive(Clone)]
pub struct TelnetTarget {
    pub host: String,
    pub port: u16,
    pub proxy: Option<ResolvedProxy>,
}

/// What the session loop hears. A clean close is the remote ending the login,
/// which is not worth retrying on its own.
pub enum TelnetEvent {
    Connected,
    Failed(String),
    Closed { is_transient: bool },
}

enum TelnetCmd {
    OpenShell {
        rows: u16,
        cols: u16,
        reply: tokio::sync::oneshot::Sender<Result<ShellHandle, String>>,
    },
}

/// One Telnet dialler. Each [`TelnetConnection::open_shell`] is its own TCP
/// connection. The first one to end for a network reason ends this handle.
#[derive(Clone)]
pub struct TelnetConnection {
    cmd_tx: Sender<TelnetCmd>,
    event_rx: Receiver<TelnetEvent>,
}

impl TelnetConnection {
    pub fn spawn(target: TelnetTarget) -> Self {
        let (cmd_tx, cmd_rx) = async_channel::bounded(8);
        let (event_tx, event_rx) = async_channel::bounded(8);
        std::thread::Builder::new()
            .name("g-ssh-telnet".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, run_telnet(target, cmd_rx, event_tx));
            })
            .expect("spawn telnet thread");
        Self { cmd_tx, event_rx }
    }

    pub fn subscribe_events(&self) -> Receiver<TelnetEvent> {
        self.event_rx.clone()
    }

    pub async fn open_shell(&self, rows: u16, cols: u16) -> Result<ShellHandle, String> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.cmd_tx
            .send(TelnetCmd::OpenShell {
                rows,
                cols,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "connection closed".to_string())?;
        reply_rx
            .await
            .map_err(|_| "connection closed".to_string())?
    }
}

async fn dial(target: &TelnetTarget) -> Result<TcpStream, String> {
    let stream = crate::ssh::connect_tcp(&target.host, target.port, target.proxy.as_ref())
        .await
        .map_err(|error: AuthError| error.to_string())?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn run_telnet(
    target: TelnetTarget,
    cmd_rx: Receiver<TelnetCmd>,
    event_tx: Sender<TelnetEvent>,
) {
    let stream = match dial(&target).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(host = %target.host, port = target.port, error, "telnet connect failed");
            let _ = event_tx.send(TelnetEvent::Failed(error)).await;
            return;
        }
    };
    tracing::info!(host = %target.host, port = target.port, "telnet connected");
    let _ = event_tx.send(TelnetEvent::Connected).await;

    let (done_tx, done_rx) = async_channel::unbounded::<ShellDone>();
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let mut idle = Some(stream);
    let mut has_primary = false;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let Ok(TelnetCmd::OpenShell { rows, cols, reply }) = cmd else {
                    let _ = shutdown_tx.send(true);
                    break;
                };
                let is_primary = !has_primary;
                has_primary = true;
                let ready = idle.take();
                let target = target.clone();
                let done_tx = done_tx.clone();
                let shutdown = shutdown_tx.subscribe();
                tokio::task::spawn_local(async move {
                    let stream = match ready {
                        Some(stream) => stream,
                        None => match dial(&target).await {
                            Ok(stream) => stream,
                            Err(error) => {
                                let _ = reply.send(Err(error));
                                if is_primary {
                                    let _ = done_tx
                                        .send(ShellDone {
                                            is_primary,
                                            kind: EndKind::Lost,
                                        })
                                        .await;
                                }
                                return;
                            }
                        },
                    };
                    let (shell_cmd_tx, shell_cmd_rx) = async_channel::bounded(64);
                    let (shell_event_tx, shell_event_rx) = async_channel::bounded(64);
                    let _ = reply.send(Ok(ShellHandle::new(shell_cmd_tx, shell_event_rx)));
                    let kind = drive_shell(
                        stream,
                        rows,
                        cols,
                        is_primary,
                        shell_cmd_rx,
                        shell_event_tx,
                        shutdown,
                    )
                    .await;
                    let _ = done_tx.send(ShellDone { is_primary, kind }).await;
                });
            }
            done = done_rx.recv() => {
                let Ok(done) = done else { break };
                if done.is_primary && matches!(done.kind, EndKind::Clean | EndKind::Lost) {
                    let _ = shutdown_tx.send(true);
                    let _ = event_tx
                        .send(TelnetEvent::Closed {
                            is_transient: done.kind == EndKind::Lost,
                        })
                        .await;
                    break;
                }
            }
        }
    }
}

struct ShellDone {
    is_primary: bool,
    kind: EndKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndKind {
    Clean,
    Lost,
    Shutdown,
    Dropped,
}

async fn drive_shell(
    stream: TcpStream,
    rows: u16,
    cols: u16,
    is_primary: bool,
    cmd_rx: Receiver<ShellCmd>,
    event_tx: Sender<ShellEvent>,
    mut shutdown: watch::Receiver<bool>,
) -> EndKind {
    let mut machine = TelnetMachine::new(rows, cols);
    let (mut reader, mut writer) = stream.into_split();
    if writer.write_all(&machine.greeting()).await.is_err() {
        report_end(&event_tx, is_primary, EndKind::Lost).await;
        return EndKind::Lost;
    }

    let mut emulator = TermEmulator::new(rows.max(1), cols.max(1));
    let mut window_visibility = subscribe_window_visible();
    let mut is_snapshot_stale = false;
    let mut is_snapshot_due = false;
    let mut last_snapshot_at = Instant::now();
    let snapshot_timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(snapshot_timer);
    let mut buf = [0u8; 32 * 1024];

    let _ = event_tx
        .send(ShellEvent::Snapshot(emulator.snapshot()))
        .await;

    loop {
        tokio::select! {
            biased;

            Ok(()) = shutdown.changed() => {
                if *shutdown.borrow_and_update() {
                    report_end(&event_tx, is_primary, EndKind::Shutdown).await;
                    return EndKind::Shutdown;
                }
            }

            cmd = cmd_rx.recv() => {
                match cmd {
                    Ok(cmd) => {
                        if apply_command(&mut emulator, &mut machine, &mut writer, &event_tx, cmd).await.is_err() {
                            report_end(&event_tx, is_primary, EndKind::Lost).await;
                            return EndKind::Lost;
                        }
                    }
                    Err(_) => return EndKind::Dropped,
                }
            }

            read = reader.read(&mut buf) => {
                match read {
                    Ok(0) => {
                        let _ = event_tx.send(ShellEvent::Snapshot(emulator.snapshot())).await;
                        report_end(&event_tx, is_primary, EndKind::Clean).await;
                        return EndKind::Clean;
                    }
                    Ok(n) => {
                        if push_remote(&mut emulator, &mut machine, &mut writer, &buf[..n]).await.is_err() {
                            let _ = event_tx.send(ShellEvent::Error("send reply: connection closed".into())).await;
                            report_end(&event_tx, is_primary, EndKind::Lost).await;
                            return EndKind::Lost;
                        }
                        note_output(
                            &mut is_snapshot_stale,
                            &mut is_snapshot_due,
                            &mut last_snapshot_at,
                            &window_visibility,
                            &mut snapshot_timer,
                            &event_tx,
                            &emulator,
                        ).await;
                    }
                    Err(error) => {
                        tracing::debug!(%error, "telnet read ended");
                        report_end(&event_tx, is_primary, EndKind::Lost).await;
                        return EndKind::Lost;
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
        }
    }
}

/// The primary shell stays on screen when its socket ends; the session draws
/// the connection card over it. An extra shell's tab closes instead.
async fn report_end(event_tx: &Sender<ShellEvent>, is_primary: bool, kind: EndKind) {
    let event = match (is_primary, kind) {
        (_, EndKind::Shutdown) | (true, EndKind::Clean | EndKind::Lost) => {
            Some(ShellEvent::Disconnected)
        }
        (false, EndKind::Clean | EndKind::Lost) => Some(ShellEvent::Exited),
        (_, EndKind::Dropped) => None,
    };
    if let Some(event) = event {
        let _ = event_tx.send(event).await;
    }
}

async fn apply_command(
    emulator: &mut TermEmulator,
    machine: &mut TelnetMachine,
    writer: &mut OwnedWriteHalf,
    event_tx: &Sender<ShellEvent>,
    cmd: ShellCmd,
) -> Result<(), ()> {
    match apply_shell_cmd(emulator, cmd) {
        ShellCmdEffect::Write(data) => {
            let wire = machine.encode_input(&data);
            if writer.write_all(&wire).await.is_err() {
                let _ = event_tx
                    .send(ShellEvent::Error("send input: connection closed".into()))
                    .await;
                return Err(());
            }
            if machine.local_echo() {
                emulator.advance(&data);
                forward_replies(emulator, machine, writer).await?;
                let _ = event_tx
                    .send(ShellEvent::Snapshot(emulator.snapshot()))
                    .await;
            }
        }
        ShellCmdEffect::Resize { rows, cols } => {
            emulator.resize(rows, cols);
            let naws = machine.resize(rows, cols);
            if !naws.is_empty() && writer.write_all(&naws).await.is_err() {
                let _ = event_tx
                    .send(ShellEvent::Error("resize: connection closed".into()))
                    .await;
                return Err(());
            }
            let _ = event_tx
                .send(ShellEvent::Snapshot(emulator.snapshot()))
                .await;
        }
        ShellCmdEffect::Snapshot => {
            let _ = event_tx
                .send(ShellEvent::Snapshot(emulator.snapshot()))
                .await;
        }
        ShellCmdEffect::Quiet => {}
    }
    Ok(())
}

async fn push_remote(
    emulator: &mut TermEmulator,
    machine: &mut TelnetMachine,
    writer: &mut OwnedWriteHalf,
    bytes: &[u8],
) -> Result<(), ()> {
    let (text, wire) = machine.push(bytes);
    if !wire.is_empty() {
        writer.write_all(&wire).await.map_err(|_| ())?;
    }
    if text.is_empty() {
        return Ok(());
    }
    emulator.advance(&text);
    forward_replies(emulator, machine, writer).await
}

async fn forward_replies(
    emulator: &mut TermEmulator,
    machine: &mut TelnetMachine,
    writer: &mut OwnedWriteHalf,
) -> Result<(), ()> {
    let replies = emulator.take_replies();
    if replies.is_empty() {
        return Ok(());
    }
    writer
        .write_all(&machine.encode_input(&replies))
        .await
        .map_err(|_| ())
}

async fn note_output(
    is_snapshot_stale: &mut bool,
    is_snapshot_due: &mut bool,
    last_snapshot_at: &mut Instant,
    window_visibility: &watch::Receiver<bool>,
    snapshot_timer: &mut std::pin::Pin<&mut tokio::time::Sleep>,
    event_tx: &Sender<ShellEvent>,
    emulator: &TermEmulator,
) {
    if !*window_visibility.borrow() {
        *is_snapshot_stale = true;
    } else if last_snapshot_at.elapsed() >= SNAPSHOT_INTERVAL {
        *is_snapshot_due = false;
        *last_snapshot_at = Instant::now();
        let _ = event_tx
            .send(ShellEvent::Snapshot(emulator.snapshot()))
            .await;
    } else if !*is_snapshot_due {
        *is_snapshot_due = true;
        snapshot_timer
            .as_mut()
            .reset(*last_snapshot_at + SNAPSHOT_INTERVAL);
    }
}

/// Telnet option state for one direction of the connection.
struct TelnetMachine {
    mode: Mode,
    sub_option: u8,
    sub: Vec<u8>,
    /// Last DO or DONT we sent about the remote side doing an option.
    told_them: [u8; 256],
    /// Last WILL or WONT we sent about us doing an option.
    told_us: [u8; 256],
    them: [bool; 256],
    us: [bool; 256],
    rows: u16,
    cols: u16,
    binary: bool,
    saw_cr: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ground,
    Iac,
    Will,
    Wont,
    Do,
    Dont,
    Sb,
    SbBody,
    SbIac,
}

impl TelnetMachine {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            mode: Mode::Ground,
            sub_option: 0,
            sub: Vec::new(),
            told_them: [0; 256],
            told_us: [0; 256],
            // Assume the server echoes until it says it will not. Echoing
            // locally as well would show every key twice.
            them: {
                let mut them = [false; 256];
                them[ECHO as usize] = true;
                them
            },
            us: [false; 256],
            rows: rows.max(1),
            cols: cols.max(1),
            binary: false,
            saw_cr: false,
        }
    }

    /// Offer a character-at-a-time session and ask the server to echo.
    fn greeting(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(15);
        self.offer_us(&mut out, WILL, SGA);
        self.offer_them(&mut out, DO, SGA);
        self.offer_us(&mut out, WILL, TTYPE);
        self.offer_us(&mut out, WILL, NAWS);
        self.offer_them(&mut out, DO, ECHO);
        out
    }

    fn local_echo(&self) -> bool {
        !self.them[ECHO as usize]
    }

    fn resize(&mut self, rows: u16, cols: u16) -> Vec<u8> {
        self.rows = rows.max(1);
        self.cols = cols.max(1);
        if self.us[NAWS as usize] {
            self.naws()
        } else {
            Vec::new()
        }
    }

    /// Bytes for the terminal, and Telnet replies to write back.
    fn push(&mut self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut text = Vec::new();
        let mut wire = Vec::new();
        for &byte in input {
            self.byte(byte, &mut text, &mut wire);
        }
        (text, wire)
    }

    /// User keystrokes, with IAC escaped and CR written in Telnet form.
    fn encode_input(&self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 4);
        let mut index = 0;
        while index < data.len() {
            let byte = data[index];
            if byte == IAC {
                out.extend([IAC, IAC]);
                index += 1;
                continue;
            }
            if self.binary {
                out.push(byte);
                index += 1;
                continue;
            }
            if byte == b'\r' {
                out.push(b'\r');
                match data.get(index + 1).copied() {
                    Some(b'\n') => {
                        out.push(b'\n');
                        index += 2;
                    }
                    Some(0) => {
                        out.push(0);
                        index += 2;
                    }
                    _ => {
                        out.push(0);
                        index += 1;
                    }
                }
                continue;
            }
            if byte == b'\n' {
                out.extend([b'\r', b'\n']);
                index += 1;
                continue;
            }
            out.push(byte);
            index += 1;
        }
        out
    }

    fn byte(&mut self, byte: u8, text: &mut Vec<u8>, wire: &mut Vec<u8>) {
        match self.mode {
            Mode::Ground => {
                if byte == IAC {
                    self.mode = Mode::Iac;
                } else {
                    self.data_byte(byte, text);
                }
            }
            Mode::Iac => self.after_iac(byte, text, wire),
            Mode::Will => {
                self.mode = Mode::Ground;
                wire.extend(self.on_will(byte));
            }
            Mode::Wont => {
                self.mode = Mode::Ground;
                wire.extend(self.on_wont(byte));
            }
            Mode::Do => {
                self.mode = Mode::Ground;
                wire.extend(self.on_do(byte));
            }
            Mode::Dont => {
                self.mode = Mode::Ground;
                wire.extend(self.on_dont(byte));
            }
            Mode::Sb => {
                self.sub_option = byte;
                self.sub.clear();
                self.mode = Mode::SbBody;
            }
            Mode::SbBody => {
                if byte == IAC {
                    self.mode = Mode::SbIac;
                } else if self.sub.len() < 512 {
                    self.sub.push(byte);
                }
            }
            Mode::SbIac => {
                if byte == SE {
                    let option = self.sub_option;
                    let data = std::mem::take(&mut self.sub);
                    self.mode = Mode::Ground;
                    wire.extend(self.on_sub(option, &data));
                } else if byte == IAC {
                    if self.sub.len() < 512 {
                        self.sub.push(IAC);
                    }
                    self.mode = Mode::SbBody;
                } else {
                    self.sub.clear();
                    self.mode = Mode::Ground;
                }
            }
        }
    }

    fn after_iac(&mut self, byte: u8, text: &mut Vec<u8>, wire: &mut Vec<u8>) {
        self.mode = match byte {
            IAC => {
                self.data_byte(IAC, text);
                Mode::Ground
            }
            WILL => Mode::Will,
            WONT => Mode::Wont,
            DO => Mode::Do,
            DONT => Mode::Dont,
            SB => Mode::Sb,
            AYT => {
                wire.extend([IAC, NOP]);
                Mode::Ground
            }
            _ => Mode::Ground,
        };
    }

    fn data_byte(&mut self, byte: u8, text: &mut Vec<u8>) {
        if self.binary {
            text.push(byte);
            return;
        }
        if self.saw_cr {
            self.saw_cr = false;
            if byte == 0 {
                text.push(b'\r');
            } else if byte == b'\n' {
                text.extend([b'\r', b'\n']);
            } else {
                text.push(b'\r');
                text.push(byte);
            }
            return;
        }
        if byte == b'\r' {
            self.saw_cr = true;
            return;
        }
        text.push(byte);
    }

    fn on_will(&mut self, option: u8) -> Vec<u8> {
        let accept = matches!(option, ECHO | SGA | BINARY);
        self.them[option as usize] = accept;
        self.note_binary();
        self.reply_them(option, if accept { DO } else { DONT })
    }

    fn on_wont(&mut self, option: u8) -> Vec<u8> {
        self.them[option as usize] = false;
        self.note_binary();
        self.reply_them(option, DONT)
    }

    fn on_do(&mut self, option: u8) -> Vec<u8> {
        let accept = matches!(option, SGA | TTYPE | NAWS | BINARY);
        let became = accept && !self.us[option as usize];
        self.us[option as usize] = accept;
        self.note_binary();
        let mut out = self.reply_us(option, if accept { WILL } else { WONT });
        if option == NAWS && became {
            out.extend(self.naws());
        }
        out
    }

    fn on_dont(&mut self, option: u8) -> Vec<u8> {
        self.us[option as usize] = false;
        self.note_binary();
        self.reply_us(option, WONT)
    }

    fn on_sub(&mut self, option: u8, data: &[u8]) -> Vec<u8> {
        if option == TTYPE && data.first() == Some(&TTYPE_SEND) && self.us[TTYPE as usize] {
            let mut out = vec![IAC, SB, TTYPE, TTYPE_IS];
            out.extend(TERMINAL_TYPE);
            out.extend([IAC, SE]);
            return out;
        }
        Vec::new()
    }

    fn reply_them(&mut self, option: u8, command: u8) -> Vec<u8> {
        if self.told_them[option as usize] == command {
            return Vec::new();
        }
        self.told_them[option as usize] = command;
        vec![IAC, command, option]
    }

    fn reply_us(&mut self, option: u8, command: u8) -> Vec<u8> {
        if self.told_us[option as usize] == command {
            return Vec::new();
        }
        self.told_us[option as usize] = command;
        vec![IAC, command, option]
    }

    fn offer_us(&mut self, out: &mut Vec<u8>, command: u8, option: u8) {
        self.told_us[option as usize] = command;
        out.extend([IAC, command, option]);
    }

    fn offer_them(&mut self, out: &mut Vec<u8>, command: u8, option: u8) {
        self.told_them[option as usize] = command;
        out.extend([IAC, command, option]);
    }

    fn note_binary(&mut self) {
        self.binary = self.us[BINARY as usize] && self.them[BINARY as usize];
    }

    fn naws(&self) -> Vec<u8> {
        let mut out = vec![IAC, SB, NAWS];
        push_doubled(&mut out, (self.cols >> 8) as u8);
        push_doubled(&mut out, self.cols as u8);
        push_doubled(&mut out, (self.rows >> 8) as u8);
        push_doubled(&mut out, self.rows as u8);
        out.extend([IAC, SE]);
        out
    }
}

fn push_doubled(out: &mut Vec<u8>, byte: u8) {
    out.push(byte);
    if byte == IAC {
        out.push(IAC);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> TelnetMachine {
        let mut machine = TelnetMachine::new(24, 80);
        let _ = machine.greeting();
        machine
    }

    #[test]
    fn plain_text_and_a_doubled_iac_reach_the_terminal() {
        let mut machine = machine();
        let (text, wire) = machine.push(b"login: \xff\xff");
        assert_eq!(text, b"login: \xff");
        assert!(wire.is_empty());
    }

    #[test]
    fn a_cr_nul_is_one_carriage_return() {
        let mut machine = machine();
        let (text, _) = machine.push(b"a\r\0b\r\n");
        assert_eq!(text, b"a\rb\r\n");
    }

    #[test]
    fn will_echo_is_not_answered_twice() {
        let mut machine = machine();
        let (_, wire) = machine.push(&[IAC, WILL, ECHO]);
        assert!(wire.is_empty(), "{wire:?}");
        assert!(!machine.local_echo());
    }

    #[test]
    fn wont_echo_turns_on_local_echo_once() {
        let mut machine = machine();
        assert!(!machine.local_echo());
        let (_, wire) = machine.push(&[IAC, WONT, ECHO]);
        assert_eq!(wire, vec![IAC, DONT, ECHO]);
        assert!(machine.local_echo());
        let (_, again) = machine.push(&[IAC, WONT, ECHO]);
        assert!(again.is_empty());
    }

    #[test]
    fn an_unknown_option_is_refused_once() {
        let mut machine = machine();
        let (_, wire) = machine.push(&[IAC, DO, 99]);
        assert_eq!(wire, vec![IAC, WONT, 99]);
        let (_, again) = machine.push(&[IAC, DONT, 99]);
        assert!(again.is_empty(), "{again:?}");
    }

    #[test]
    fn terminal_type_and_window_size_are_answered() {
        let mut machine = machine();
        let (_, wire) = machine.push(&[
            IAC, DO, TTYPE, IAC, SB, TTYPE, TTYPE_SEND, IAC, SE, IAC, DO, NAWS,
        ]);
        assert!(
            wire.windows(TERMINAL_TYPE.len())
                .any(|window| window == TERMINAL_TYPE),
            "{wire:?}"
        );
        assert!(
            wire.windows(6)
                .any(|window| window == [0, 80, 0, 24, IAC, SE]),
            "{wire:?}"
        );
    }

    #[test]
    fn a_255_wide_window_doubles_iac_in_naws() {
        let mut machine = machine();
        machine.resize(24, 255);
        let (_, wire) = machine.push(&[IAC, DO, NAWS]);
        assert_eq!(wire, vec![IAC, SB, NAWS, 0, IAC, IAC, 0, 24, IAC, SE]);
    }

    #[test]
    fn keystrokes_escape_iac_and_map_enter() {
        let machine = machine();
        assert_eq!(machine.encode_input(b"a\r"), b"a\r\0");
        assert_eq!(machine.encode_input(b"a\n"), b"a\r\n");
        assert_eq!(machine.encode_input(&[b'x', IAC]), [b'x', IAC, IAC]);
    }
}
