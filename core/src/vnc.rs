//! A VNC session on the remote framebuffer protocol (RFB 3.3 to 3.8).
//!
//! One TCP connection carries the desktop, dialled directly or through the
//! vault's proxy. Every rectangle the server sends is decoded into one
//! framebuffer here, and each finished update goes to the view as a whole
//! frame. Keys go back as X11 keysyms and the pointer as a button mask.

mod auth;
mod clipboard;
mod decode;
mod handshake;
mod message;

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::desktop::{DesktopFrame, PointerButton};
use crate::ssh::connection::ResolvedProxy;
use clipboard::ClipboardState;
use decode::{Decoders, Framebuffer, Layout, Screen};

/// Signing in waits on the server, and a Mac may first ask its user.
const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(60);

/// A server that signed in but never sends a picture is not coming back.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// Updates are asked for at most this often, so a busy screen is not copied
/// out for the view more than about sixty times a second.
const UPDATE_INTERVAL: Duration = Duration::from_millis(16);

/// Wheel notches one scroll event may send.
const MAX_WHEEL_STEPS: u16 = 10;

const READ_BUFFER: usize = 64 * 1024;

const BUTTON_LEFT: u8 = 1;
const BUTTON_MIDDLE: u8 = 1 << 1;
const BUTTON_RIGHT: u8 = 1 << 2;
const WHEEL_UP: u8 = 1 << 3;
const WHEEL_DOWN: u8 = 1 << 4;
const WHEEL_LEFT: u8 = 1 << 5;
const WHEEL_RIGHT: u8 = 1 << 6;

/// How a VNC host's picture and input behave. Saved with the host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VncSettings {
    #[serde(default)]
    pub quality: VncQuality,
    /// Ask the server to resize its desktop to the tab. A server that cannot
    /// keeps its size, and the picture is scaled to fit instead.
    #[serde(default)]
    pub resize_remote: bool,
    /// Watch only. No keys, pointer or clipboard go to the server, and the
    /// server draws its own pointer into the picture.
    #[serde(default)]
    pub view_only: bool,
    /// Share text copied on either side.
    #[serde(default)]
    pub clipboard: bool,
}

impl VncSettings {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// How the server may compress the picture. Only servers with the Tight
/// encoding send JPEG; the others are lossless whatever this says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VncQuality {
    /// Every pixel exact, for a fast network.
    Lossless,
    /// Photos and video as JPEG at high quality.
    #[default]
    High,
    /// Stronger JPEG and zlib compression, for a slow link.
    Low,
}

/// Where a VNC session dials, and how it signs in.
pub struct VncTarget {
    pub host: String,
    pub port: u16,
    pub proxy: Option<ResolvedProxy>,
    /// Only a Mac's own sign-in uses it. A VNC password has no user.
    pub username: String,
    /// Empty for a server without a password.
    pub password: Zeroizing<String>,
    pub settings: VncSettings,
}

/// What the session loop hears. Frames travel on
/// [`VncConnection::subscribe_frames`].
pub enum VncEvent {
    /// The first picture is up. Later ones stay on the watch.
    Connected {
        width: u16,
        height: u16,
        name: String,
    },
    Failed(VncFailure),
    /// Text copied on the remote, for the local clipboard.
    RemoteClipboard(String),
    Closed {
        message: String,
        is_transient: bool,
    },
}

/// Why a connect never showed a picture. The message is written for the user.
#[derive(Debug)]
pub struct VncFailure {
    pub message: String,
    /// The server turned the password or the account down. Another
    /// password may get in.
    pub is_auth: bool,
    /// The network rather than the server's answer. Another try may help.
    pub is_transient: bool,
}

/// One thing to send. Coordinates are framebuffer pixels.
#[derive(Clone, Debug)]
pub enum VncInput {
    Move {
        x: u16,
        y: u16,
    },
    Button {
        x: u16,
        y: u16,
        button: PointerButton,
        pressed: bool,
    },
    /// Whole wheel notches. Positive steps scroll toward the top, or toward
    /// the left when horizontal.
    Wheel {
        x: u16,
        y: u16,
        steps: i16,
        horizontal: bool,
    },
    /// An X11 keysym going down or up.
    Key {
        keysym: u32,
        pressed: bool,
    },
    /// Ask for a desktop this size. Dropped unless the server can resize.
    Resize {
        width: u16,
        height: u16,
    },
}

enum Command {
    Inputs(Vec<VncInput>),
    Clipboard(String),
}

/// Set on the session thread, read by the view.
#[derive(Default)]
struct LinkFlags {
    /// The server can change its desktop size and has not refused to.
    can_resize: AtomicBool,
}

/// One live desktop. Cloning shares the session; dropping the last clone
/// ends it.
#[derive(Clone)]
pub struct VncConnection {
    commands: mpsc::UnboundedSender<Command>,
    event_rx: async_channel::Receiver<VncEvent>,
    frame_rx: watch::Receiver<Option<DesktopFrame>>,
    flags: Arc<LinkFlags>,
    settings: VncSettings,
}

impl VncConnection {
    pub fn spawn(target: VncTarget) -> Self {
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = async_channel::bounded(8);
        let (frame_tx, frame_rx) = watch::channel(None);
        let flags = Arc::new(LinkFlags::default());
        let settings = target.settings;
        let thread_flags = flags.clone();
        std::thread::Builder::new()
            .name("g-ssh-vnc".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                runtime.block_on(run(target, command_rx, event_tx, frame_tx, thread_flags));
            })
            .expect("spawn vnc thread");
        Self {
            commands,
            event_rx,
            frame_rx,
            flags,
            settings,
        }
    }

    pub fn subscribe_events(&self) -> async_channel::Receiver<VncEvent> {
        self.event_rx.clone()
    }

    pub fn subscribe_frames(&self) -> watch::Receiver<Option<DesktopFrame>> {
        self.frame_rx.clone()
    }

    /// False for a host that only watches.
    pub fn accepts_input(&self) -> bool {
        !self.settings.view_only
    }

    /// Whether local copies go to the remote.
    pub fn shares_clipboard(&self) -> bool {
        self.settings.clipboard && !self.settings.view_only
    }

    /// The desktop follows the tab: the host asks for it, and the server
    /// has said it can.
    pub fn resizes_remote(&self) -> bool {
        self.settings.resize_remote && self.flags.can_resize.load(Ordering::Relaxed)
    }

    /// Best effort. A session that has ended, or one that only watches,
    /// drops the input.
    pub fn send(&self, inputs: &[VncInput]) {
        if inputs.is_empty() || !self.accepts_input() {
            return;
        }
        let _ = self.commands.send(Command::Inputs(inputs.to_vec()));
    }

    /// Put local text on the remote clipboard. Text the remote already has
    /// is skipped, so this is cheap to call whenever the view is touched.
    pub fn offer_clipboard(&self, text: String) {
        if self.shares_clipboard() {
            let _ = self.commands.send(Command::Clipboard(text));
        }
    }
}

/// Why a session ended. The text is shown to the user as it is.
#[derive(Debug, thiserror::Error)]
enum VncError {
    /// Dialling, reading or writing. Another try may get through.
    #[error("{0}")]
    Network(String),
    /// The server turned the password or the account down.
    #[error("{0}")]
    Auth(String),
    /// The server refused, or sent something this client cannot use.
    /// Another try would end the same way.
    #[error("{0}")]
    Protocol(String),
}

impl From<std::io::Error> for VncError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            return Self::Network("The server closed the connection.".to_string());
        }
        Self::Network(sentence(&error.to_string()))
    }
}

impl VncError {
    fn is_transient(&self) -> bool {
        matches!(self, Self::Network(_))
    }

    fn into_failure(self) -> VncFailure {
        let is_auth = matches!(self, Self::Auth(_));
        let is_transient = self.is_transient();
        VncFailure {
            message: self.to_string(),
            is_auth,
            is_transient,
        }
    }
}

/// First letter up, the way the error card shows a message.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

struct Link {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    init: handshake::ServerInit,
}

/// What the reading and the writing half both need. They run on one task,
/// so plain cells do: neither holds a borrow across an await.
#[derive(Default)]
struct Shared {
    /// The server's screens, once it has said it can resize.
    screens: RefCell<Option<Vec<Screen>>>,
    /// The server turned a resize down, so the picture is scaled from now on.
    resize_refused: Cell<bool>,
    clipboard: RefCell<ClipboardState>,
}

enum Outgoing {
    /// Ask for the next update, no sooner than [`UPDATE_INTERVAL`] after
    /// the last ask.
    Update {
        incremental: bool,
        width: u16,
        height: u16,
    },
    /// An encoded message, sent as it is.
    Bytes(Vec<u8>),
}

async fn run(
    target: VncTarget,
    mut commands: mpsc::UnboundedReceiver<Command>,
    event_tx: async_channel::Sender<VncEvent>,
    frame_tx: watch::Sender<Option<DesktopFrame>>,
    flags: Arc<LinkFlags>,
) {
    let host = target.host.clone();
    let port = target.port;
    let link = match sign_in(&target).await {
        Ok(link) => link,
        Err(error) => {
            let failure = error.into_failure();
            tracing::warn!(host = %host, port, error = %failure.message, "vnc connect failed");
            let _ = event_tx.send(VncEvent::Failed(failure)).await;
            return;
        }
    };
    tracing::info!(
        host = %host,
        port,
        width = link.init.width,
        height = link.init.height,
        name = %link.init.name,
        security = link.init.security,
        "vnc signed in"
    );
    let shown = Cell::new(false);
    let ended = serve(
        link,
        target.settings,
        &mut commands,
        &event_tx,
        &frame_tx,
        &flags,
        &shown,
    )
    .await;
    let Err(error) = ended else {
        tracing::info!(host = %host, port, "vnc session closed");
        return;
    };
    if shown.get() {
        let is_transient = error.is_transient();
        let message = error.to_string();
        tracing::warn!(host = %host, port, error = %message, "vnc session ended");
        let _ = event_tx
            .send(VncEvent::Closed {
                message,
                is_transient,
            })
            .await;
    } else {
        let failure = error.into_failure();
        tracing::warn!(host = %host, port, error = %failure.message, "vnc connect failed");
        let _ = event_tx.send(VncEvent::Failed(failure)).await;
    }
}

async fn sign_in(target: &VncTarget) -> Result<Link, VncError> {
    let stream = crate::ssh::connect_tcp(&target.host, target.port, target.proxy.as_ref())
        .await
        .map_err(|error| VncError::Network(sentence(&error.to_string())))?;
    let _ = stream.set_nodelay(true);
    keep_alive(&stream);
    let (read, mut writer) = stream.into_split();
    let mut reader = BufReader::with_capacity(READ_BUFFER, read);
    let init = tokio::time::timeout(
        SIGN_IN_TIMEOUT,
        handshake::sign_in(&mut reader, &mut writer, &target.username, &target.password),
    )
    .await
    .map_err(|_| {
        VncError::Network(format!(
            "The server did not finish signing in within {}s.",
            SIGN_IN_TIMEOUT.as_secs()
        ))
    })??;
    Ok(Link {
        reader,
        writer,
        init,
    })
}

/// VNC has no keepalive of its own. Without TCP's, a link that died quietly
/// (a laptop asleep, a dropped Wi-Fi) leaves the picture frozen until the
/// system gives up hours later.
fn keep_alive(stream: &tokio::net::TcpStream) {
    let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let keepalive = keepalive.with_interval(Duration::from_secs(10));
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

async fn serve(
    link: Link,
    settings: VncSettings,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    event_tx: &async_channel::Sender<VncEvent>,
    frame_tx: &watch::Sender<Option<DesktopFrame>>,
    flags: &LinkFlags,
    shown: &Cell<bool>,
) -> Result<(), VncError> {
    let Link {
        mut reader,
        mut writer,
        init,
    } = link;
    let mut framebuffer = Framebuffer::new(init.width, init.height)?;
    let mut setup = Vec::new();
    message::set_pixel_format(&mut setup);
    message::set_encodings(&mut setup, &encodings(settings));
    message::update_request(&mut setup, false, init.width, init.height);
    writer.write_all(&setup).await?;

    let shared = Shared::default();
    let (out_tx, out_rx) = mpsc::unbounded_channel();
    let reading = read_loop(
        &mut reader,
        &mut framebuffer,
        &shared,
        &out_tx,
        event_tx,
        frame_tx,
        flags,
        settings,
        shown,
        &init.name,
    );
    let writing = write_loop(&mut writer, commands, out_rx, &shared, flags);
    let first_frame = async {
        tokio::time::sleep(FIRST_FRAME_TIMEOUT).await;
        if shown.get() {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        result = reading => result,
        result = writing => result,
        () = first_frame => Err(VncError::Network(format!(
            "The server sent no picture within {}s.",
            FIRST_FRAME_TIMEOUT.as_secs()
        ))),
    }
}

/// In order of preference. CopyRect leads: a server uses it wherever
/// something only moved, whatever else it prefers.
fn encodings(settings: VncSettings) -> Vec<i32> {
    use decode::{
        compress_level, jpeg_quality, COPY_RECT, CURSOR, DESKTOP_SIZE, EXTENDED_DESKTOP_SIZE,
        HEXTILE, LAST_RECT, RAW, TIGHT, ZLIB, ZRLE,
    };
    let mut list = vec![COPY_RECT];
    match settings.quality {
        VncQuality::Lossless => list.extend([ZRLE, TIGHT, HEXTILE, ZLIB]),
        VncQuality::High | VncQuality::Low => list.extend([TIGHT, ZRLE, HEXTILE, ZLIB]),
    }
    list.push(RAW);
    match settings.quality {
        // Without a quality level, Tight never sends JPEG.
        VncQuality::Lossless => {}
        VncQuality::High => list.push(jpeg_quality(8)),
        VncQuality::Low => list.extend([jpeg_quality(4), compress_level(6)]),
    }
    list.extend([DESKTOP_SIZE, EXTENDED_DESKTOP_SIZE, LAST_RECT]);
    // With the cursor shape on its own, the server leaves the pointer out of
    // the picture and the local one is the only one. A viewer that only
    // watches wants to see where the remote pointer is.
    if !settings.view_only {
        list.push(CURSOR);
    }
    if settings.clipboard {
        list.push(clipboard::EXTENDED_CLIPBOARD);
    }
    list
}

async fn read_loop<R: AsyncRead + Unpin>(
    reader: &mut R,
    framebuffer: &mut Framebuffer,
    shared: &Shared,
    out_tx: &mpsc::UnboundedSender<Outgoing>,
    event_tx: &async_channel::Sender<VncEvent>,
    frame_tx: &watch::Sender<Option<DesktopFrame>>,
    flags: &LinkFlags,
    settings: VncSettings,
    shown: &Cell<bool>,
    name: &str,
) -> Result<(), VncError> {
    let mut decoders = Decoders::default();
    loop {
        match reader.read_u8().await? {
            message::FRAMEBUFFER_UPDATE => {
                let news = decode::update(reader, framebuffer, &mut decoders).await?;
                if let Some(layout) = news.layout {
                    note_layout(layout, shared, flags, settings);
                }
                let _ = out_tx.send(Outgoing::Update {
                    incremental: !news.resized,
                    width: framebuffer.width(),
                    height: framebuffer.height(),
                });
                frame_tx.send_replace(Some(framebuffer.frame()));
                if !shown.replace(true) {
                    let _ = event_tx
                        .send(VncEvent::Connected {
                            width: framebuffer.width(),
                            height: framebuffer.height(),
                            name: name.to_string(),
                        })
                        .await;
                }
            }
            message::SET_COLOUR_MAP_ENTRIES => {
                // Only for a palette format, which this client never asks for.
                let mut header = [0u8; 5];
                reader.read_exact(&mut header).await?;
                let count = u16::from_be_bytes([header[3], header[4]]);
                decode::skip(reader, usize::from(count) * 6).await?;
            }
            message::BELL => {}
            message::SERVER_CUT_TEXT => {
                let mut padding = [0u8; 3];
                reader.read_exact(&mut padding).await?;
                let length = reader.read_i32().await?;
                let size = length.unsigned_abs() as usize;
                if size > clipboard::MAX_TEXT {
                    decode::skip(reader, size).await?;
                    continue;
                }
                let mut payload = vec![0u8; size];
                reader.read_exact(&mut payload).await?;
                if !settings.clipboard {
                    continue;
                }
                let (text, reply) = shared.clipboard.borrow_mut().receive(length, &payload)?;
                if let Some(reply) = reply {
                    let _ = out_tx.send(Outgoing::Bytes(reply));
                }
                if let Some(text) = text {
                    let _ = event_tx.send(VncEvent::RemoteClipboard(text)).await;
                }
            }
            other => {
                return Err(VncError::Protocol(format!(
                    "The server sent message type {other}, which this client does not know."
                )))
            }
        }
    }
}

fn note_layout(layout: Layout, shared: &Shared, flags: &LinkFlags, settings: VncSettings) {
    if layout.is_refusal() {
        tracing::info!(status = layout.status, "vnc server kept its desktop size");
        shared.resize_refused.set(true);
        flags.can_resize.store(false, Ordering::Relaxed);
        return;
    }
    shared.screens.replace(Some(layout.screens));
    if settings.resize_remote && !shared.resize_refused.get() {
        flags.can_resize.store(true, Ordering::Relaxed);
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(
    writer: &mut W,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    mut outgoing: mpsc::UnboundedReceiver<Outgoing>,
    shared: &Shared,
    flags: &LinkFlags,
) -> Result<(), VncError> {
    let mut buttons = 0u8;
    let mut last_update: Option<Instant> = None;
    let mut pending: Option<(bool, u16, u16)> = None;
    let timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(timer);
    let mut buf = Vec::with_capacity(512);
    loop {
        buf.clear();
        tokio::select! {
            command = commands.recv() => match command {
                None => return Ok(()),
                Some(Command::Inputs(inputs)) => {
                    encode_inputs(&mut buf, &inputs, &mut buttons, shared, flags);
                }
                Some(Command::Clipboard(text)) => {
                    if let Some(message) = shared.clipboard.borrow_mut().offer(text) {
                        buf.extend_from_slice(&message);
                    }
                }
            },
            out = outgoing.recv() => match out {
                None => return Ok(()),
                Some(Outgoing::Bytes(bytes)) => buf.extend_from_slice(&bytes),
                Some(Outgoing::Update { incremental, width, height }) => {
                    let incremental = incremental && pending.is_none_or(|(was, _, _)| was);
                    let due = last_update.map_or_else(Instant::now, |at| at + UPDATE_INTERVAL);
                    if Instant::now() >= due {
                        message::update_request(&mut buf, incremental, width, height);
                        last_update = Some(Instant::now());
                        pending = None;
                    } else {
                        pending = Some((incremental, width, height));
                        timer.as_mut().reset(due);
                    }
                }
            },
            () = &mut timer, if pending.is_some() => {
                if let Some((incremental, width, height)) = pending.take() {
                    message::update_request(&mut buf, incremental, width, height);
                    last_update = Some(Instant::now());
                }
            }
        }
        if !buf.is_empty() {
            writer.write_all(&buf).await?;
        }
    }
}

fn encode_inputs(
    buf: &mut Vec<u8>,
    inputs: &[VncInput],
    buttons: &mut u8,
    shared: &Shared,
    flags: &LinkFlags,
) {
    for input in inputs {
        match *input {
            VncInput::Move { x, y } => message::pointer(buf, *buttons, x, y),
            VncInput::Button {
                x,
                y,
                button,
                pressed,
            } => {
                let bit = match button {
                    PointerButton::Left => BUTTON_LEFT,
                    PointerButton::Middle => BUTTON_MIDDLE,
                    PointerButton::Right => BUTTON_RIGHT,
                };
                if pressed {
                    *buttons |= bit;
                } else {
                    *buttons &= !bit;
                }
                message::pointer(buf, *buttons, x, y);
            }
            // A notch is the wheel button pressed and let go.
            VncInput::Wheel {
                x,
                y,
                steps,
                horizontal,
            } => {
                let bit = match (horizontal, steps > 0) {
                    (false, true) => WHEEL_UP,
                    (false, false) => WHEEL_DOWN,
                    (true, true) => WHEEL_LEFT,
                    (true, false) => WHEEL_RIGHT,
                };
                for _ in 0..steps.unsigned_abs().min(MAX_WHEEL_STEPS) {
                    message::pointer(buf, *buttons | bit, x, y);
                    message::pointer(buf, *buttons, x, y);
                }
            }
            VncInput::Key { keysym, pressed } => message::key(buf, pressed, keysym),
            VncInput::Resize { width, height } => {
                if !flags.can_resize.load(Ordering::Relaxed) {
                    continue;
                }
                if let Some(screens) = shared.screens.borrow().as_deref() {
                    message::set_desktop_size(buf, width, height, screens);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    async fn listen() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    fn connect(port: u16, password: &str, settings: VncSettings) -> VncConnection {
        VncConnection::spawn(VncTarget {
            host: "127.0.0.1".to_string(),
            port,
            proxy: None,
            username: String::new(),
            password: Zeroizing::new(password.to_string()),
            settings,
        })
    }

    async fn read(stream: &mut TcpStream, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        timeout(WAIT, stream.read_exact(&mut bytes))
            .await
            .expect("client went quiet")
            .unwrap();
        bytes
    }

    /// One client message, whole, by its type.
    async fn client_message(stream: &mut TcpStream) -> Vec<u8> {
        let mut bytes = read(stream, 1).await;
        let rest = match bytes[0] {
            0 => 19,
            3 => 9,
            4 => 7,
            5 => 5,
            2 => {
                let head = read(stream, 3).await;
                let count = usize::from(u16::from_be_bytes([head[1], head[2]]));
                bytes.extend_from_slice(&head);
                count * 4
            }
            6 => {
                let head = read(stream, 7).await;
                let length = i32::from_be_bytes([head[3], head[4], head[5], head[6]]);
                bytes.extend_from_slice(&head);
                length.unsigned_abs() as usize
            }
            251 => {
                let head = read(stream, 7).await;
                let screens = usize::from(head[5]);
                bytes.extend_from_slice(&head);
                screens * 16
            }
            other => panic!("unexpected client message {other}"),
        };
        bytes.extend_from_slice(&read(stream, rest).await);
        bytes
    }

    /// The next client message that is not an update request.
    async fn input_message(stream: &mut TcpStream) -> Vec<u8> {
        loop {
            let message = client_message(stream).await;
            if message[0] != 3 {
                return message;
            }
        }
    }

    /// RFB 3.8 with a VNC password, then a 4 × 2 desktop. Returns the
    /// client's SetEncodings list.
    async fn sign_in(stream: &mut TcpStream, password: &str) -> Vec<i32> {
        stream.write_all(b"RFB 003.008\n").await.unwrap();
        assert_eq!(read(stream, 12).await, b"RFB 003.008\n");
        stream.write_all(&[1, 2]).await.unwrap();
        assert_eq!(read(stream, 1).await, [2]);
        let challenge = [9u8; 16];
        stream.write_all(&challenge).await.unwrap();
        assert_eq!(
            read(stream, 16).await,
            auth::vnc_response(password, &challenge)
        );
        stream.write_all(&0u32.to_be_bytes()).await.unwrap();
        assert_eq!(read(stream, 1).await, [1], "shared flag");

        let mut init = Vec::new();
        init.extend_from_slice(&4u16.to_be_bytes());
        init.extend_from_slice(&2u16.to_be_bytes());
        init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        init.extend_from_slice(&4u32.to_be_bytes());
        init.extend_from_slice(b"desk");
        stream.write_all(&init).await.unwrap();

        let pixel_format = client_message(stream).await;
        assert_eq!(pixel_format[0], 0);
        let encodings = client_message(stream).await;
        assert_eq!(encodings[0], 2);
        let request = client_message(stream).await;
        assert_eq!(
            request,
            [3, 0, 0, 0, 0, 0, 0, 4, 0, 2],
            "a full first request"
        );
        encodings[4..]
            .chunks_exact(4)
            .map(|bytes| i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            .collect()
    }

    /// A whole-desktop raw update, with optional rectangles before it.
    fn update(colour: [u8; 4], before: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0, 0];
        bytes.extend_from_slice(&(before.len() as u16 + 1).to_be_bytes());
        for rect in before {
            bytes.extend_from_slice(rect);
        }
        for value in [0u16, 0, 4, 2] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&decode::RAW.to_be_bytes());
        for _ in 0..8 {
            bytes.extend_from_slice(&colour);
        }
        bytes
    }

    async fn next_event(events: &async_channel::Receiver<VncEvent>) -> VncEvent {
        timeout(WAIT, events.recv())
            .await
            .expect("no event")
            .expect("events closed")
    }

    #[tokio::test]
    async fn signs_in_shows_the_desktop_and_sends_input() {
        let (listener, port) = listen().await;
        let conn = connect(port, "s3cret", VncSettings::default());
        let events = conn.subscribe_events();
        let (mut stream, _) = listener.accept().await.unwrap();
        let encodings = sign_in(&mut stream, "s3cret").await;
        assert!(encodings.contains(&decode::TIGHT));
        assert!(encodings.contains(&decode::CURSOR));
        assert!(!encodings.contains(&clipboard::EXTENDED_CLIPBOARD));

        stream
            .write_all(&update([10, 20, 30, 0], &[]))
            .await
            .unwrap();
        let VncEvent::Connected {
            width,
            height,
            name,
        } = next_event(&events).await
        else {
            panic!("expected Connected");
        };
        assert_eq!((width, height, name.as_str()), (4, 2, "desk"));
        let frame = conn.subscribe_frames().borrow().clone().unwrap();
        assert_eq!((frame.width, frame.height), (4, 2));
        assert_eq!(&frame.bgra[..4], &[10, 20, 30, 255]);

        conn.send(&[
            VncInput::Key {
                keysym: 0x61,
                pressed: true,
            },
            VncInput::Button {
                x: 1,
                y: 1,
                button: PointerButton::Left,
                pressed: true,
            },
            VncInput::Wheel {
                x: 1,
                y: 1,
                steps: -1,
                horizontal: false,
            },
        ]);
        assert_eq!(
            input_message(&mut stream).await,
            [4, 1, 0, 0, 0, 0, 0, 0x61]
        );
        assert_eq!(input_message(&mut stream).await, [5, 1, 0, 1, 0, 1]);
        assert_eq!(
            input_message(&mut stream).await,
            [5, 1 | WHEEL_DOWN, 0, 1, 0, 1]
        );
        assert_eq!(input_message(&mut stream).await, [5, 1, 0, 1, 0, 1]);

        drop(stream);
        let VncEvent::Closed { is_transient, .. } = next_event(&events).await else {
            panic!("expected Closed");
        };
        assert!(is_transient);
    }

    #[tokio::test]
    async fn a_wrong_password_is_an_auth_failure_with_the_servers_reason() {
        let (listener, port) = listen().await;
        let conn = connect(port, "wrong", VncSettings::default());
        let events = conn.subscribe_events();
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"RFB 003.008\n").await.unwrap();
        read(&mut stream, 12).await;
        stream.write_all(&[1, 2]).await.unwrap();
        read(&mut stream, 1).await;
        stream.write_all(&[0u8; 16]).await.unwrap();
        read(&mut stream, 16).await;
        let reason = b"authentication failure";
        stream.write_all(&1u32.to_be_bytes()).await.unwrap();
        stream
            .write_all(&(reason.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(reason).await.unwrap();

        let VncEvent::Failed(failure) = next_event(&events).await else {
            panic!("expected Failed");
        };
        assert!(failure.is_auth);
        assert!(!failure.is_transient);
        assert_eq!(failure.message, "Authentication failure");
    }

    #[tokio::test]
    async fn no_password_for_a_server_that_needs_one_asks_for_it() {
        let (listener, port) = listen().await;
        let conn = connect(port, "", VncSettings::default());
        let events = conn.subscribe_events();
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"RFB 003.008\n").await.unwrap();
        read(&mut stream, 12).await;
        stream.write_all(&[1, 2]).await.unwrap();

        let VncEvent::Failed(failure) = next_event(&events).await else {
            panic!("expected Failed");
        };
        assert!(failure.is_auth);
        assert_eq!(failure.message, "This server asks for a password.");
    }

    #[tokio::test]
    async fn a_closed_port_is_a_transient_failure() {
        let (listener, port) = listen().await;
        drop(listener);
        let conn = connect(port, "", VncSettings::default());
        let VncEvent::Failed(failure) = next_event(&conn.subscribe_events()).await else {
            panic!("expected Failed");
        };
        assert!(failure.is_transient);
        assert!(!failure.is_auth);
    }

    #[tokio::test]
    async fn rfb_3_3_without_a_password() {
        let (listener, port) = listen().await;
        let conn = connect(port, "", VncSettings::default());
        let events = conn.subscribe_events();
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"RFB 003.003\n").await.unwrap();
        assert_eq!(read(&mut stream, 12).await, b"RFB 003.003\n");
        stream.write_all(&1u32.to_be_bytes()).await.unwrap();
        assert_eq!(read(&mut stream, 1).await, [1]);
        let mut init = vec![0, 4, 0, 2];
        init.extend_from_slice(&[0u8; 16]);
        init.extend_from_slice(&0u32.to_be_bytes());
        stream.write_all(&init).await.unwrap();
        for _ in 0..3 {
            client_message(&mut stream).await;
        }
        stream.write_all(&update([1, 2, 3, 0], &[])).await.unwrap();
        assert!(matches!(
            next_event(&events).await,
            VncEvent::Connected { .. }
        ));
    }

    #[tokio::test]
    async fn the_remote_desktop_follows_the_tab_where_the_server_allows_it() {
        let (listener, port) = listen().await;
        let settings = VncSettings {
            resize_remote: true,
            ..VncSettings::default()
        };
        let conn = connect(port, "pw", settings);
        let events = conn.subscribe_events();
        let (mut stream, _) = listener.accept().await.unwrap();
        sign_in(&mut stream, "pw").await;
        assert!(!conn.resizes_remote());

        let mut layout = Vec::new();
        for value in [0u16, 0, 4, 2] {
            layout.extend_from_slice(&value.to_be_bytes());
        }
        layout.extend_from_slice(&decode::EXTENDED_DESKTOP_SIZE.to_be_bytes());
        layout.extend_from_slice(&[1, 0, 0, 0]);
        layout.extend_from_slice(&9u32.to_be_bytes());
        for value in [0u16, 0, 4, 2] {
            layout.extend_from_slice(&value.to_be_bytes());
        }
        layout.extend_from_slice(&0u32.to_be_bytes());
        stream.write_all(&update([0; 4], &[layout])).await.unwrap();
        assert!(matches!(
            next_event(&events).await,
            VncEvent::Connected { .. }
        ));
        assert!(conn.resizes_remote());

        conn.send(&[VncInput::Resize {
            width: 8,
            height: 6,
        }]);
        let resize = input_message(&mut stream).await;
        assert_eq!(&resize[..8], &[251, 0, 0, 8, 0, 6, 1, 0]);
        assert_eq!(&resize[8..12], &9u32.to_be_bytes());
    }

    #[tokio::test]
    async fn a_view_only_session_sends_no_input_and_keeps_the_remote_pointer() {
        let (listener, port) = listen().await;
        let settings = VncSettings {
            view_only: true,
            clipboard: true,
            ..VncSettings::default()
        };
        let conn = connect(port, "pw", settings);
        let events = conn.subscribe_events();
        let (mut stream, _) = listener.accept().await.unwrap();
        let encodings = sign_in(&mut stream, "pw").await;
        assert!(!encodings.contains(&decode::CURSOR));
        stream.write_all(&update([0; 4], &[])).await.unwrap();
        next_event(&events).await;

        assert!(!conn.accepts_input());
        conn.send(&[VncInput::Key {
            keysym: 0x61,
            pressed: true,
        }]);
        conn.offer_clipboard("local".to_string());
        // Only the incremental request arrives.
        assert_eq!(client_message(&mut stream).await[0], 3);
        let mut probe = [0u8; 1];
        let quiet = timeout(Duration::from_millis(200), stream.read(&mut probe)).await;
        assert!(quiet.is_err(), "a view-only client wrote {probe:?}");
    }

    #[tokio::test]
    async fn copied_text_on_the_server_reaches_the_local_clipboard() {
        let (listener, port) = listen().await;
        let settings = VncSettings {
            clipboard: true,
            ..VncSettings::default()
        };
        let conn = connect(port, "pw", settings);
        let events = conn.subscribe_events();
        let (mut stream, _) = listener.accept().await.unwrap();
        let encodings = sign_in(&mut stream, "pw").await;
        assert!(encodings.contains(&clipboard::EXTENDED_CLIPBOARD));
        stream.write_all(&update([0; 4], &[])).await.unwrap();
        next_event(&events).await;

        let mut cut = vec![3, 0, 0, 0];
        cut.extend_from_slice(&5u32.to_be_bytes());
        cut.extend_from_slice(b"hello");
        stream.write_all(&cut).await.unwrap();
        let VncEvent::RemoteClipboard(text) = next_event(&events).await else {
            panic!("expected RemoteClipboard");
        };
        assert_eq!(text, "hello");

        conn.offer_clipboard("hello".to_string());
        conn.offer_clipboard("from here".to_string());
        let message = input_message(&mut stream).await;
        assert_eq!(&message[8..], b"from here");
    }
}
