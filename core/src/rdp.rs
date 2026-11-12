//! A Remote Desktop session on [IronRDP](https://github.com/Devolutions/IronRDP).
//!
//! One TCP connection carries the desktop. The framebuffer arrives as frames,
//! and the keys and the pointer go back as fast-path input. A size change is
//! IronRDP's own reconnect. Jump hosts and the vault's proxy are not on this
//! path: IronRDP dials the address itself.

mod clipboard;

use std::sync::Arc;

use crate::desktop::{DesktopFrame, PointerButton};
use clipboard::SharedClipboard;
use ironrdp_client::config::{ClipboardType, ConfigBuilder, Destination};
use ironrdp_client::rdp::{RdpClient, RdpInputEvent, RdpOutputEvent};
use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp_pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

/// First desktop, until the view has measured itself and asks for its own size.
pub const DEFAULT_WIDTH: u16 = 1280;
pub const DEFAULT_HEIGHT: u16 = 720;

/// The most events one fast-path input packet can carry. A long paste needs several.
const MAX_FAST_PATH_EVENTS: usize = 255;

/// What the session loop hears. Frames travel on [`RdpConnection::subscribe_frames`]
/// so a slow view never queues a stack of full desktops.
pub enum RdpEvent {
    /// The first frame is up. Later frames stay on the watch.
    Connected {
        width: u16,
        height: u16,
    },
    Failed(String),
    /// Text copied on the remote, for the local clipboard.
    RemoteClipboard(String),
    Closed {
        message: String,
        is_transient: bool,
    },
}

/// One thing to send. Several of these in one [`RdpConnection::send`] leave as
/// one fast-path packet, up to [`MAX_FAST_PATH_EVENTS`], so a modifier and its
/// key stay together.
#[derive(Clone)]
pub enum RdpInput {
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
    /// `units` is a signed wheel delta. 120 is one notch.
    Wheel {
        x: u16,
        y: u16,
        units: i16,
        horizontal: bool,
    },
    Unicode {
        unit: u16,
        pressed: bool,
    },
    Scan {
        code: u8,
        extended: bool,
        pressed: bool,
    },
    Resize {
        width: u16,
        height: u16,
    },
    Close,
}

/// `DOMAIN\user` splits. `user@domain` stays the username: that is a UPN, and
/// Network Level Authentication takes it in the user field.
pub fn split_account(raw: &str) -> (String, String) {
    let Some((domain, user)) = raw.split_once('\\') else {
        return (raw.to_string(), String::new());
    };
    if domain.is_empty() || user.is_empty() {
        return (raw.to_string(), String::new());
    }
    (user.to_string(), domain.to_string())
}

/// The smallest and largest fixed desktop side a host can save.
pub const MIN_FIXED_SIDE: u16 = 200;
pub const MAX_FIXED_SIDE: u16 = 8192;

/// How an RDP host's desktop is shaped. Saved with the host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdpSettings {
    #[serde(default)]
    pub resolution: RdpResolution,
    #[serde(default)]
    pub color_depth: RdpColorDepth,
    #[serde(default)]
    pub scale: RdpScale,
    /// Play the remote session's sound here.
    #[serde(default)]
    pub audio: bool,
    /// Share text copied on either side.
    #[serde(default)]
    pub clipboard: bool,
}

impl RdpSettings {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum RdpResolution {
    /// The desktop follows the tab, and is resized when the tab is.
    #[default]
    FitWindow,
    /// The desktop keeps this size and is scaled to fit the tab.
    Fixed { width: u16, height: u16 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpColorDepth {
    #[default]
    Bits32,
    Bits24,
    Bits16,
    Bits15,
}

impl RdpColorDepth {
    pub fn bits(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits24 => 24,
            Self::Bits16 => 16,
            Self::Bits15 => 15,
        }
    }
}

/// How large the remote session draws text and controls. The server may
/// ignore it: Windows follows it, xrdp leaves it to the desktop it starts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpScale {
    #[default]
    Percent100,
    Percent125,
    Percent150,
    Percent200,
}

impl RdpScale {
    pub fn percent(self) -> u32 {
        match self {
            Self::Percent100 => 100,
            Self::Percent125 => 125,
            Self::Percent150 => 150,
            Self::Percent200 => 200,
        }
    }
}

/// Where an RDP session dials, and the account that signs in.
pub struct RdpTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    pub password: Zeroizing<String>,
    pub width: u16,
    pub height: u16,
    pub color_depth: RdpColorDepth,
    pub scale: RdpScale,
    pub audio: bool,
    pub clipboard: bool,
}

impl RdpTarget {
    /// A fixed resolution is the first desktop. Fitting the window starts at
    /// the default and resizes once the view has measured itself.
    pub fn new(
        host: String,
        port: u16,
        account: &str,
        password: Zeroizing<String>,
        settings: RdpSettings,
    ) -> Self {
        let (username, domain) = split_account(account);
        let (width, height) = match settings.resolution {
            RdpResolution::FitWindow => (DEFAULT_WIDTH, DEFAULT_HEIGHT),
            RdpResolution::Fixed { width, height } => (
                width.clamp(MIN_FIXED_SIDE, MAX_FIXED_SIDE),
                height.clamp(MIN_FIXED_SIDE, MAX_FIXED_SIDE),
            ),
        };
        Self {
            host,
            port,
            username,
            domain,
            password,
            width,
            height,
            color_depth: settings.color_depth,
            scale: settings.scale,
            audio: settings.audio,
            clipboard: settings.clipboard,
        }
    }
}

/// Sends input. The last clone asks the session to end.
struct RdpSend {
    input: mpsc::UnboundedSender<RdpInputEvent>,
}

impl Drop for RdpSend {
    fn drop(&mut self) {
        let _ = self.input.send(RdpInputEvent::Close);
    }
}

/// One live desktop. Cloning shares the session.
#[derive(Clone)]
pub struct RdpConnection {
    send: Arc<RdpSend>,
    event_rx: async_channel::Receiver<RdpEvent>,
    frame_rx: watch::Receiver<Option<DesktopFrame>>,
    /// Sent again with every resize, or the server falls back to 100%.
    scale: RdpScale,
    clipboard: Option<SharedClipboard>,
}

impl RdpConnection {
    pub fn spawn(target: RdpTarget) -> Self {
        let (event_tx, event_rx) = async_channel::bounded(8);
        let (frame_tx, frame_rx) = watch::channel(None);
        let (output_tx, output_rx) = mpsc::channel(2);
        let mut built = build_client(&target, output_tx);
        let mut clipboard = None;
        let input = match &mut built {
            Ok(client) => {
                let input = client.input_sender();
                if target.clipboard {
                    let shared = SharedClipboard::new(input.clone(), event_tx.clone());
                    client.set_clipboard_backend(Box::new(shared.clone()));
                    clipboard = Some(shared);
                }
                input
            }
            Err(error) => {
                tracing::warn!(host = %target.host, port = target.port, error, "rdp config rejected");
                let _ = event_tx.try_send(RdpEvent::Failed(error.clone()));
                mpsc::unbounded_channel().0
            }
        };
        if let Ok(client) = built {
            let host = target.host.clone();
            let port = target.port;
            std::thread::Builder::new()
                .name("g-ssh-rdp".into())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("tokio runtime");
                    runtime.block_on(async move {
                        let pump = pump_output(output_rx, event_tx, frame_tx, host, port);
                        tokio::join!(client.run(), pump);
                    });
                })
                .expect("spawn rdp thread");
        }
        Self {
            send: Arc::new(RdpSend { input }),
            event_rx,
            frame_rx,
            scale: target.scale,
            clipboard,
        }
    }

    /// Whether this session shares the clipboard.
    pub fn shares_clipboard(&self) -> bool {
        self.clipboard.is_some()
    }

    /// Put local text on the remote clipboard. Text the remote already has is
    /// skipped, so this is cheap to call whenever the view is touched.
    pub fn offer_clipboard(&self, text: String) {
        if let Some(clipboard) = &self.clipboard {
            clipboard.offer(text);
        }
    }

    pub fn subscribe_events(&self) -> async_channel::Receiver<RdpEvent> {
        self.event_rx.clone()
    }

    pub fn subscribe_frames(&self) -> watch::Receiver<Option<DesktopFrame>> {
        self.frame_rx.clone()
    }

    /// Best effort. A session that has already ended drops the input.
    pub fn send(&self, inputs: &[RdpInput]) {
        let mut fast_path = SmallVec::<[FastPathInputEvent; 2]>::new();
        let mut resize = None;
        let mut close = false;
        for input in inputs {
            match input {
                RdpInput::Move { x, y } => fast_path.push(mouse(*x, *y, PointerFlags::MOVE, 0)),
                RdpInput::Button {
                    x,
                    y,
                    button,
                    pressed,
                } => {
                    let mut flags = match button {
                        PointerButton::Left => PointerFlags::LEFT_BUTTON,
                        PointerButton::Right => PointerFlags::RIGHT_BUTTON,
                        PointerButton::Middle => PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
                    };
                    if *pressed {
                        flags |= PointerFlags::DOWN;
                    }
                    fast_path.push(mouse(*x, *y, flags, 0));
                }
                RdpInput::Wheel {
                    x,
                    y,
                    units,
                    horizontal,
                } => {
                    let flags = if *horizontal {
                        PointerFlags::HORIZONTAL_WHEEL
                    } else {
                        PointerFlags::VERTICAL_WHEEL
                    };
                    let units = (*units).clamp(-255, 255);
                    fast_path.push(mouse(*x, *y, flags, units));
                }
                RdpInput::Unicode { unit, pressed } => {
                    let flags = if *pressed {
                        KeyboardFlags::empty()
                    } else {
                        KeyboardFlags::RELEASE
                    };
                    fast_path.push(FastPathInputEvent::UnicodeKeyboardEvent(flags, *unit));
                }
                RdpInput::Scan {
                    code,
                    extended,
                    pressed,
                } => {
                    let mut flags = if *pressed {
                        KeyboardFlags::empty()
                    } else {
                        KeyboardFlags::RELEASE
                    };
                    if *extended {
                        flags |= KeyboardFlags::EXTENDED;
                    }
                    fast_path.push(FastPathInputEvent::KeyboardEvent(flags, *code));
                }
                RdpInput::Resize { width, height } => resize = Some((*width, *height)),
                RdpInput::Close => close = true,
            }
        }
        for packet in fast_path.chunks(MAX_FAST_PATH_EVENTS) {
            let _ = self
                .send
                .input
                .send(RdpInputEvent::FastPath(SmallVec::from_slice(packet)));
        }
        if let Some((width, height)) = resize {
            let _ = self.send.input.send(RdpInputEvent::Resize {
                width,
                height,
                scale_factor: self.scale.percent(),
                physical_size: None,
            });
        }
        if close {
            let _ = self.send.input.send(RdpInputEvent::Close);
        }
    }
}

fn mouse(x: u16, y: u16, flags: PointerFlags, units: i16) -> FastPathInputEvent {
    FastPathInputEvent::MouseEvent(MousePdu {
        flags,
        number_of_wheel_rotation_units: units,
        x_position: x,
        y_position: y,
    })
}

async fn pump_output(
    mut output_rx: mpsc::Receiver<RdpOutputEvent>,
    event_tx: async_channel::Sender<RdpEvent>,
    frame_tx: watch::Sender<Option<DesktopFrame>>,
    host: String,
    port: u16,
) {
    let mut announced = false;
    while let Some(event) = output_rx.recv().await {
        match event {
            RdpOutputEvent::Image {
                buffer,
                width,
                height,
            } => {
                let width = width.get();
                let height = height.get();
                if let Some(frame) = bgra_frame(&buffer, width, height) {
                    let _ = frame_tx.send(Some(frame));
                }
                if !announced {
                    announced = true;
                    tracing::info!(host = %host, port, width, height, "rdp desktop ready");
                    let _ = event_tx.send(RdpEvent::Connected { width, height }).await;
                }
            }
            RdpOutputEvent::ConnectionFailure(error) => {
                let message = format!("{error:?}");
                tracing::warn!(host = %host, port, error = %message, "rdp connect failed");
                let _ = event_tx.send(RdpEvent::Failed(message)).await;
            }
            RdpOutputEvent::Terminated(Ok(reason)) => {
                let message = format!("{reason:?}");
                tracing::info!(host = %host, port, reason = %message, "rdp session ended");
                let _ = event_tx
                    .send(RdpEvent::Closed {
                        message,
                        is_transient: false,
                    })
                    .await;
            }
            RdpOutputEvent::Terminated(Err(error)) => {
                let message = format!("{error:?}");
                // A GUI-stopped error is us closing. Anything else can be retried.
                let is_transient = !message.contains("GUI is stopped");
                tracing::warn!(host = %host, port, error = %message, "rdp session ended");
                let _ = event_tx
                    .send(RdpEvent::Closed {
                        message,
                        is_transient,
                    })
                    .await;
            }
            RdpOutputEvent::PointerDefault
            | RdpOutputEvent::PointerHidden
            | RdpOutputEvent::PointerPosition { .. }
            | RdpOutputEvent::PointerBitmap(_) => {}
        }
    }
}

fn build_client(
    target: &RdpTarget,
    output_tx: mpsc::Sender<RdpOutputEvent>,
) -> Result<RdpClient, String> {
    let destination = Destination::from_parts(&target.host, target.port);
    let mut builder = ConfigBuilder::new()
        .with_destination(destination)
        .with_username(&target.username)
        .with_password(target.password.as_str())
        .with_client_name("g-ssh")
        .with_client_dir("C:\\Windows\\System32\\mstscax.dll")
        .with_client_build(18363)
        .with_platform(MajorPlatformType::UNSPECIFIED)
        .with_desktop_width(target.width)
        .with_desktop_height(target.height)
        .with_desktop_scale_factor(target.scale.percent())
        .with_color_depth(target.color_depth.bits())
        .with_sound(target.audio)
        .with_clipboard(if target.clipboard {
            ClipboardType::Enable
        } else {
            ClipboardType::Disable
        })
        .with_credssp(true)
        .with_tls(true)
        // xrdp without a readable TLS certificate answers with standard RDP security
        // whatever the client offers.
        .with_standard_security(true)
        .with_autologon(true)
        // The view draws its own pointer. The server's sprite would sit on
        // top of it inside the framebuffer.
        .with_server_pointer(false)
        .with_pointer_software_rendering(false);
    if !target.domain.is_empty() {
        builder = builder.with_domain(&target.domain);
    }
    let config = builder.build().map_err(|error| error.to_string())?;
    Ok(RdpClient::new(config, output_tx))
}

/// IronRDP packs each pixel as `0x00RRGGBB`. The view wants BGRA.
fn bgra_frame(buffer: &[u32], width: u16, height: u16) -> Option<DesktopFrame> {
    let pixels = usize::from(width) * usize::from(height);
    if buffer.len() < pixels || pixels == 0 {
        return None;
    }
    let mut bgra = Vec::with_capacity(pixels * 4);
    for pixel in buffer.iter().take(pixels) {
        let red = (pixel >> 16) as u8;
        let green = (pixel >> 8) as u8;
        let blue = *pixel as u8;
        bgra.extend_from_slice(&[blue, green, red, 255]);
    }
    Some(DesktopFrame {
        width: u32::from(width),
        height: u32::from(height),
        bgra: Arc::new(bgra),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backslash_account_splits_into_domain_and_user() {
        let (user, domain) = split_account(r"CORP\ada");
        assert_eq!(user, "ada");
        assert_eq!(domain, "CORP");
    }

    #[test]
    fn user_principal_name_stays_in_the_user_field() {
        let (user, domain) = split_account("ada@corp.example");
        assert_eq!(user, "ada@corp.example");
        assert_eq!(domain, "");
    }

    #[test]
    fn a_bare_user_has_no_domain() {
        let (user, domain) = split_account("ada");
        assert_eq!(user, "ada");
        assert_eq!(domain, "");
    }
}
