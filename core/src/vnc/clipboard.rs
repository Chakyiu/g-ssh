//! Copied text, both ways. Plain cut text is Latin-1. The extended clipboard
//! (TigerVNC, UltraVNC, QEMU) carries UTF-8 through zlib, and each side
//! announces new text and sends it when the other asks.

use std::io::{Read, Write};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;

use super::message::CLIENT_CUT_TEXT;
use super::VncError;

/// The pseudo-encoding that says this client speaks the extended clipboard.
pub(super) const EXTENDED_CLIPBOARD: i32 = 0xC0A1_E5CE_u32 as i32;

/// Copied text larger than this is dropped rather than held.
pub(super) const MAX_TEXT: usize = 8 << 20;

const TEXT: u32 = 1;
const FORMATS: u32 = 0xffff;
const CAPS: u32 = 1 << 24;
const REQUEST: u32 = 1 << 25;
const PEEK: u32 = 1 << 26;
const NOTIFY: u32 = 1 << 27;
const PROVIDE: u32 = 1 << 28;

/// What the server said it can do with the extended clipboard.
#[derive(Clone, Copy)]
struct ServerCaps {
    actions: u32,
    has_text: bool,
    /// Text up to this size may be sent without being asked for.
    text_size: usize,
}

#[derive(Default)]
pub(super) struct ClipboardState {
    /// Set once the server has sent its extended clipboard caps.
    server: Option<ServerCaps>,
    /// The latest local text, for a server that asks for it later.
    local: Option<String>,
    /// What the remote clipboard holds as far as this side knows: the last
    /// text either side sent. Offering it again sends nothing.
    known: Option<String>,
}

impl ClipboardState {
    /// A ServerCutText payload. A negative length is the extended form.
    /// Returns text for the local clipboard and a reply for the server.
    pub(super) fn receive(
        &mut self,
        length: i32,
        payload: &[u8],
    ) -> Result<(Option<String>, Option<Vec<u8>>), VncError> {
        if length >= 0 {
            let text = legacy_text(payload);
            self.known = Some(text.clone());
            return Ok((Some(text), None));
        }
        let Some(flags) = payload
            .get(..4)
            .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        else {
            return Err(broken());
        };
        let body = &payload[4..];
        if flags & CAPS != 0 {
            // One size for each format the server has, in bit order. Text is bit 0.
            let text_size = if flags & TEXT != 0 {
                body.get(..4).map_or(0, |bytes| {
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
                })
            } else {
                0
            };
            self.server = Some(ServerCaps {
                actions: flags & !FORMATS,
                has_text: flags & TEXT != 0,
                text_size,
            });
            return Ok((None, Some(caps_message())));
        }
        let Some(server) = self.server else {
            return Ok((None, None));
        };
        if flags & PROVIDE != 0 {
            let text = provided_text(flags, body)?;
            if let Some(text) = &text {
                self.known = Some(text.clone());
            }
            return Ok((text, None));
        }
        if flags & NOTIFY != 0 {
            // The remote clipboard changed. Ask for it if it is text.
            self.known = None;
            let wants = flags & TEXT != 0 && server.actions & REQUEST != 0;
            return Ok((None, wants.then(|| extended(REQUEST | TEXT, &[]))));
        }
        if flags & REQUEST != 0 {
            let reply = match &self.local {
                Some(text) if flags & TEXT != 0 && server.actions & PROVIDE != 0 => {
                    Some(provide_message(text))
                }
                _ => None,
            };
            return Ok((None, reply));
        }
        if flags & PEEK != 0 && server.actions & NOTIFY != 0 {
            let formats = if self.local.is_some() { TEXT } else { 0 };
            return Ok((None, Some(extended(NOTIFY | formats, &[]))));
        }
        Ok((None, None))
    }

    /// Local text for the remote, or `None` when the remote already has it.
    pub(super) fn offer(&mut self, text: String) -> Option<Vec<u8>> {
        if self.known.as_deref() == Some(text.as_str()) {
            return None;
        }
        self.known = Some(text.clone());
        let message = match self.server {
            // LibVNCServer 0.9.14 takes text unasked, then drops it unless its
            // app reads UTF-8, and x11vnc does not. The plain copy goes first,
            // so a server that reads both ends with the UTF-8 one.
            Some(server)
                if server.has_text
                    && server.actions & PROVIDE != 0
                    && text.len() < server.text_size =>
            {
                let mut message = legacy_message(&text);
                message.extend_from_slice(&provide_message(&text));
                message
            }
            Some(server) if server.actions & NOTIFY != 0 => extended(NOTIFY | TEXT, &[]),
            _ => legacy_message(&text),
        };
        self.local = Some(text);
        Some(message)
    }
}

fn broken() -> VncError {
    VncError::Protocol("The server sent a broken clipboard message.".to_string())
}

/// Latin-1 by the specification, but some servers send UTF-8. Latin-1 text
/// with accents is almost never valid UTF-8, so UTF-8 that parses is taken
/// as UTF-8.
fn legacy_text(bytes: &[u8]) -> String {
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|&byte| char::from(byte)).collect(),
    };
    text.replace("\r\n", "\n")
}

/// Latin-1 with bare line feeds. A character outside Latin-1 becomes `?`.
fn legacy_message(text: &str) -> Vec<u8> {
    let bytes: Vec<u8> = text
        .replace("\r\n", "\n")
        .chars()
        .map(|ch| u8::try_from(u32::from(ch)).unwrap_or(b'?'))
        .collect();
    let mut message = vec![CLIENT_CUT_TEXT, 0, 0, 0];
    message.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    message.extend_from_slice(&bytes);
    message
}

/// A ClientCutText with a negative length: flags, then the body.
fn extended(flags: u32, body: &[u8]) -> Vec<u8> {
    let length = -((4 + body.len()) as i32);
    let mut message = vec![CLIENT_CUT_TEXT, 0, 0, 0];
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(body);
    message
}

/// Text only, and every action, with the largest text this side takes unasked.
fn caps_message() -> Vec<u8> {
    let flags = CAPS | TEXT | REQUEST | PEEK | NOTIFY | PROVIDE;
    extended(flags, &(MAX_TEXT as u32).to_be_bytes())
}

/// UTF-8 with CRLF line ends and a NUL, behind its length, all through zlib.
/// The stream is flushed, not finished, as TigerVNC's own viewer sends it:
/// LibVNCServer reads the end of a finished stream as an error.
fn provide_message(text: &str) -> Vec<u8> {
    let mut data = text
        .replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .into_bytes();
    data.push(0);
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    let written = encoder
        .write_all(&(data.len() as u32).to_be_bytes())
        .and_then(|()| encoder.write_all(&data))
        .and_then(|()| encoder.flush());
    let compressed = match written {
        Ok(()) => std::mem::take(encoder.get_mut()),
        Err(_) => Vec::new(),
    };
    extended(PROVIDE | TEXT, &compressed)
}

/// The text out of a provide message. Its formats follow in bit order, each
/// a length and its bytes; text is the first.
fn provided_text(flags: u32, body: &[u8]) -> Result<Option<String>, VncError> {
    if flags & TEXT == 0 {
        return Ok(None);
    }
    let mut decoder = ZlibDecoder::new(body).take(MAX_TEXT as u64 + 4);
    let mut length = [0u8; 4];
    decoder.read_exact(&mut length).map_err(|_| broken())?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_TEXT {
        return Ok(None);
    }
    let mut data = vec![0u8; length];
    decoder.read_exact(&mut data).map_err(|_| broken())?;
    let end = data
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(data.len());
    let text = String::from_utf8_lossy(&data[..end]).replace("\r\n", "\n");
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags_of(message: &[u8]) -> u32 {
        u32::from_be_bytes([message[8], message[9], message[10], message[11]])
    }

    /// What a server sends: its caps, with the text size it takes unasked.
    fn server_caps(actions: u32, text_size: u32) -> (i32, Vec<u8>) {
        let mut payload = (CAPS | TEXT | actions).to_be_bytes().to_vec();
        payload.extend_from_slice(&text_size.to_be_bytes());
        (-(payload.len() as i32), payload)
    }

    #[test]
    fn plain_cut_text_is_latin1_unless_it_is_utf8() {
        assert_eq!(legacy_text(b"caf\xe9"), "café");
        assert_eq!(legacy_text("café".as_bytes()), "café");
        assert_eq!(legacy_text(b"a\r\nb\0"), "a\nb");
    }

    #[test]
    fn plain_messages_replace_what_latin1_cannot_hold() {
        let message = legacy_message("é中\r\n");
        assert_eq!(&message[..8], &[6, 0, 0, 0, 0, 0, 0, 3]);
        assert_eq!(&message[8..], &[0xe9, b'?', b'\n']);
    }

    #[test]
    fn provided_text_round_trips_through_zlib() {
        let message = provide_message("一\n二");
        assert_eq!(flags_of(&message), PROVIDE | TEXT);
        let length = i32::from_be_bytes([message[4], message[5], message[6], message[7]]);
        assert_eq!(length.unsigned_abs() as usize, message.len() - 8);
        let text = provided_text(PROVIDE | TEXT, &message[12..]).unwrap();
        assert_eq!(text.as_deref(), Some("一\n二"));
    }

    #[test]
    fn caps_are_answered_with_this_clients_caps() {
        let mut state = ClipboardState::default();
        let (length, payload) = server_caps(REQUEST | NOTIFY | PROVIDE, 0);
        let (text, reply) = state.receive(length, &payload).unwrap();
        assert!(text.is_none());
        let reply = reply.unwrap();
        assert_eq!(
            flags_of(&reply),
            CAPS | TEXT | REQUEST | PEEK | NOTIFY | PROVIDE
        );
    }

    #[test]
    fn local_text_is_announced_then_sent_when_asked() {
        let mut state = ClipboardState::default();
        let (length, payload) = server_caps(REQUEST | NOTIFY | PROVIDE, 0);
        state.receive(length, &payload).unwrap();

        let notify = state.offer("hello".to_string()).unwrap();
        assert_eq!(flags_of(&notify), NOTIFY | TEXT);
        assert!(state.offer("hello".to_string()).is_none());

        let request = (REQUEST | TEXT).to_be_bytes();
        let (_, reply) = state.receive(-4, &request).unwrap();
        let reply = reply.unwrap();
        assert_eq!(flags_of(&reply), PROVIDE | TEXT);
        let text = provided_text(PROVIDE | TEXT, &reply[12..]).unwrap();
        assert_eq!(text.as_deref(), Some("hello"));
    }

    #[test]
    fn a_server_that_takes_text_unasked_gets_it_plain_then_extended() {
        let mut state = ClipboardState::default();
        let (length, payload) = server_caps(PROVIDE, 1 << 20);
        state.receive(length, &payload).unwrap();
        let message = state.offer("hello".to_string()).unwrap();
        let plain = legacy_message("hello");
        assert_eq!(&message[..plain.len()], plain.as_slice());
        let provide = &message[plain.len()..];
        assert_eq!(flags_of(provide), PROVIDE | TEXT);
        let text = provided_text(PROVIDE | TEXT, &provide[12..]).unwrap();
        assert_eq!(text.as_deref(), Some("hello"));
    }

    #[test]
    fn remote_notify_is_answered_with_a_request() {
        let mut state = ClipboardState::default();
        let (length, payload) = server_caps(REQUEST | NOTIFY | PROVIDE, 0);
        state.receive(length, &payload).unwrap();
        let notify = (NOTIFY | TEXT).to_be_bytes();
        let (_, reply) = state.receive(-4, &notify).unwrap();
        assert_eq!(flags_of(&reply.unwrap()), REQUEST | TEXT);
    }

    #[test]
    fn text_from_the_server_is_not_sent_back() {
        let mut state = ClipboardState::default();
        let (text, _) = state.receive(5, b"hello").unwrap();
        assert_eq!(text.as_deref(), Some("hello"));
        assert!(state.offer("hello".to_string()).is_none());
        assert!(state.offer("other".to_string()).is_some());
    }

    #[test]
    fn without_extended_caps_text_goes_as_plain_cut_text() {
        let mut state = ClipboardState::default();
        let message = state.offer("hi".to_string()).unwrap();
        assert_eq!(message, [6, 0, 0, 0, 0, 0, 0, 2, b'h', b'i']);
    }
}
