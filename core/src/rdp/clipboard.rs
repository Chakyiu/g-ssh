//! Text on the clipboard, shared both ways over CLIPRDR.
//!
//! A remote copy is fetched at once and handed to the view as
//! [`RdpEvent::RemoteClipboard`]. Local text is offered with
//! [`super::RdpConnection::offer_clipboard`] and sent when the remote pastes.
//! Files and images stay on their own side.

use std::sync::{Arc, Mutex};

use ironrdp_client::rdp::RdpInputEvent;
use ironrdp_cliprdr::backend::{ClipboardMessage, CliprdrBackend, CliprdrBackendFactory};
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use tokio::sync::mpsc;

use super::RdpEvent;

/// The text each side last put on the shared clipboard.
#[derive(Default)]
struct Texts {
    /// Offered from here. Served when the remote pastes.
    local: Option<String>,
    /// Copied over there, and already on the local clipboard.
    remote: Option<String>,
}

/// Shared by the connection and the backend of each (re)connect.
#[derive(Clone)]
pub(super) struct SharedClipboard {
    texts: Arc<Mutex<Texts>>,
    input: mpsc::UnboundedSender<RdpInputEvent>,
    events: async_channel::Sender<RdpEvent>,
}

impl SharedClipboard {
    pub(super) fn new(
        input: mpsc::UnboundedSender<RdpInputEvent>,
        events: async_channel::Sender<RdpEvent>,
    ) -> Self {
        Self {
            texts: Arc::default(),
            input,
            events,
        }
    }

    /// Advertise `text` unless the remote has it already.
    pub(super) fn offer(&self, text: String) {
        {
            let mut texts = self.texts.lock().unwrap_or_else(|e| e.into_inner());
            if texts.local.as_deref() == Some(text.as_str())
                || texts.remote.as_deref() == Some(text.as_str())
            {
                return;
            }
            texts.local = Some(text);
        }
        self.advertise();
    }

    fn advertise(&self) {
        let has_text = self
            .texts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .local
            .is_some();
        let formats = if has_text {
            vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]
        } else {
            Vec::new()
        };
        self.send(ClipboardMessage::SendInitiateCopy(formats));
    }

    fn send(&self, message: ClipboardMessage) {
        let _ = self.input.send(RdpInputEvent::Clipboard(message));
    }
}

impl CliprdrBackendFactory for SharedClipboard {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        Box::new(TextBackend {
            shared: self.clone(),
            requested: None,
        })
    }
}

struct TextBackend {
    shared: SharedClipboard,
    /// The format of the paste in flight.
    requested: Option<ClipboardFormatId>,
}

ironrdp_core::impl_as_any!(TextBackend);

impl std::fmt::Debug for TextBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextBackend").finish_non_exhaustive()
    }
}

impl CliprdrBackend for TextBackend {
    fn temporary_directory(&self) -> &str {
        ""
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {}

    fn on_request_format_list(&mut self) {
        self.shared.advertise();
    }

    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        let has = |id| available_formats.iter().any(|format| format.id() == id);
        let format = if has(ClipboardFormatId::CF_UNICODETEXT) {
            ClipboardFormatId::CF_UNICODETEXT
        } else if has(ClipboardFormatId::CF_TEXT) {
            ClipboardFormatId::CF_TEXT
        } else {
            return;
        };
        self.requested = Some(format);
        self.shared
            .send(ClipboardMessage::SendInitiatePaste(format));
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        let local = self
            .shared
            .texts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .local
            .clone();
        let response = match local {
            Some(text) if request.format == ClipboardFormatId::CF_UNICODETEXT => {
                FormatDataResponse::new_unicode_string(&text)
            }
            _ => FormatDataResponse::new_error(),
        };
        self.shared.send(ClipboardMessage::SendFormatData(response));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        let Some(format) = self.requested.take() else {
            return;
        };
        if response.is_error() {
            return;
        }
        let text = if format == ClipboardFormatId::CF_UNICODETEXT {
            match response.to_unicode_string() {
                Ok(text) => text,
                Err(error) => {
                    tracing::warn!(%error, "rdp clipboard text undecodable");
                    return;
                }
            }
        } else {
            ansi_text(response.data())
        };
        let text = text.trim_end_matches('\0').to_string();
        {
            let mut texts = self.shared.texts.lock().unwrap_or_else(|e| e.into_inner());
            texts.remote = Some(text.clone());
            texts.local = None;
        }
        if self
            .shared
            .events
            .try_send(RdpEvent::RemoteClipboard(text))
            .is_err()
        {
            tracing::debug!("rdp clipboard text dropped: the session is busy or gone");
        }
    }

    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _: LockDataId) {}

    fn on_unlock(&mut self, _: LockDataId) {}
}

/// `CF_TEXT` is the sender's code page. UTF-8 is the common case on xrdp.
fn ansi_text(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared() -> (SharedClipboard, mpsc::UnboundedReceiver<RdpInputEvent>) {
        let (input, rx) = mpsc::unbounded_channel();
        let (events, _) = async_channel::unbounded();
        (SharedClipboard::new(input, events), rx)
    }

    fn offered(rx: &mut mpsc::UnboundedReceiver<RdpInputEvent>) -> bool {
        matches!(
            rx.try_recv(),
            Ok(RdpInputEvent::Clipboard(ClipboardMessage::SendInitiateCopy(formats))) if !formats.is_empty()
        )
    }

    #[test]
    fn the_same_local_text_is_offered_once() {
        let (shared, mut rx) = shared();
        shared.offer("ada".into());
        assert!(offered(&mut rx));
        shared.offer("ada".into());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn text_that_came_from_the_remote_is_not_offered_back() {
        let (shared, mut rx) = shared();
        let mut backend = TextBackend {
            shared: shared.clone(),
            requested: Some(ClipboardFormatId::CF_UNICODETEXT),
        };
        backend.on_format_data_response(FormatDataResponse::new_unicode_string("from there"));
        shared.offer("from there".into());
        assert!(rx.try_recv().is_err());
        shared.offer("from here".into());
        assert!(offered(&mut rx));
    }

    #[test]
    fn ansi_text_stops_at_the_terminator() {
        assert_eq!(ansi_text(b"hello\0junk"), "hello");
    }
}
