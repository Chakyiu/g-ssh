//! Message types from the server, and what this client sends, byte for byte.

use super::decode::Screen;

pub(super) const FRAMEBUFFER_UPDATE: u8 = 0;
pub(super) const SET_COLOUR_MAP_ENTRIES: u8 = 1;
pub(super) const BELL: u8 = 2;
pub(super) const SERVER_CUT_TEXT: u8 = 3;

const SET_PIXEL_FORMAT: u8 = 0;
const SET_ENCODINGS: u8 = 2;
const FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
const KEY_EVENT: u8 = 4;
const POINTER_EVENT: u8 = 5;
pub(super) const CLIENT_CUT_TEXT: u8 = 6;
const SET_DESKTOP_SIZE: u8 = 251;

/// 32 bits a pixel, little-endian, red at bit 16 and blue at bit 0: on the
/// wire, B, G, R and a spare byte, which is the view's BGRA but for alpha.
pub(super) fn set_pixel_format(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&[SET_PIXEL_FORMAT, 0, 0, 0]);
    // Bits per pixel, depth, big-endian, true colour.
    buf.extend_from_slice(&[32, 24, 0, 1]);
    for max in [255u16; 3] {
        buf.extend_from_slice(&max.to_be_bytes());
    }
    // Red, green and blue shifts, then padding.
    buf.extend_from_slice(&[16, 8, 0, 0, 0, 0]);
}

pub(super) fn set_encodings(buf: &mut Vec<u8>, encodings: &[i32]) {
    buf.extend_from_slice(&[SET_ENCODINGS, 0]);
    let count = u16::try_from(encodings.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&count.to_be_bytes());
    for encoding in encodings.iter().take(usize::from(count)) {
        buf.extend_from_slice(&encoding.to_be_bytes());
    }
}

/// The whole desktop. An incremental request is answered once something
/// has changed.
pub(super) fn update_request(buf: &mut Vec<u8>, incremental: bool, width: u16, height: u16) {
    buf.extend_from_slice(&[
        FRAMEBUFFER_UPDATE_REQUEST,
        u8::from(incremental),
        0,
        0,
        0,
        0,
    ]);
    buf.extend_from_slice(&width.to_be_bytes());
    buf.extend_from_slice(&height.to_be_bytes());
}

pub(super) fn key(buf: &mut Vec<u8>, pressed: bool, keysym: u32) {
    buf.extend_from_slice(&[KEY_EVENT, u8::from(pressed), 0, 0]);
    buf.extend_from_slice(&keysym.to_be_bytes());
}

/// `buttons` is every button held, not the one that changed.
pub(super) fn pointer(buf: &mut Vec<u8>, buttons: u8, x: u16, y: u16) {
    buf.extend_from_slice(&[POINTER_EVENT, buttons]);
    buf.extend_from_slice(&x.to_be_bytes());
    buf.extend_from_slice(&y.to_be_bytes());
}

/// One screen covering the whole desktop, with the id and flags of the
/// server's first screen so the server reads it as that screen resized.
pub(super) fn set_desktop_size(buf: &mut Vec<u8>, width: u16, height: u16, screens: &[Screen]) {
    let (id, flags) = screens
        .first()
        .map_or((0, 0), |screen| (screen.id, screen.flags));
    buf.extend_from_slice(&[SET_DESKTOP_SIZE, 0]);
    buf.extend_from_slice(&width.to_be_bytes());
    buf.extend_from_slice(&height.to_be_bytes());
    buf.extend_from_slice(&[1, 0]);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(&width.to_be_bytes());
    buf.extend_from_slice(&height.to_be_bytes());
    buf.extend_from_slice(&flags.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pixel_format_asks_for_bgrx() {
        let mut buf = Vec::new();
        set_pixel_format(&mut buf);
        assert_eq!(
            buf,
            [0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]
        );
    }

    #[test]
    fn desktop_size_keeps_the_first_screen_id() {
        let screens = [Screen {
            id: 7,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            flags: 3,
        }];
        let mut buf = Vec::new();
        set_desktop_size(&mut buf, 1024, 768, &screens);
        assert_eq!(
            buf,
            [251, 0, 4, 0, 3, 0, 1, 0, 0, 0, 0, 7, 0, 0, 0, 0, 4, 0, 3, 0, 0, 0, 0, 3]
        );
    }
}
