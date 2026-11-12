//! What an RDP and a VNC session hand the view that paints them.

use std::sync::Arc;

/// One decoded desktop. Pixels are BGRA, top to bottom, with a full alpha byte.
#[derive(Clone)]
pub struct DesktopFrame {
    pub width: u32,
    pub height: u32,
    pub bgra: Arc<Vec<u8>>,
}

/// A button on the remote pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerButton {
    Left,
    Right,
    Middle,
}
