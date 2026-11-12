//! The remote desktop of an RDP or a VNC host. The session decodes the
//! framebuffer; this paints it and sends the pointer and the keys back.

mod keysym;

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use gpui::prelude::*;
use gpui::{
    canvas, div, point, px, Bounds, Context, Corners, FocusHandle, Focusable, KeyDownEvent,
    KeyUpEvent, Keystroke, Modifiers, MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent,
    Pixels, Point, RenderImage, ScrollDelta, ScrollEvent, Subscription, Task, Window,
};
use image::{Frame, RgbaImage};
use smallvec::smallvec;
use tokio::sync::watch;

use crate::ui::keyboard::is_secondary;
use gssh::desktop::{DesktopFrame, PointerButton};
use gssh::rdp::{RdpConnection, RdpInput};
use gssh::vnc::{VncConnection, VncInput};

/// Below this the server rejects the desktop. Above it, so does the display
/// control path IronRDP adjusts toward.
const MIN_DESKTOP: f32 = 200.;
const MAX_DESKTOP: f32 = 4096.;
/// Wait out a drag of the window edge before asking the server to resize.
const RESIZE_SETTLE: Duration = Duration::from_millis(400);
/// Trackpad travel that makes one VNC wheel notch, the distance the RDP path
/// counts as a line.
const PIXELS_PER_NOTCH: f32 = 40.;

/// The session a desktop view paints and sends input to.
#[derive(Clone)]
pub(crate) enum DesktopLink {
    Rdp(RdpConnection),
    Vnc(VncConnection),
}

impl DesktopLink {
    fn subscribe_frames(&self) -> watch::Receiver<Option<DesktopFrame>> {
        match self {
            Self::Rdp(conn) => conn.subscribe_frames(),
            Self::Vnc(conn) => conn.subscribe_frames(),
        }
    }

    fn shares_clipboard(&self) -> bool {
        match self {
            Self::Rdp(conn) => conn.shares_clipboard(),
            Self::Vnc(conn) => conn.shares_clipboard(),
        }
    }

    fn offer_clipboard(&self, text: String) {
        match self {
            Self::Rdp(conn) => conn.offer_clipboard(text),
            Self::Vnc(conn) => conn.offer_clipboard(text),
        }
    }

    fn move_pointer(&self, x: u16, y: u16) {
        match self {
            Self::Rdp(conn) => conn.send(&[RdpInput::Move { x, y }]),
            Self::Vnc(conn) => conn.send(&[VncInput::Move { x, y }]),
        }
    }

    fn press(&self, x: u16, y: u16, button: PointerButton, pressed: bool) {
        match self {
            Self::Rdp(conn) => conn.send(&[RdpInput::Button {
                x,
                y,
                button,
                pressed,
            }]),
            Self::Vnc(conn) => conn.send(&[VncInput::Button {
                x,
                y,
                button,
                pressed,
            }]),
        }
    }

    fn resize(&self, width: u16, height: u16) {
        match self {
            Self::Rdp(conn) => conn.send(&[RdpInput::Resize { width, height }]),
            Self::Vnc(conn) => conn.send(&[VncInput::Resize { width, height }]),
        }
    }
}

pub(crate) struct DesktopView {
    focus_handle: FocusHandle,
    link: Option<DesktopLink>,
    /// Keys go out as X11 keysyms instead of RDP scancodes. Fixed for the
    /// view, so a VNC tab keeps its keyboard while it reconnects.
    is_vnc: bool,
    layout: Rc<Cell<Bounds<Pixels>>>,
    image: Option<Arc<RenderImage>>,
    /// The picture just replaced, dropped from the atlas on the next paint.
    retired: Option<Arc<RenderImage>>,
    frame: Option<DesktopFrame>,
    /// The desktop is resized with the tab. A fixed one is only scaled.
    follows_window: bool,
    /// What the server is showing, once a frame has said so. For VNC, the
    /// size last asked for: a server may settle on another size, and asking
    /// again would only repeat.
    asked: Option<(u16, u16)>,
    pending_size: Option<(u16, u16)>,
    resize_task: Option<Task<()>>,
    frame_task: Option<Task<()>>,
    mods: HeldMods,
    held: Option<HeldKey>,
    /// VNC keys down, with the keysym each went down as. A key is let go as
    /// that keysym, even if shift has changed since.
    vnc_keys: Vec<(String, u32)>,
    /// Wheel travel not yet sent as a whole VNC notch, across and down.
    wheel_rest: (f32, f32),
    /// Lets go of held VNC keys when the view or the window loses the
    /// keyboard, so a key-up that goes elsewhere does not leave them down.
    focus_watch: Vec<Subscription>,
}

#[derive(Clone, Copy, Default)]
struct HeldMods {
    control: bool,
    alt: bool,
    shift: bool,
    meta: bool,
}

enum HeldKey {
    Unicode(u16),
    Scan { code: u8, extended: bool },
}

impl HeldKey {
    fn release(&self) -> RdpInput {
        match *self {
            HeldKey::Unicode(unit) => RdpInput::Unicode {
                unit,
                pressed: false,
            },
            HeldKey::Scan { code, extended } => RdpInput::Scan {
                code,
                extended,
                pressed: false,
            },
        }
    }
}

impl DesktopView {
    pub(crate) fn new(link: DesktopLink, follows_window: bool, cx: &mut Context<Self>) -> Self {
        let focus_handle = cx.focus_handle();
        let mut view = Self {
            focus_handle,
            link: None,
            is_vnc: matches!(link, DesktopLink::Vnc(_)),
            layout: Rc::new(Cell::new(Bounds::default())),
            image: None,
            retired: None,
            frame: None,
            follows_window,
            asked: None,
            pending_size: None,
            resize_task: None,
            frame_task: None,
            mods: HeldMods::default(),
            held: None,
            vnc_keys: Vec::new(),
            wheel_rest: (0., 0.),
            focus_watch: Vec::new(),
        };
        view.follow(link, cx);
        view
    }

    /// The session reconnected. Frames and input follow the new connection,
    /// and the picture already on screen stays until the next one arrives.
    pub(crate) fn follow(&mut self, link: DesktopLink, cx: &mut Context<Self>) {
        self.link = Some(link.clone());
        self.mods = HeldMods::default();
        self.held = None;
        self.vnc_keys.clear();
        self.wheel_rest = (0., 0.);
        if self.is_vnc {
            // A new connection has not been asked for a size yet.
            self.asked = None;
            self.pending_size = None;
        }
        let mut frames = link.subscribe_frames();
        self.frame_task = Some(cx.spawn(async move |this, cx| loop {
            let frame = frames.borrow_and_update().clone();
            if let Some(frame) = frame {
                if this
                    .update(cx, |view, cx| view.show_frame(frame, cx))
                    .is_err()
                {
                    break;
                }
            }
            if frames.changed().await.is_err() {
                break;
            }
        }));
    }

    /// The session gave up. The last picture stays; the connection does not.
    pub(crate) fn disconnect(&mut self, cx: &mut Context<Self>) {
        self.link = None;
        self.resize_task = None;
        self.frame_task = None;
        self.pending_size = None;
        self.vnc_keys.clear();
        cx.notify();
    }

    fn show_frame(&mut self, frame: DesktopFrame, cx: &mut Context<Self>) {
        if self
            .frame
            .as_ref()
            .is_some_and(|shown| Arc::ptr_eq(&shown.bgra, &frame.bgra))
        {
            return;
        }
        let Some(image) = raster(&frame) else {
            return;
        };
        if self.pending_size.is_none() && !self.is_vnc {
            self.asked = Some((
                u16::try_from(frame.width).unwrap_or(u16::MAX),
                u16::try_from(frame.height).unwrap_or(u16::MAX),
            ));
        }
        if let Some(previous) = self.image.take() {
            self.retired = Some(previous);
        }
        self.image = Some(image);
        self.frame = Some(frame);
        cx.notify();
    }

    fn note_layout(&mut self, bounds: Bounds<Pixels>, window: &Window, cx: &mut Context<Self>) {
        if !self.follows_window {
            return;
        }
        let (width, height) = match &self.link {
            None => return,
            Some(DesktopLink::Rdp(_)) => {
                let scale = window.scale_factor();
                (
                    desktop_pixels(bounds.size.width.as_f32() * scale),
                    desktop_pixels(bounds.size.height.as_f32() * scale),
                )
            }
            // Points, not device pixels: VNC has no scale setting, and a
            // desktop of twice the pixels would draw everything half as large.
            Some(DesktopLink::Vnc(conn)) => {
                if !conn.resizes_remote() {
                    return;
                }
                (
                    desktop_pixels(bounds.size.width.as_f32()),
                    desktop_pixels(bounds.size.height.as_f32()),
                )
            }
        };
        if self.asked == Some((width, height)) || self.pending_size == Some((width, height)) {
            return;
        }
        self.pending_size = Some((width, height));
        self.resize_task = Some(cx.spawn(async move |this, cx| {
            cx.background_executor().timer(RESIZE_SETTLE).await;
            this.update(cx, |view, _| {
                let Some((width, height)) = view.pending_size.take() else {
                    return;
                };
                if view.asked == Some((width, height)) {
                    return;
                }
                view.asked = Some((width, height));
                if let Some(link) = &view.link {
                    link.resize(width, height);
                }
            })
            .ok();
        }));
    }

    fn send_rdp(&self, inputs: &[RdpInput]) {
        if let Some(DesktopLink::Rdp(conn)) = &self.link {
            conn.send(inputs);
        }
    }

    fn send_vnc(&self, inputs: &[VncInput]) {
        if let Some(DesktopLink::Vnc(conn)) = &self.link {
            conn.send(inputs);
        }
    }

    /// False while a view-only VNC host is connected. Its keys stay with the
    /// app, so its shortcuts still work.
    fn accepts_input(&self) -> bool {
        match &self.link {
            Some(DesktopLink::Vnc(conn)) => conn.accepts_input(),
            _ => true,
        }
    }

    /// Hand the local clipboard text to the remote before a click or a
    /// shortcut that may paste it there.
    fn offer_clipboard(&self, cx: &gpui::App) {
        let Some(link) = self.link.as_ref().filter(|link| link.shares_clipboard()) else {
            return;
        };
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            link.offer_clipboard(text);
        }
    }

    fn remote_point(&self, position: Point<Pixels>) -> Option<(u16, u16)> {
        let frame = self.frame.as_ref()?;
        let bounds = self.layout.get();
        let placed = letterbox(bounds, frame.width, frame.height)?;
        if position.x < placed.origin.x
            || position.y < placed.origin.y
            || position.x > placed.origin.x + placed.size.width
            || position.y > placed.origin.y + placed.size.height
        {
            return None;
        }
        let x = (position.x.as_f32() - placed.origin.x.as_f32()) / placed.size.width.as_f32()
            * frame.width as f32;
        let y = (position.y.as_f32() - placed.origin.y.as_f32()) / placed.size.height.as_f32()
            * frame.height as f32;
        Some((
            (x.round() as u32).min(frame.width.saturating_sub(1)) as u16,
            (y.round() as u32).min(frame.height.saturating_sub(1)) as u16,
        ))
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        window.focus(&self.focus_handle, cx);
        self.offer_clipboard(cx);
        self.pointer_button(event.button, event.position, true);
        cx.stop_propagation();
    }

    fn on_mouse_up(&mut self, event: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.pointer_button(event.button, event.position, false);
        cx.stop_propagation();
    }

    fn on_mouse_move(&mut self, event: &MouseMoveEvent, _: &mut Window, _: &mut Context<Self>) {
        let Some((x, y)) = self.remote_point(event.position) else {
            return;
        };
        if let Some(link) = &self.link {
            link.move_pointer(x, y);
        }
    }

    fn on_scroll(&mut self, event: &ScrollEvent, _: &mut Window, cx: &mut Context<Self>) {
        let Some((x, y)) = self.remote_point(event.position) else {
            return;
        };
        if self.is_vnc {
            self.vnc_scroll(event.delta, x, y);
            cx.stop_propagation();
            return;
        }
        // A positive GPUI delta scrolls content downward, which is a wheel
        // toward the user: a negative RDP rotation.
        let (horizontal, raw) = match event.delta {
            ScrollDelta::Lines(delta) if delta.x.abs() > delta.y.abs() => (true, -delta.x),
            ScrollDelta::Lines(delta) => (false, -delta.y),
            ScrollDelta::Pixels(delta) if delta.x.as_f32().abs() > delta.y.as_f32().abs() => {
                (true, -delta.x.as_f32() / 40.)
            }
            ScrollDelta::Pixels(delta) => (false, -delta.y.as_f32() / 40.),
        };
        let units = (raw * 120.).round().clamp(-255., 255.) as i16;
        if units == 0 {
            return;
        }
        self.send_rdp(&[RdpInput::Wheel {
            x,
            y,
            units,
            horizontal,
        }]);
        cx.stop_propagation();
    }

    /// VNC scrolls in whole notches. A trackpad's small steps add up here
    /// until they make one. A positive delta moves the content down, which
    /// is a notch toward the top.
    fn vnc_scroll(&mut self, delta: ScrollDelta, x: u16, y: u16) {
        let (across, down) = match delta {
            ScrollDelta::Lines(delta) => (delta.x, delta.y),
            ScrollDelta::Pixels(delta) => (
                delta.x.as_f32() / PIXELS_PER_NOTCH,
                delta.y.as_f32() / PIXELS_PER_NOTCH,
            ),
        };
        self.wheel_rest.0 += across;
        self.wheel_rest.1 += down;
        let mut inputs = Vec::new();
        for (rest, horizontal) in [
            (&mut self.wheel_rest.1, false),
            (&mut self.wheel_rest.0, true),
        ] {
            let steps = rest.trunc();
            if steps != 0. {
                *rest -= steps;
                inputs.push(VncInput::Wheel {
                    x,
                    y,
                    steps: steps.clamp(-127., 127.) as i16,
                    horizontal,
                });
            }
        }
        self.send_vnc(&inputs);
    }

    fn pointer_button(&mut self, button: MouseButton, position: Point<Pixels>, pressed: bool) {
        let Some(button) = pointer_button(button) else {
            return;
        };
        let Some((x, y)) = self.remote_point(position) else {
            return;
        };
        if let Some(link) = &self.link {
            link.press(x, y, button, pressed);
        }
    }

    fn on_key_down(&mut self, event: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.is_vnc {
            self.vnc_key_down(event, cx);
        } else {
            self.rdp_key_down(event, cx);
        }
    }

    fn on_key_up(&mut self, event: &KeyUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.is_vnc {
            self.vnc_key_up(event, cx);
        } else {
            self.rdp_key_up(event, cx);
        }
    }

    fn rdp_key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        if self.try_paste(&event.keystroke, cx) {
            cx.stop_propagation();
            return;
        }
        let mut inputs = Vec::new();
        if is_modifier_key(&event.keystroke.key) {
            self.offer_clipboard(cx);
            inputs.extend(self.sync_mods(&event.keystroke, true));
            self.send_rdp(&inputs);
            cx.stop_propagation();
            return;
        }
        let named = event.keystroke.key.chars().count() != 1;
        if named {
            if let Some((code, extended)) = scancode(&event.keystroke.key) {
                inputs.extend(self.sync_mods(&event.keystroke, true));
                inputs.push(RdpInput::Scan {
                    code,
                    extended,
                    pressed: true,
                });
                self.held = Some(HeldKey::Scan { code, extended });
                self.send_rdp(&inputs);
                cx.stop_propagation();
            }
            return;
        }
        let chord = event.keystroke.modifiers.control
            || event.keystroke.modifiers.alt
            || event.keystroke.modifiers.platform;
        if !chord {
            if let Some(ch) = typed_char(&event.keystroke) {
                inputs.extend(self.sync_mods(&event.keystroke, false));
                let mut units = [0u16; 2];
                let count = ch.encode_utf16(&mut units).len();
                for unit in units[..count].iter().copied() {
                    inputs.push(RdpInput::Unicode {
                        unit,
                        pressed: true,
                    });
                }
                if let Some(unit) = units[..count].last().copied() {
                    self.held = Some(HeldKey::Unicode(unit));
                }
                self.send_rdp(&inputs);
                cx.stop_propagation();
                return;
            }
        }
        if let Some((code, extended)) = scancode(&event.keystroke.key.to_ascii_lowercase()) {
            inputs.extend(self.sync_mods(&event.keystroke, true));
            inputs.push(RdpInput::Scan {
                code,
                extended,
                pressed: true,
            });
            self.held = Some(HeldKey::Scan { code, extended });
            self.send_rdp(&inputs);
            cx.stop_propagation();
        }
    }

    fn rdp_key_up(&mut self, event: &KeyUpEvent, cx: &mut Context<Self>) {
        let mut inputs = Vec::new();
        if let Some(held) = self.held.take() {
            inputs.push(held.release());
        }
        inputs.extend(self.sync_mods(&event.keystroke, true));
        if !inputs.is_empty() {
            self.send_rdp(&inputs);
            cx.stop_propagation();
        }
    }

    /// Local clipboard, typed in, which works in any remote app. A shared
    /// clipboard also gets the text, for the remote's own paste.
    fn try_paste(&mut self, keystroke: &Keystroke, cx: &Context<Self>) -> bool {
        if keystroke.key != "v" || !is_secondary(&keystroke.modifiers) || keystroke.modifiers.shift
        {
            return false;
        }
        let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) else {
            return true;
        };
        if let Some(link) = self.link.as_ref() {
            link.offer_clipboard(text.clone());
        }
        let mut inputs = self.sync_mods(keystroke, false);
        if let Some(held) = self.held.take() {
            inputs.insert(0, held.release());
        }
        for ch in text.chars() {
            if ch == '\n' || ch == '\r' {
                inputs.push(RdpInput::Scan {
                    code: 0x1C,
                    extended: false,
                    pressed: true,
                });
                inputs.push(RdpInput::Scan {
                    code: 0x1C,
                    extended: false,
                    pressed: false,
                });
                continue;
            }
            if ch == '\t' {
                inputs.push(RdpInput::Scan {
                    code: 0x0F,
                    extended: false,
                    pressed: true,
                });
                inputs.push(RdpInput::Scan {
                    code: 0x0F,
                    extended: false,
                    pressed: false,
                });
                continue;
            }
            let Ok(unit) = u16::try_from(u32::from(ch)) else {
                continue;
            };
            inputs.push(RdpInput::Unicode {
                unit,
                pressed: true,
            });
            inputs.push(RdpInput::Unicode {
                unit,
                pressed: false,
            });
        }
        self.send_rdp(&inputs);
        true
    }

    /// Press or release the modifiers that changed. `shift` is included for a
    /// scancode and left up for a character, which already contains it.
    fn sync_mods(&mut self, keystroke: &Keystroke, include_shift: bool) -> Vec<RdpInput> {
        let want = &keystroke.modifiers;
        let mut inputs = Vec::new();
        sync_one(
            want.control,
            &mut self.mods.control,
            0x1D,
            false,
            &mut inputs,
        );
        sync_one(want.alt, &mut self.mods.alt, 0x38, false, &mut inputs);
        sync_one(want.platform, &mut self.mods.meta, 0x5B, true, &mut inputs);
        if include_shift {
            sync_one(want.shift, &mut self.mods.shift, 0x2A, false, &mut inputs);
        } else if self.mods.shift {
            sync_one(false, &mut self.mods.shift, 0x2A, false, &mut inputs);
        }
        inputs
    }

    /// The modifiers go along as held, shift included: a VNC server reads a
    /// shifted keysym with shift down as the character it names.
    fn vnc_key_down(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        if !self.accepts_input() {
            return;
        }
        let keystroke = &event.keystroke;
        if self.vnc_paste(keystroke, cx) {
            cx.stop_propagation();
            return;
        }
        if is_modifier_key(&keystroke.key) {
            self.offer_clipboard(cx);
            let inputs = self.vnc_sync_mods(&keystroke.modifiers);
            self.send_vnc(&inputs);
            cx.stop_propagation();
            return;
        }
        let Some(keysym) = keysym::for_keystroke(keystroke) else {
            return;
        };
        let mut inputs = self.vnc_sync_mods(&keystroke.modifiers);
        // A key already down is repeating, as the keysym it went down as.
        let keysym = match self.vnc_keys.iter().find(|(key, _)| *key == keystroke.key) {
            Some(&(_, held)) => held,
            None => {
                self.vnc_keys.push((keystroke.key.clone(), keysym));
                keysym
            }
        };
        inputs.push(VncInput::Key {
            keysym,
            pressed: true,
        });
        self.send_vnc(&inputs);
        cx.stop_propagation();
    }

    fn vnc_key_up(&mut self, event: &KeyUpEvent, cx: &mut Context<Self>) {
        if !self.accepts_input() {
            return;
        }
        let mut inputs = Vec::new();
        if let Some(index) = self
            .vnc_keys
            .iter()
            .position(|(key, _)| *key == event.keystroke.key)
        {
            let (_, keysym) = self.vnc_keys.remove(index);
            inputs.push(VncInput::Key {
                keysym,
                pressed: false,
            });
        }
        inputs.extend(self.vnc_sync_mods(&event.keystroke.modifiers));
        if !inputs.is_empty() {
            self.send_vnc(&inputs);
            cx.stop_propagation();
        }
    }

    /// Local clipboard, typed in, as the RDP path does. Every key and
    /// modifier is let go first: the command key behind the paste would
    /// otherwise turn each character into a shortcut.
    fn vnc_paste(&mut self, keystroke: &Keystroke, cx: &Context<Self>) -> bool {
        if keystroke.key != "v" || !is_secondary(&keystroke.modifiers) || keystroke.modifiers.shift
        {
            return false;
        }
        let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) else {
            return true;
        };
        if let Some(link) = self.link.as_ref() {
            link.offer_clipboard(text.clone());
        }
        let mut inputs = self.vnc_release_keys();
        for ch in text.replace("\r\n", "\n").chars() {
            let keysym = match ch {
                '\n' | '\r' => keysym::RETURN,
                '\t' => keysym::TAB,
                ch if ch.is_control() => continue,
                ch => keysym::for_char(ch),
            };
            for pressed in [true, false] {
                inputs.push(VncInput::Key { keysym, pressed });
            }
        }
        self.send_vnc(&inputs);
        true
    }

    fn vnc_sync_mods(&mut self, want: &Modifiers) -> Vec<VncInput> {
        let mut inputs = Vec::new();
        for (wanted, held, keysym) in [
            (want.control, &mut self.mods.control, keysym::CONTROL_L),
            (want.alt, &mut self.mods.alt, keysym::ALT_L),
            (want.platform, &mut self.mods.meta, keysym::SUPER_L),
            (want.shift, &mut self.mods.shift, keysym::SHIFT_L),
        ] {
            if *held != wanted {
                *held = wanted;
                inputs.push(VncInput::Key {
                    keysym,
                    pressed: wanted,
                });
            }
        }
        inputs
    }

    /// Every VNC key and modifier this view holds down, let go.
    fn vnc_release_keys(&mut self) -> Vec<VncInput> {
        let mut inputs: Vec<VncInput> = self
            .vnc_keys
            .drain(..)
            .map(|(_, keysym)| VncInput::Key {
                keysym,
                pressed: false,
            })
            .collect();
        inputs.extend(self.vnc_sync_mods(&Modifiers::default()));
        inputs
    }

    fn watch_focus(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.is_vnc || !self.focus_watch.is_empty() {
            return;
        }
        let blur = cx.on_blur(&self.focus_handle, window, |view, _, _| {
            let inputs = view.vnc_release_keys();
            view.send_vnc(&inputs);
        });
        let activation = cx.observe_window_activation(window, |view, window, _| {
            if !window.is_window_active() {
                let inputs = view.vnc_release_keys();
                view.send_vnc(&inputs);
            }
        });
        self.focus_watch = vec![blur, activation];
    }
}

fn sync_one(want: bool, held: &mut bool, code: u8, extended: bool, inputs: &mut Vec<RdpInput>) {
    if *held == want {
        return;
    }
    *held = want;
    inputs.push(RdpInput::Scan {
        code,
        extended,
        pressed: want,
    });
}

impl Focusable for DesktopView {
    fn focus_handle(&self, _cx: &gpui::App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for DesktopView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if let Some(old) = self.retired.take() {
            let _ = window.drop_image(old);
        }
        self.watch_focus(window, cx);
        let bounds = self.layout.get();
        if bounds.size.width > px(0.) && bounds.size.height > px(0.) {
            self.note_layout(bounds, window, cx);
        }
        let layout = self.layout.clone();
        let image = self.image.clone();
        let frame = self.frame.as_ref().map(|frame| (frame.width, frame.height));
        div()
            .id("remote-desktop")
            .track_focus(&self.focus_handle)
            .size_full()
            .bg(gpui::rgb(0x000000))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_down(MouseButton::Right, cx.listener(Self::on_mouse_down))
            .on_mouse_down(MouseButton::Middle, cx.listener(Self::on_mouse_down))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up(MouseButton::Right, cx.listener(Self::on_mouse_up))
            .on_mouse_up(MouseButton::Middle, cx.listener(Self::on_mouse_up))
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .on_scroll(cx.listener(Self::on_scroll))
            .on_key_down(cx.listener(Self::on_key_down))
            .on_key_up(cx.listener(Self::on_key_up))
            .child(
                canvas(
                    move |bounds, _, _| layout.set(bounds),
                    move |bounds, _, window, _| {
                        let Some(image) = image.clone() else {
                            return;
                        };
                        let Some((width, height)) = frame else {
                            return;
                        };
                        let Some(placed) = letterbox(bounds, width, height) else {
                            return;
                        };
                        let _ =
                            window.paint_image(bounds, placed, Corners::default(), image, 0, false);
                    },
                )
                .size_full(),
            )
    }
}

fn raster(frame: &DesktopFrame) -> Option<Arc<RenderImage>> {
    let buffer = RgbaImage::from_raw(frame.width, frame.height, frame.bgra.as_ref().clone())?;
    Some(Arc::new(RenderImage::new(smallvec![Frame::new(buffer)])))
}

fn desktop_pixels(value: f32) -> u16 {
    value.round().clamp(MIN_DESKTOP, MAX_DESKTOP) as u16
}

/// The desktop, fitted inside `bounds` without stretching.
fn letterbox(bounds: Bounds<Pixels>, width: u32, height: u32) -> Option<Bounds<Pixels>> {
    if width == 0 || height == 0 || bounds.size.width <= px(0.) || bounds.size.height <= px(0.) {
        return None;
    }
    let scale = (bounds.size.width.as_f32() / width as f32)
        .min(bounds.size.height.as_f32() / height as f32);
    if scale <= 0. {
        return None;
    }
    let placed_w = width as f32 * scale;
    let placed_h = height as f32 * scale;
    Some(Bounds {
        origin: point(
            bounds.origin.x + px((bounds.size.width.as_f32() - placed_w) / 2.),
            bounds.origin.y + px((bounds.size.height.as_f32() - placed_h) / 2.),
        ),
        size: gpui::size(px(placed_w), px(placed_h)),
    })
}

fn pointer_button(button: MouseButton) -> Option<PointerButton> {
    match button {
        MouseButton::Left => Some(PointerButton::Left),
        MouseButton::Right => Some(PointerButton::Right),
        MouseButton::Middle => Some(PointerButton::Middle),
        MouseButton::Navigate(_) => None,
    }
}

fn is_modifier_key(key: &str) -> bool {
    matches!(
        key,
        "control"
            | "ctrl"
            | "alt"
            | "shift"
            | "function"
            | "fn"
            | "platform"
            | "cmd"
            | "super"
            | "win"
            | "meta"
    )
}

fn typed_char(keystroke: &Keystroke) -> Option<char> {
    let text = keystroke.key_char.as_deref()?;
    let mut chars = text.chars();
    let ch = chars.next()?;
    if chars.next().is_some() || ch.is_control() {
        return None;
    }
    Some(ch)
}

/// Set 1 scancode, and whether the extended flag goes with it.
fn scancode(key: &str) -> Option<(u8, bool)> {
    let (code, extended) = match key {
        "escape" => (0x01, false),
        "1" => (0x02, false),
        "2" => (0x03, false),
        "3" => (0x04, false),
        "4" => (0x05, false),
        "5" => (0x06, false),
        "6" => (0x07, false),
        "7" => (0x08, false),
        "8" => (0x09, false),
        "9" => (0x0A, false),
        "0" => (0x0B, false),
        "-" => (0x0C, false),
        "=" => (0x0D, false),
        "backspace" => (0x0E, false),
        "tab" => (0x0F, false),
        "q" => (0x10, false),
        "w" => (0x11, false),
        "e" => (0x12, false),
        "r" => (0x13, false),
        "t" => (0x14, false),
        "y" => (0x15, false),
        "u" => (0x16, false),
        "i" => (0x17, false),
        "o" => (0x18, false),
        "p" => (0x19, false),
        "[" => (0x1A, false),
        "]" => (0x1B, false),
        "enter" | "return" => (0x1C, false),
        "a" => (0x1E, false),
        "s" => (0x1F, false),
        "d" => (0x20, false),
        "f" => (0x21, false),
        "g" => (0x22, false),
        "h" => (0x23, false),
        "j" => (0x24, false),
        "k" => (0x25, false),
        "l" => (0x26, false),
        ";" => (0x27, false),
        "'" => (0x28, false),
        "`" => (0x29, false),
        "\\" => (0x2B, false),
        "z" => (0x2C, false),
        "x" => (0x2D, false),
        "c" => (0x2E, false),
        "v" => (0x2F, false),
        "b" => (0x30, false),
        "n" => (0x31, false),
        "m" => (0x32, false),
        "," => (0x33, false),
        "." => (0x34, false),
        "/" => (0x35, false),
        "space" => (0x39, false),
        "f1" => (0x3B, false),
        "f2" => (0x3C, false),
        "f3" => (0x3D, false),
        "f4" => (0x3E, false),
        "f5" => (0x3F, false),
        "f6" => (0x40, false),
        "f7" => (0x41, false),
        "f8" => (0x42, false),
        "f9" => (0x43, false),
        "f10" => (0x44, false),
        "f11" => (0x57, false),
        "f12" => (0x58, false),
        "up" => (0x48, true),
        "down" => (0x50, true),
        "left" => (0x4B, true),
        "right" => (0x4D, true),
        "home" => (0x47, true),
        "end" => (0x4F, true),
        "pageup" => (0x49, true),
        "pagedown" => (0x51, true),
        "insert" => (0x52, true),
        "delete" => (0x53, true),
        _ => return None,
    };
    Some((code, extended))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrows_are_extended_scancodes() {
        assert_eq!(scancode("up"), Some((0x48, true)));
        assert_eq!(scancode("enter"), Some((0x1C, false)));
        assert_eq!(scancode("c"), Some((0x2E, false)));
    }

    #[test]
    fn letterbox_centers_a_wide_desktop() {
        let bounds = Bounds {
            origin: point(px(0.), px(0.)),
            size: gpui::size(px(200.), px(100.)),
        };
        let placed = letterbox(bounds, 200, 50).unwrap();
        assert!((placed.size.width.as_f32() - 200.).abs() < 0.1);
        assert!((placed.size.height.as_f32() - 50.).abs() < 0.1);
        assert!((placed.origin.y.as_f32() - 25.).abs() < 0.1);
    }
}
