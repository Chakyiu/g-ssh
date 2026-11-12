//! X11 keysyms, which is how VNC names keys: a typed character by its own
//! code, a named key such as Enter by a fixed number.

use gpui::Keystroke;

pub(super) const SHIFT_L: u32 = 0xffe1;
pub(super) const CONTROL_L: u32 = 0xffe3;
pub(super) const ALT_L: u32 = 0xffe9;
pub(super) const SUPER_L: u32 = 0xffeb;
pub(super) const RETURN: u32 = 0xff0d;
pub(super) const TAB: u32 = 0xff09;

/// The keysym a key goes down as. A named key comes from the table. With no
/// shortcut modifier it is the character typed, so the remote gets the same
/// text whatever its keyboard layout. With one it is the key itself, upper
/// case under shift, so the shortcut reaches the remote.
pub(super) fn for_keystroke(keystroke: &Keystroke) -> Option<u32> {
    if let Some(keysym) = named(&keystroke.key) {
        return Some(keysym);
    }
    let modifiers = &keystroke.modifiers;
    if !(modifiers.control || modifiers.alt || modifiers.platform) {
        if let Some(ch) = super::typed_char(keystroke) {
            return Some(for_char(ch));
        }
    }
    let mut chars = keystroke.key.chars();
    let ch = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    Some(for_char(if modifiers.shift {
        ch.to_ascii_uppercase()
    } else {
        ch
    }))
}

/// Latin-1 keysyms are the character code. Anything else is the Unicode
/// keysym range, which servers map to a key on the fly.
pub(super) fn for_char(ch: char) -> u32 {
    let code = u32::from(ch);
    match code {
        0x20..=0x7e | 0xa0..=0xff => code,
        _ => 0x0100_0000 | code,
    }
}

fn named(key: &str) -> Option<u32> {
    let keysym = match key {
        "escape" => 0xff1b,
        "backspace" => 0xff08,
        "tab" => TAB,
        "enter" | "return" => RETURN,
        "space" => 0x0020,
        "delete" => 0xffff,
        "insert" => 0xff63,
        "home" => 0xff50,
        "end" => 0xff57,
        "pageup" => 0xff55,
        "pagedown" => 0xff56,
        "left" => 0xff51,
        "up" => 0xff52,
        "right" => 0xff53,
        "down" => 0xff54,
        "menu" => 0xff67,
        _ => return function_key(key),
    };
    Some(keysym)
}

/// F1 is 0xffbe and the rest follow it, up to F24.
fn function_key(key: &str) -> Option<u32> {
    let number: u32 = key.strip_prefix('f')?.parse().ok()?;
    (1..=24).contains(&number).then(|| 0xffbe + number - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keystroke(text: &'static str) -> Keystroke {
        Keystroke::parse(text).unwrap()
    }

    #[test]
    fn named_keys_and_function_keys() {
        assert_eq!(for_keystroke(&keystroke("enter")), Some(RETURN));
        assert_eq!(for_keystroke(&keystroke("up")), Some(0xff52));
        assert_eq!(for_keystroke(&keystroke("f1")), Some(0xffbe));
        assert_eq!(for_keystroke(&keystroke("f12")), Some(0xffc9));
        assert_eq!(for_keystroke(&keystroke("f25")), None);
    }

    #[test]
    fn a_shortcut_sends_the_key_itself() {
        assert_eq!(for_keystroke(&keystroke("ctrl-c")), Some(u32::from(b'c')));
        assert_eq!(
            for_keystroke(&keystroke("ctrl-shift-t")),
            Some(u32::from(b'T'))
        );
        assert_eq!(for_keystroke(&keystroke("alt-tab")), Some(TAB));
    }

    #[test]
    fn characters_outside_latin1_use_the_unicode_range() {
        assert_eq!(for_char('a'), 0x61);
        assert_eq!(for_char('é'), 0xe9);
        assert_eq!(for_char('中'), 0x0100_4e2d);
        assert_eq!(for_char('€'), 0x0100_20ac);
    }
}
