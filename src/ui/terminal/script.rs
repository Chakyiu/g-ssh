//! Specials inside a command that is typed into a shell.
//!
//! Plain text is sent as keystrokes. A `{name}` the shell would otherwise
//! see is handled here instead: `{sleep 1}` waits, `{enter}` presses Enter.
//! Anything in braces that is not one of these is typed as written.

use std::time::Duration;

/// One thing to do while typing a command.
pub(crate) enum ScriptStep {
    /// Bytes to write to the shell, in order.
    Type(Vec<u8>),
    /// Pause before the next keystrokes. Capped at 60 seconds.
    Sleep(Duration),
}

/// Turn `content` into keystrokes and pauses.
///
/// A command that does not already end on Enter gets one, so `cd /app` runs.
/// A script that is only a pause does not.
pub(crate) fn script_steps(content: &str) -> Vec<ScriptStep> {
    let mut steps = Vec::new();
    let mut buf = String::new();
    let mut rest = content;
    while let Some(open) = rest.find('{') {
        buf.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let body = &after[..close];
            if !body.contains('\n') {
                if let Some(step) = parse_token(body) {
                    push_text(&mut steps, &mut buf);
                    steps.push(step);
                    rest = &after[close + 1..];
                    continue;
                }
            }
        }
        buf.push('{');
        rest = after;
    }
    buf.push_str(rest);
    push_text(&mut steps, &mut buf);
    submit_if_needed(&mut steps);
    steps
}

fn push_text(steps: &mut Vec<ScriptStep>, buf: &mut String) {
    if buf.is_empty() {
        return;
    }
    let text = std::mem::take(buf);
    if let Some(ScriptStep::Type(bytes)) = steps.last_mut() {
        bytes.extend(text.into_bytes());
    } else {
        steps.push(ScriptStep::Type(text.into_bytes()));
    }
}

/// Press Enter when the typed text would otherwise sit on the line.
fn submit_if_needed(steps: &mut Vec<ScriptStep>) {
    let ends_with_enter = steps.iter().rev().find_map(|step| match step {
        ScriptStep::Type(bytes) if !bytes.is_empty() => {
            Some(matches!(bytes.last(), Some(b'\n' | b'\r')))
        }
        _ => None,
    });
    if ends_with_enter == Some(false) {
        steps.push(ScriptStep::Type(vec![b'\r']));
    }
}

fn parse_token(body: &str) -> Option<ScriptStep> {
    let body = body.trim();
    if body.is_empty() {
        return None;
    }
    let lower = body.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("sleep") {
        let rest = rest.trim();
        if rest.is_empty() {
            return None;
        }
        return Some(ScriptStep::Sleep(parse_sleep(rest)?));
    }
    if let Some(byte) = control_byte(&lower) {
        return Some(ScriptStep::Type(vec![byte]));
    }
    let key = match lower.as_str() {
        "enter" | "cr" | "return" => b'\r',
        "tab" => b'\t',
        "esc" | "escape" => 0x1b,
        "space" => b' ',
        "bs" | "backspace" => 0x7f,
        "up" => return Some(arrow(b'A')),
        "down" => return Some(arrow(b'B')),
        "right" => return Some(arrow(b'C')),
        "left" => return Some(arrow(b'D')),
        _ => return None,
    };
    Some(ScriptStep::Type(vec![key]))
}

fn arrow(letter: u8) -> ScriptStep {
    ScriptStep::Type(vec![0x1b, b'[', letter])
}

/// `{ctrl-c}`, `{ctrl c}`, `{ctrl+c}` and `{^c}`.
fn control_byte(lower: &str) -> Option<u8> {
    let rest = lower
        .strip_prefix("ctrl")
        .or_else(|| lower.strip_prefix('^'))?;
    let rest = rest.trim_start_matches(['-', '+', ' ']);
    let mut chars = rest.chars();
    let ch = chars.next()?.to_ascii_lowercase();
    if chars.next().is_some() {
        return None;
    }
    match ch {
        'a'..='z' => Some(ch as u8 - b'a' + 1),
        _ => None,
    }
}

/// A bare number is seconds. `ms` and `s` name the unit. Above 60 seconds
/// waits 60: a typo must not pause the session for hours.
fn parse_sleep(raw: &str) -> Option<Duration> {
    let raw = raw.trim();
    let (number, millis_each) = if let Some(number) = raw.strip_suffix("ms") {
        (number.trim(), 1.0)
    } else if let Some(number) = raw.strip_suffix('s') {
        (number.trim(), 1000.0)
    } else {
        (raw, 1000.0)
    };
    let value: f64 = number.parse().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    let millis = (value * millis_each).round().min(60_000.0);
    Some(Duration::from_millis(millis as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(steps: &[ScriptStep]) -> Vec<u8> {
        let mut out = Vec::new();
        for step in steps {
            if let ScriptStep::Type(bytes) = step {
                out.extend(bytes);
            }
        }
        out
    }

    fn sleeps(steps: &[ScriptStep]) -> Vec<u64> {
        steps
            .iter()
            .filter_map(|step| match step {
                ScriptStep::Sleep(duration) => Some(duration.as_millis() as u64),
                ScriptStep::Type(_) => None,
            })
            .collect()
    }

    #[test]
    fn a_plain_command_is_typed_and_submitted() {
        let steps = script_steps("cd /srv/app");
        assert_eq!(typed(&steps), b"cd /srv/app\r");
        assert!(sleeps(&steps).is_empty());
    }

    #[test]
    fn a_line_that_already_ends_is_not_submitted_again() {
        assert_eq!(typed(&script_steps("cd /srv/app\n")), b"cd /srv/app\n");
    }

    #[test]
    fn sleep_waits_before_the_next_keys() {
        let steps = script_steps("{sleep 1}\ncd /srv/app");
        assert!(matches!(steps[0], ScriptStep::Sleep(_)));
        assert_eq!(sleeps(&steps), vec![1000]);
        assert_eq!(typed(&steps), b"\ncd /srv/app\r");
    }

    #[test]
    fn sleep_after_text_submits_after_the_pause() {
        let steps = script_steps("cd /app{sleep 1}");
        assert!(matches!(steps[0], ScriptStep::Type(_)));
        assert!(matches!(steps[1], ScriptStep::Sleep(_)));
        assert!(matches!(&steps[2], ScriptStep::Type(bytes) if bytes == b"\r"));
    }

    #[test]
    fn sleep_units() {
        assert_eq!(sleeps(&script_steps("{sleep 500ms}x")), vec![500]);
        assert_eq!(sleeps(&script_steps("{sleep 1.5}x")), vec![1500]);
        assert_eq!(sleeps(&script_steps("{sleep 2s}x")), vec![2000]);
        assert_eq!(sleeps(&script_steps("{sleep 120}x")), vec![60_000]);
    }

    #[test]
    fn a_pause_on_its_own_does_not_press_enter() {
        let steps = script_steps("{sleep 1}");
        assert_eq!(sleeps(&steps), vec![1000]);
        assert!(typed(&steps).is_empty());
    }

    #[test]
    fn unknown_braces_are_typed() {
        assert_eq!(typed(&script_steps("echo {hi}")), b"echo {hi}\r");
        assert_eq!(typed(&script_steps("{sleep}")), b"{sleep}\r");
        assert_eq!(typed(&script_steps("{sleep abc}")), b"{sleep abc}\r");
    }

    #[test]
    fn keys() {
        assert_eq!(typed(&script_steps("a{enter}b")), b"a\rb\r");
        assert_eq!(typed(&script_steps("{tab}")), b"\t\r");
        assert_eq!(typed(&script_steps("{esc}")), b"\x1b\r");
        assert_eq!(typed(&script_steps("{ctrl-c}")), b"\x03\r");
        assert_eq!(typed(&script_steps("{ctrl+d}")), b"\x04\r");
        assert_eq!(typed(&script_steps("{^z}")), b"\x1a\r");
        assert_eq!(typed(&script_steps("{up}")), b"\x1b[A\r");
    }
}
