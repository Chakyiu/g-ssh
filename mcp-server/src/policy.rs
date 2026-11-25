//! Unattended answers for prompts the SSH handshake cannot skip.
//!
//! Stdio is the MCP protocol, so this process has no second channel for a
//! person to approve a key or type a one-time code. Unknown and changed keys
//! are refused. Keyboard-interactive auth is cancelled.

use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostKeyAnswer {
    pub accept: bool,
    pub reason: &'static str,
}

pub const fn host_key_answer(stored_fingerprint: Option<&str>) -> HostKeyAnswer {
    match stored_fingerprint {
        Some(_) => HostKeyAnswer {
            accept: false,
            reason: "host key does not match the vault or known_hosts record",
        },
        None => HostKeyAnswer {
            accept: false,
            reason: "host key is not in the vault or known_hosts; refusing instead of trusting on first use",
        },
    }
}

const REFUSE_UNKNOWN: HostKeyAnswer = host_key_answer(None);
const REFUSE_CHANGED: HostKeyAnswer = host_key_answer(Some("SHA256:recorded"));
const _: () = assert!(!REFUSE_UNKNOWN.accept && !REFUSE_CHANGED.accept);

/// `None` cancels keyboard-interactive auth. There is no answer vector.
pub fn auth_prompt_reply() -> Option<Vec<Zeroizing<String>>> {
    None
}

/// Local `-L` binds. Anything else would listen beyond this machine.
pub fn loopback_bind(address: Option<&str>) -> Result<String, String> {
    let address = match address {
        Some(address) if !address.is_empty() => address,
        Some(_) => return Err("bind address is empty".into()),
        None => "127.0.0.1",
    };
    if !gssh::ssh::connection::is_loopback_bind(address) {
        return Err(format!(
            "bind address {address} is not loopback; local forwards listen on loopback only"
        ));
    }
    Ok(address.to_string())
}

pub fn command_error(command: &str) -> Option<String> {
    if command.is_empty() || command.chars().all(char::is_whitespace) {
        return Some("command is empty".into());
    }
    if command.as_bytes().contains(&0) {
        return Some("command contains a NUL byte".into());
    }
    if command.len() > MAX_COMMAND_BYTES {
        return Some(format!(
            "command is {} bytes; the limit is {MAX_COMMAND_BYTES}",
            command.len()
        ));
    }
    None
}

/// shortcut: 16 KiB command cap, raise it if a real saved snippet exceeds it
const MAX_COMMAND_BYTES: usize = 16 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_changed_host_keys_are_refused() {
        let unknown = host_key_answer(None);
        let changed = host_key_answer(Some("SHA256:old"));
        assert!(!unknown.accept);
        assert!(!changed.accept);
        assert!(unknown.reason.contains("first use"));
        assert!(changed.reason.contains("does not match"));
        assert_ne!(unknown.reason, changed.reason);
    }

    #[test]
    fn keyboard_interactive_prompts_are_cancelled() {
        assert!(auth_prompt_reply().is_none());
    }

    #[test]
    fn forwards_bind_on_loopback_only() {
        assert_eq!(loopback_bind(None).unwrap(), "127.0.0.1");
        assert_eq!(loopback_bind(Some("localhost")).unwrap(), "localhost");
        assert_eq!(loopback_bind(Some("::1")).unwrap(), "::1");
        assert!(loopback_bind(Some("0.0.0.0")).is_err());
        assert!(loopback_bind(Some("192.168.1.10")).is_err());
        assert!(loopback_bind(Some("")).is_err());
    }

    #[test]
    fn commands_must_be_non_empty_and_bounded() {
        assert!(command_error("").is_some());
        assert!(command_error(" \n").is_some());
        assert!(command_error("echo ok\0").is_some());
        assert!(command_error("uname -a").is_none());
        let huge = "a".repeat(MAX_COMMAND_BYTES + 1);
        assert!(command_error(&huge).is_some());
    }
}
