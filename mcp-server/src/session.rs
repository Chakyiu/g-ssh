//! One SSH session per saved host. The event task is the only reader of the
//! connection's event channel, so a prompt is always answered.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gssh::ssh::connection::{ForwardKind, ForwardSpec};
use gssh::ssh::{ForwardState, SshConnection, SshConnectionEvent};
use serde::Serialize;
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::hosts;
use crate::policy;

const DEFAULT_CONNECT_SECS: u64 = 90;
const DEFAULT_EXEC_SECS: u64 = 60;
const DEFAULT_FORWARD_SECS: u64 = 20;
const FORWARD_POLL: Duration = Duration::from_millis(50);
/// shortcut: 256 KiB per stream, raise MAX_CAPTURE if a caller needs the full output
const MAX_CAPTURE: usize = 256 * 1024;

pub struct App {
    vault: Mutex<gssh::vault::VaultManager>,
    sessions: Mutex<HashMap<Uuid, SessionSlot>>,
    gate: tokio::sync::Mutex<()>,
    connect_timeout: Duration,
    exec_timeout: Duration,
    forward_timeout: Duration,
}

struct SessionSlot {
    live: LiveSession,
    task: JoinHandle<()>,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct LiveSession {
    conn: SshConnection,
    alive: Arc<AtomicBool>,
    forwards: Arc<Mutex<HashMap<String, ForwardState>>>,
    hops: Arc<Vec<String>>,
}

impl App {
    pub fn new(vault: gssh::vault::VaultManager) -> Result<Self, String> {
        if let Err(error) = gssh::mcp_audit::prune() {
            tracing::warn!(%error, "mcp audit log was not pruned");
        }
        Ok(Self {
            vault: Mutex::new(vault),
            sessions: Mutex::new(HashMap::new()),
            gate: tokio::sync::Mutex::new(()),
            connect_timeout: timeout_from_env(
                "GSSH_MCP_CONNECT_TIMEOUT_SECS",
                DEFAULT_CONNECT_SECS,
            )?,
            exec_timeout: timeout_from_env("GSSH_MCP_EXEC_TIMEOUT_SECS", DEFAULT_EXEC_SECS)?,
            forward_timeout: timeout_from_env(
                "GSSH_MCP_FORWARD_TIMEOUT_SECS",
                DEFAULT_FORWARD_SECS,
            )?,
        })
    }

    pub fn list_hosts(&self) -> Result<String, String> {
        let vault = self.vault.lock().unwrap();
        hosts::list_json(&vault)
    }

    pub async fn exec(&self, host: &str, command: &str) -> Result<String, String> {
        if let Some(error) = policy::command_error(command) {
            return Err(error);
        }
        let live = self.session_for(host).await?;
        tracing::info!(hops = live.hops.len(), bytes = command.len(), "ssh_exec");
        let captured = live
            .conn
            .open_exec_captured(command.to_string())
            .await
            .map_err(|e| e.to_string())?;
        let report = collect_exec(captured, self.exec_timeout, &live.hops).await?;
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())
    }

    pub async fn start_forward(
        &self,
        host: &str,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
        bind_address: Option<&str>,
    ) -> Result<String, String> {
        if local_port == 0 || remote_port == 0 {
            return Err("local_port and remote_port must be non-zero".into());
        }
        let remote_host = remote_host.trim();
        if remote_host.is_empty() {
            return Err("remote_host is empty".into());
        }
        let bind_address = policy::loopback_bind(bind_address)?;
        let live = self.session_for(host).await?;
        let id = Uuid::new_v4().to_string();
        let spec = ForwardSpec {
            id: id.clone(),
            kind: ForwardKind::Local,
            bind_address,
            bind_port: local_port,
            target_host: remote_host.to_string(),
            target_port: remote_port,
        };
        tracing::info!(%id, local_port, "start_forward");
        live.conn.start_forward(spec).await;
        let state = wait_forward(&live, &id, self.forward_timeout).await?;
        match state {
            ForwardState::Bound { bound_port, active } => {
                let report = ForwardReport {
                    forward_id: id,
                    bound_port,
                    active,
                    hops: (*live.hops).clone(),
                };
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())
            }
            ForwardState::Stopped { reason } => {
                Err(reason.unwrap_or_else(|| "forward stopped".into()))
            }
        }
    }

    pub async fn stop_forward(&self, forward_id: &str) -> Result<String, String> {
        let forward_id = forward_id.trim();
        if forward_id.is_empty() {
            return Err("forward_id is empty".into());
        }
        let live = {
            let sessions = self.sessions.lock().unwrap();
            sessions
                .values()
                .find(|slot| slot.live.forwards.lock().unwrap().contains_key(forward_id))
                .map(|slot| slot.live.clone())
        };
        let Some(live) = live else {
            return Err(format!("no running forward {forward_id}"));
        };
        live.forwards.lock().unwrap().remove(forward_id);
        live.conn.stop_forward(forward_id.to_string()).await;
        wait_stopped(&live, forward_id, self.forward_timeout).await?;
        serde_json::to_string_pretty(&StopReport {
            forward_id: forward_id.to_string(),
            stopped: true,
        })
        .map_err(|e| e.to_string())
    }

    async fn session_for(&self, host: &str) -> Result<LiveSession, String> {
        let _gate = self.gate.lock().await;
        let id = {
            let vault = self.vault.lock().unwrap();
            hosts::find_host(&vault, host)?
        };
        if let Some(live) = self.take_alive(id) {
            return Ok(live);
        }
        let route = {
            let vault = self.vault.lock().unwrap();
            hosts::prepare_route(&vault, id)?
        };
        let hops: Arc<Vec<String>> = Arc::new(
            route
                .hops()
                .map(|hop| hop.display_name().to_string())
                .collect(),
        );
        tracing::info!(hops = hops.len(), "connecting");
        let (live, task) = connect_route(route, hops, self.connect_timeout).await?;
        self.sessions.lock().unwrap().insert(
            id,
            SessionSlot {
                live: live.clone(),
                task,
            },
        );
        Ok(live)
    }

    fn take_alive(&self, id: Uuid) -> Option<LiveSession> {
        let mut sessions = self.sessions.lock().unwrap();
        let alive = sessions
            .get(&id)
            .is_some_and(|slot| slot.live.alive.load(Ordering::SeqCst));
        if alive {
            Some(sessions.get(&id).unwrap().live.clone())
        } else {
            sessions.remove(&id);
            None
        }
    }
}

fn timeout_from_env(name: &str, default: u64) -> Result<Duration, String> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => parse_timeout(None, name, default),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is not valid Unicode")),
        Ok(value) => parse_timeout(Some(&value), name, default),
    }
}

fn parse_timeout(value: Option<&str>, name: &str, default: u64) -> Result<Duration, String> {
    let Some(value) = value else {
        return Ok(Duration::from_secs(default));
    };
    let secs: u64 = value
        .parse()
        .map_err(|_| format!("{name} must be a number of seconds, got {value}"))?;
    if secs == 0 || secs > 3600 {
        return Err(format!("{name} must be between 1 and 3600"));
    }
    Ok(Duration::from_secs(secs))
}

async fn connect_route(
    route: gssh::ssh::SshRoute,
    hops: Arc<Vec<String>>,
    timeout: Duration,
) -> Result<(LiveSession, JoinHandle<()>), String> {
    let conn = SshConnection::spawn(route);
    let events = conn.subscribe_events();
    let alive = Arc::new(AtomicBool::new(true));
    let forwards = Arc::new(Mutex::new(HashMap::new()));
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = spawn_reader(events, Arc::clone(&alive), Arc::clone(&forwards), tx);
    let live = LiveSession {
        conn,
        alive,
        forwards,
        hops,
    };
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(Ok(()))) => Ok((live, task)),
        Ok(Ok(Err(error))) => {
            task.abort();
            drop(live);
            Err(error)
        }
        Ok(Err(_)) => {
            task.abort();
            drop(live);
            Err("connection task ended before the session was ready".into())
        }
        Err(_) => {
            task.abort();
            drop(live);
            Err(format!("timed out connecting after {}s", timeout.as_secs()))
        }
    }
}

fn spawn_reader(
    events: async_channel::Receiver<SshConnectionEvent>,
    alive: Arc<AtomicBool>,
    forwards: Arc<Mutex<HashMap<String, ForwardState>>>,
    tx: tokio::sync::oneshot::Sender<Result<(), String>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let mut denied: Option<String> = None;
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(_) => {
                    fail(&alive, &mut tx, denied.take(), "connection closed");
                    break;
                }
            };
            match event {
                SshConnectionEvent::Connected => {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(Ok(()));
                    }
                }
                SshConnectionEvent::AuthFailed { entry_id, error } => {
                    let fallback = format!("authentication failed for {entry_id}: {error}");
                    fail(&alive, &mut tx, denied.take(), &fallback);
                    break;
                }
                SshConnectionEvent::Disconnected => {
                    fail(&alive, &mut tx, denied.take(), "connection closed");
                    break;
                }
                SshConnectionEvent::HostKeyPrompt(prompt) => {
                    let answer = policy::host_key_answer(prompt.stored_fingerprint.as_deref());
                    debug_assert!(!answer.accept);
                    let detail = format!(
                        "{}. presented {} {}",
                        answer.reason, prompt.key_type, prompt.fingerprint
                    );
                    let _ = prompt.reply.send(answer.accept);
                    if denied.is_none() {
                        denied = Some(detail);
                    }
                }
                SshConnectionEvent::AuthPrompt(prompt) => {
                    let _ = prompt.reply.send(policy::auth_prompt_reply());
                    if denied.is_none() {
                        let which = if prompt.name.is_empty() {
                            "the server".to_string()
                        } else {
                            format!("'{}'", prompt.name)
                        };
                        denied = Some(format!(
                            "keyboard-interactive prompt from {which} was denied; there is no attendant on this server"
                        ));
                    }
                }
                SshConnectionEvent::HostKeyTrusted {
                    entry_id,
                    fingerprint,
                } => {
                    tracing::info!(
                        entry_id,
                        fingerprint,
                        "host key matched known_hosts; fingerprint was not written to the vault"
                    );
                }
                SshConnectionEvent::ForwardChanged { id, state } => {
                    forwards.lock().unwrap().insert(id, state);
                }
            }
        }
    })
}

fn fail(
    alive: &AtomicBool,
    tx: &mut Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
    denied: Option<String>,
    fallback: &str,
) {
    alive.store(false, Ordering::SeqCst);
    if let Some(tx) = tx.take() {
        let _ = tx.send(Err(denied.unwrap_or_else(|| fallback.to_string())));
    }
}

async fn wait_forward(
    live: &LiveSession,
    id: &str,
    timeout: Duration,
) -> Result<ForwardState, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(state) = live.forwards.lock().unwrap().get(id).cloned() {
            return Ok(state);
        }
        if !live.alive.load(Ordering::SeqCst) {
            return Err("connection closed before the forward reported state".into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("timed out waiting for forward {id}"));
        }
        tokio::time::sleep(FORWARD_POLL).await;
    }
}

async fn wait_stopped(live: &LiveSession, id: &str, timeout: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if matches!(
            live.forwards.lock().unwrap().get(id),
            Some(ForwardState::Stopped { .. })
        ) {
            return Ok(());
        }
        if !live.alive.load(Ordering::SeqCst) {
            return Err("connection closed while stopping the forward".into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("timed out stopping forward {id}"));
        }
        tokio::time::sleep(FORWARD_POLL).await;
    }
}

#[derive(Serialize)]
struct ExecReport {
    exit_code: Option<u32>,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    hops: Vec<String>,
}

#[derive(Serialize)]
struct ForwardReport {
    forward_id: String,
    bound_port: u16,
    active: u32,
    hops: Vec<String>,
}

#[derive(Serialize)]
struct StopReport {
    forward_id: String,
    stopped: bool,
}

async fn collect_exec(
    exec: gssh::ssh::CapturedExec,
    timeout: Duration,
    hops: &[String],
) -> Result<ExecReport, String> {
    let stdout_rx = exec.stdout();
    let stderr_rx = exec.stderr();
    let exit_rx = exec.exit_status();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;
    let mut exit_code = None;
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut exit_open = true;
    let sleep = tokio::time::sleep(timeout);
    tokio::pin!(sleep);
    while stdout_open || stderr_open || exit_open {
        tokio::select! {
            chunk = stdout_rx.recv(), if stdout_open => match chunk {
                Ok(bytes) => {
                    if push_capped(&mut stdout, &bytes, MAX_CAPTURE) {
                        stdout_truncated = true;
                    }
                }
                Err(_) => stdout_open = false,
            },
            chunk = stderr_rx.recv(), if stderr_open => match chunk {
                Ok(bytes) => {
                    if push_capped(&mut stderr, &bytes, MAX_CAPTURE) {
                        stderr_truncated = true;
                    }
                }
                Err(_) => stderr_open = false,
            },
            code = exit_rx.recv(), if exit_open => match code {
                Ok(code) => {
                    exit_code = Some(code);
                    exit_open = false;
                }
                Err(_) => exit_open = false,
            },
            _ = &mut sleep => {
                return Err(format!(
                    "command timed out after {}s",
                    timeout.as_secs()
                ));
            }
        }
    }
    Ok(ExecReport {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        stdout_truncated,
        stderr_truncated,
        hops: hops.to_vec(),
    })
}

fn push_capped(buf: &mut Vec<u8>, chunk: &[u8], cap: usize) -> bool {
    if buf.len() >= cap {
        return true;
    }
    let room = cap - buf.len();
    if chunk.len() > room {
        buf.extend_from_slice(&chunk[..room]);
        true
    } else {
        buf.extend_from_slice(chunk);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_stops_at_the_cap_and_keeps_the_prefix() {
        let mut buf = Vec::new();
        assert!(!push_capped(&mut buf, b"hello", 8));
        assert!(push_capped(&mut buf, b"world", 8));
        assert_eq!(buf, b"hellowor");
        assert!(push_capped(&mut buf, b"!", 8));
        assert_eq!(buf, b"hellowor");
    }

    #[test]
    fn timeout_parser_uses_the_default_or_rejects_junk() {
        assert_eq!(
            parse_timeout(None, "GSSH_MCP_CONNECT_TIMEOUT_SECS", 12).unwrap(),
            Duration::from_secs(12)
        );
        assert_eq!(
            parse_timeout(Some("30"), "GSSH_MCP_CONNECT_TIMEOUT_SECS", 12).unwrap(),
            Duration::from_secs(30)
        );
        assert!(parse_timeout(Some("0"), "limit", 12).is_err());
        assert!(parse_timeout(Some("nope"), "limit", 12).is_err());
        assert!(parse_timeout(Some("9999"), "limit", 12).is_err());
    }
}
