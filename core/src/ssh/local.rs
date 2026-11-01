//! A shell on this computer, driven through the same emulator as an SSH session.
//!
//! The PTY is the local stand-in for the remote shell channel: keystrokes go in,
//! output is parsed by [`TermEmulator`](crate::ssh::terminal::TermEmulator), and the
//! UI keeps talking to a [`ShellHandle`].

use std::io::{Read, Write};
use std::time::Duration;

use async_channel::{Receiver, Sender};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtyPair, PtySize};
use tokio::time::Instant;

use crate::ssh::shell::{
    apply_shell_cmd, subscribe_window_visible, ShellCmd, ShellCmdEffect, ShellEvent, ShellHandle,
    SNAPSHOT_INTERVAL,
};
use crate::ssh::terminal::TermEmulator;

/// Bytes from the PTY, or the notice that the slave hung up.
enum PtyIn {
    Bytes(Vec<u8>),
    Closed,
}

/// Kills the shell when the driver task ends, including when the tab is dropped.
struct Reap(Option<Box<dyn Child + Send + Sync>>);

impl Reap {
    fn new(child: Box<dyn Child + Send + Sync>) -> Self {
        Self(Some(child))
    }
}

impl Drop for Reap {
    fn drop(&mut self) {
        let Some(child) = self.0.as_mut() else {
            return;
        };
        // SIGHUP is the hangup a terminal sends. A shell that ignores it (a login
        // shell can) would otherwise keep running after the tab is gone.
        let _ = child.kill();
        let started = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if started.elapsed() < Duration::from_millis(300) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => break,
            }
        }
        #[cfg(unix)]
        if let Some(pid) = child.process_id() {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
        let _ = child.wait();
    }
}

/// Open the user's login shell. `rows` and `cols` are the first grid; the view
/// sends a resize once it has measured itself.
pub fn spawn_local_shell(rows: u16, cols: u16) -> Result<ShellHandle, String> {
    let mut cmd = CommandBuilder::new_default_prog();
    // The emulator speaks xterm, the same terminal type an SSH session requests.
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");
    spawn_command(cmd, rows, cols)
}

fn spawn_command(cmd: CommandBuilder, rows: u16, cols: u16) -> Result<ShellHandle, String> {
    let rows = rows.max(1);
    let cols = cols.max(1);
    let pair = native_pty_system()
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|err| err.to_string())?;
    let child = Reap::new(
        pair.slave
            .spawn_command(cmd)
            .map_err(|err| err.to_string())?,
    );
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|err| err.to_string())?;
    let writer = pair.master.take_writer().map_err(|err| err.to_string())?;
    let PtyPair { slave, master } = pair;
    // The child has the slave side. Holding our copy open would keep the PTY
    // alive after the shell exits, so the reader would never see EOF.
    drop(slave);

    let (cmd_tx, cmd_rx) = async_channel::bounded(64);
    let (event_tx, event_rx) = async_channel::bounded(64);
    // Unbounded so a full queue cannot stall the reader. A stalled reader stops
    // draining the PTY, the shell blocks on its own write, and our write of the
    // next keystroke then blocks the thread that should have been reading.
    let (output_tx, output_rx) = async_channel::unbounded();

    std::thread::Builder::new()
        .name("g-ssh-local-pty".into())
        .spawn(move || pump_output(reader, output_tx))
        .map_err(|err| err.to_string())?;

    std::thread::Builder::new()
        .name("g-ssh-local-shell".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime.block_on(drive_local_shell(
                master, writer, rows, cols, cmd_rx, output_rx, event_tx, child,
            ));
        })
        .map_err(|err| err.to_string())?;

    tracing::info!(rows, cols, "opened a local shell");
    Ok(ShellHandle::new(cmd_tx, event_rx))
}

fn pump_output(mut reader: Box<dyn Read + Send>, tx: Sender<PtyIn>) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                let _ = tx.send_blocking(PtyIn::Closed);
                break;
            }
            Ok(n) => {
                if tx.send_blocking(PtyIn::Bytes(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                tracing::debug!(%err, "local shell output ended");
                let _ = tx.send_blocking(PtyIn::Closed);
                break;
            }
        }
    }
}

fn write_pty(writer: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

/// Feed PTY output into the emulator and write back its answers (device
/// attributes, cursor position). vim waits on those at startup.
fn push_output(
    emulator: &mut TermEmulator,
    bytes: &[u8],
    writer: &mut dyn Write,
) -> std::io::Result<()> {
    emulator.advance(bytes);
    let replies = emulator.take_replies();
    if !replies.is_empty() {
        write_pty(writer, &replies)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn drive_local_shell(
    master: Box<dyn MasterPty + Send>,
    mut writer: Box<dyn Write + Send>,
    rows: u16,
    cols: u16,
    cmd_rx: Receiver<ShellCmd>,
    output_rx: Receiver<PtyIn>,
    event_tx: Sender<ShellEvent>,
    child: Reap,
) {
    let _child = child;
    let mut emulator = TermEmulator::new(rows, cols);
    let mut window_visibility = subscribe_window_visible();
    let mut is_snapshot_stale = false;
    let mut is_snapshot_due = false;
    let mut last_snapshot_at = Instant::now();
    let snapshot_timer = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(snapshot_timer);

    let _ = event_tx
        .send(ShellEvent::Snapshot(emulator.snapshot()))
        .await;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Ok(cmd) => match apply_shell_cmd(&mut emulator, cmd) {
                        ShellCmdEffect::Write(data) => {
                            if let Err(err) = write_pty(&mut writer, &data) {
                                let _ = event_tx
                                    .send(ShellEvent::Error(format!("send input: {err}")))
                                    .await;
                                let _ = event_tx.send(ShellEvent::Exited).await;
                                break;
                            }
                        }
                        ShellCmdEffect::Resize { rows, cols } => {
                            let size = PtySize {
                                rows,
                                cols,
                                pixel_width: 0,
                                pixel_height: 0,
                            };
                            if let Err(err) = master.resize(size) {
                                tracing::warn!(%err, rows, cols, "local shell resize failed");
                            }
                            emulator.resize(rows, cols);
                            let _ = event_tx
                                .send(ShellEvent::Snapshot(emulator.snapshot()))
                                .await;
                        }
                        ShellCmdEffect::Snapshot => {
                            let _ = event_tx
                                .send(ShellEvent::Snapshot(emulator.snapshot()))
                                .await;
                        }
                        ShellCmdEffect::Quiet => {}
                    },
                    // The tab was closed. Dropping `child` hangs the shell up.
                    Err(_) => break,
                }
            }

            incoming = output_rx.recv() => {
                match incoming {
                    Ok(PtyIn::Bytes(data)) => {
                        if let Err(err) = push_output(&mut emulator, &data, &mut writer) {
                            let _ = event_tx
                                .send(ShellEvent::Error(format!("send reply: {err}")))
                                .await;
                            let _ = event_tx.send(ShellEvent::Exited).await;
                            break;
                        }
                        if !*window_visibility.borrow() {
                            is_snapshot_stale = true;
                        } else if last_snapshot_at.elapsed() >= SNAPSHOT_INTERVAL {
                            is_snapshot_due = false;
                            last_snapshot_at = Instant::now();
                            let _ = event_tx
                                .send(ShellEvent::Snapshot(emulator.snapshot()))
                                .await;
                        } else if !is_snapshot_due {
                            is_snapshot_due = true;
                            snapshot_timer
                                .as_mut()
                                .reset(last_snapshot_at + SNAPSHOT_INTERVAL);
                        }
                    }
                    Ok(PtyIn::Closed) | Err(_) => {
                        let _ = event_tx
                            .send(ShellEvent::Snapshot(emulator.snapshot()))
                            .await;
                        let _ = event_tx.send(ShellEvent::Exited).await;
                        break;
                    }
                }
            }

            Ok(()) = window_visibility.changed() => {
                if *window_visibility.borrow_and_update() && is_snapshot_stale {
                    is_snapshot_stale = false;
                    let _ = event_tx
                        .send(ShellEvent::Snapshot(emulator.snapshot()))
                        .await;
                }
            }

            () = &mut snapshot_timer, if is_snapshot_due => {
                is_snapshot_due = false;
                if *window_visibility.borrow() {
                    last_snapshot_at = Instant::now();
                    let _ = event_tx
                        .send(ShellEvent::Snapshot(emulator.snapshot()))
                        .await;
                } else {
                    is_snapshot_stale = true;
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use portable_pty::CommandBuilder;

    use super::spawn_command;
    use crate::ssh::shell::{ShellEvent, TermSnapshot};

    fn visible_text(snapshot: &TermSnapshot) -> String {
        let mut text = String::new();
        for row in &snapshot.cells {
            for cell in row {
                text.push(cell.c);
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn a_local_shell_prints_what_it_is_told() {
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.env("TERM", "xterm-256color");
        cmd.env("ENV", "");
        cmd.env("PS1", "$ ");
        let shell = spawn_command(cmd, 24, 80).expect("open a local shell");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let events = shell.subscribe();
            // `42` is the shell's answer, not a character of the command, so a
            // passing test means the shell ran it and the emulator showed it.
            shell.send_input(b"echo $((40+2))\r".to_vec()).await;

            let last = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
            let slot = last.clone();
            let found = tokio::time::timeout(Duration::from_secs(5), async move {
                loop {
                    match events.recv().await {
                        Ok(ShellEvent::Snapshot(snapshot)) => {
                            let text = visible_text(&snapshot);
                            if text.contains("42") {
                                return true;
                            }
                            *slot.lock().expect("last output") = text;
                        }
                        Ok(ShellEvent::Exited) | Err(_) => return false,
                        Ok(_) => {}
                    }
                }
            })
            .await;

            match found {
                Ok(true) => {}
                Ok(false) => panic!("shell exited:\n{}", last.lock().expect("last output")),
                Err(_) => panic!("timed out:\n{}", last.lock().expect("last output")),
            }
        });
    }
}
