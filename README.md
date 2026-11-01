# g-ssh

AI-agent-enabled SSH and SFTP client. Keys stay in an encrypted vault.
Each host is a file you can copy out, and the password in that file is
sealed with the vault key.

A host opens as a terminal tab or an SFTP tab on the same connection.
Several shells can share that connection, and a tab can be split so two
hosts sit side by side.

The window is this crate. SSH, SFTP, the terminal emulator, the vault, and
account sync are in `core`. That library is imported as `gssh`, because Rust
already owns the name `core`.

It runs on macOS 12 or newer, Windows, and Linux (X11 and Wayland).

## What it does

- Sign in with a password, a private key stored in the vault, or an SSH
  agent. A host can sit behind up to four jump hosts, and behind a SOCKS5 or
  HTTP proxy.
- Local, remote, and dynamic (SOCKS) port forwards. A forward can start with
  the connection.
- Up to eight shells on one connection. Scrollback is 10,000 lines, with
  search, clickable links, shell history suggestions, and a choice of font
  and colors. Drag a tab onto an edge to split the window. The side panel
  reads CPU, memory, disk, and network from a Linux server.
- An SFTP tab, opened from the host list, with this computer or another saved
  server beside the one you opened. Files move in both directions and between
  two servers, and can be previewed or opened in a local app or in an editor
  on the server.
- Groups, tags, and snippets, including commands that belong to one host.
  The command palette opens a host, connects to an address you type, and runs
  a snippet.
- The host key is remembered on first connect. A key already in
  `~/.ssh/known_hosts` is accepted without asking. A later mismatch warns and
  stops.

Hosts can be imported from `~/.ssh/config` and from a Termius export file.
On Windows they can also be imported from PuTTY's saved sessions and from a
Termius install on this computer.

## Agent

The Agent button opens a chat beside the open terminal. Ask agent on the
terminal menu does the same and attaches the selection. Command+Enter
sends on a Mac, and Ctrl+Enter elsewhere. A message sent while the agent
is working waits until it is free.

The chat uses an OpenAI-compatible endpoint from Settings. The default is
OpenAI. Ollama is a local URL with an empty key. The models are the ones
the endpoint reports. The API key is stored in the vault and stays on this
computer. The system prompt is edited in Settings.

The model can ask to type one command into that terminal. The exact
command is shown and runs after Allow, or when its program is on the
always-allow list. `ls` on that list allows `ls -la`. A line that starts
another program still asks. The agent then reads what the terminal prints.
Chats are saved per host on this computer.

## Vault

The vault is `~/.g-ssh/vault.json`. The password unlocks it. A 24-word
recovery phrase unlocks it without the password. On macOS, Touch ID can
unlock it: the vault key is kept in the keychain and only the enrolled
fingers can read it back.

An older `vault.bin` is opened once and rewritten in this layout. Hosts then
live under `connections/`, one JSON file per host, in a folder for its group.
Copying a file copies the host. The password in that file is sealed with the
vault key. A file from another vault still opens, and its password stays
sealed until a new one is typed. Keys, snippets, and the rest of the vault
stay in `vault.json`.

The password is stretched with Argon2id. Vault contents are encrypted with
XChaCha20-Poly1305. The data key stays locked in memory, and core dumps are
disabled while the app runs.

Signing in with GitHub attaches the vault to an account. The vault password
becomes the account password, and changes sync. A host can be shared with a
team or kept personal.

## First launch on a Mac

A download from the release page is ad-hoc signed and
not notarized, so Gatekeeper says Apple could not verify "g-ssh" is free of
malware. Allow the app once.

Drag `g-ssh.app` from the disk image into Applications and open it.

- macOS 15 or newer: click Done on the warning. Open System Settings, go to
  Privacy & Security, and click Open Anyway next to g-ssh. Confirm and enter
  your password.
- macOS 13 and 14: Control-click `g-ssh.app`, choose Open, then click Open.
  The same Open Anyway button is under Privacy & Security.
- macOS 12: Control-click `g-ssh.app` and choose Open. Or open System
  Preferences, Security & Privacy, General, and click Open Anyway.

Or clear the download mark in Terminal, then open the app:

```sh
xattr -dr com.apple.quarantine /Applications/g-ssh.app
```

A binary from `cargo build` has no download mark, so Gatekeeper leaves it
alone.

## Updates

macOS (Apple silicon) and Windows x86_64 can ask GitHub for a newer
build at startup and every six hours after that. The check reads the latest
[release](https://github.com/Chakyiu/g-ssh/releases). Update downloads the
archive for this computer, checks it against the checksum on that release,
replaces the app you are running, and reopens it. The sandboxed Mac App
Store build updates from the store. Linux builds have no update check.

## Building

`rust-toolchain.toml` pins Rust 1.98.1. With rustup, that toolchain installs
itself.

```sh
cargo build --release
```

The binary is `target/release/g-ssh`, or `g-ssh.exe` on Windows.

[`.github/workflows/release.yml`](.github/workflows/release.yml) builds
Linux, macOS arm64, and Windows x86_64. Pushing a `v*` tag
starts it and publishes the builds on the GitHub release for that tag,
which is what the update check downloads. macOS is a `.dmg` containing
`g-ssh.app`. Windows is a `.zip` and Linux is a `.tar.gz`. It can still
be started by hand, and that run only keeps the builds as artifacts.
The macOS app is ad-hoc signed so it can launch, and not notarized. See
[First launch on a Mac](#first-launch-on-a-mac).

```sh
cargo test
cargo clippy --workspace --all-targets
```

## Files

The app writes under `~/.g-ssh`:

| Path | What it is |
| --- | --- |
| `vault.json` | The encrypted vault: keys, snippets, groups, account sync, and the agent endpoint |
| `connections/` | One JSON file per host. The password in the file is sealed |
| `agent-chats/` | Agent chats, one JSON file per host. This computer only |
| `preferences.json` | Theme, terminal, and other settings read before unlock |
| `file_associations.json` | Which local app opens a given file type |
| `open_tabs.json` | Hosts that were open, so the next start opens them again. This computer only |
| `logs/g-ssh.log` | The log, plus one rotated copy |

`RUST_LOG` replaces the default filter, which is `warn,g-ssh=info`.