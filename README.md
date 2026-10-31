# g-ssh

SSH and SFTP client. Keys stay in an encrypted vault. Each host is a file
you can copy out, and the password in that file is sealed with the vault key.

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

## Updates

macOS (Apple silicon) and Windows x86_64 can ask GitHub for a newer
build at startup and every six hours after that. The check reads the latest
[release](https://github.com/Chakyiu/g-ssh/releases) and downloads the archive
for this computer from that page. The sandboxed Mac App Store build updates
from the store. Linux builds have no update check.

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
The macOS app is ad-hoc signed so it can launch, and not notarized.

```sh
cargo test
cargo clippy --workspace --all-targets
```

## Files

The app writes under `~/.g-ssh`:

| Path | What it is |
| --- | --- |
| `vault.json` | The encrypted vault: keys, snippets, groups, and account sync |
| `connections/` | One JSON file per host. The password in the file is sealed |
| `preferences.json` | Theme, terminal, and other settings read before unlock |
| `file_associations.json` | Which local app opens a given file type |
| `open_tabs.json` | Hosts that were open, so the next start opens them again. This computer only |
| `logs/g-ssh.log` | The log, plus one rotated copy |

`RUST_LOG` replaces the default filter, which is `warn,g-ssh=info`.