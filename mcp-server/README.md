# mcp-server

Private spike: a stdio MCP server on the `gssh` core crate (not the GUI).
It lists saved hosts, runs one remote command, and opens or closes a local
port forward. Release archives do not include this binary.

## Build

From the repo root, with the Rust 1.98.1 toolchain in `rust-toolchain.toml`:

```sh
cargo build -p mcp-server
```

The binary is `target/debug/mcp-server` (`mcp-server.exe` on Windows).
`cargo build --release --workspace` writes it next to `g-ssh` as
`target/release/mcp-server`.

## Run

Stdout is the MCP protocol. Logs go to stderr.

| Variable | Required | Meaning |
| --- | --- | --- |
| `GSSH_VAULT_PASSWORD` | yes | Vault password. Read once at startup, then removed from this process's environment. Not a recovery phrase. |
| `GSSH_DATA_DIR` | no | Data directory. Default `~/.g-ssh` (`%USERPROFILE%\.g-ssh` on Windows). |
| `GSSH_MCP_CONNECT_TIMEOUT_SECS` | no | Connect timeout, default 90, range 1–3600. |
| `GSSH_MCP_EXEC_TIMEOUT_SECS` | no | Command timeout, default 60. |
| `GSSH_MCP_FORWARD_TIMEOUT_SECS` | no | Forward start/stop timeout, default 20. |

The password is the value of the variable exactly, with no trimming.
Touch ID and the macOS keychain stay in the GUI. This process does not
read the OS keychain, and it has no tool that returns a recovery phrase,
a vault key, or a private key.

Example client config (path and password stay on this machine):

```json
{
  "mcpServers": {
    "gssh": {
      "command": "target/debug/mcp-server",
      "env": {
        "GSSH_VAULT_PASSWORD": "vault password"
      }
    }
  }
}
```

## Tools

| Tool | What it does |
| --- | --- |
| `list_hosts` | Hosts from `connections/`. Id, label, address, kind, group, jump host id, host-key fingerprint, and auth kind. No passwords, key material, or notes. |
| `ssh_exec` | One command via `open_exec_captured` on the host's saved route (`route_for`, jump hosts included). Returns stdout, stderr, and the remote exit code. A non-zero exit is still a successful tool call (`isError` is false); the code is in the JSON body. `exit_code` is null only when the server sends no `exit-status` (for example a signal). |
| `start_forward` | One local `-L` forward. Bind address defaults to `127.0.0.1` and must be loopback. |
| `stop_forward` | Stops a forward by the `forward_id` from `start_forward`. |

There is no interactive shell tool, no SFTP tool, and no `-R` or `-D` forward.

## Host keys and prompts

A fingerprint already stored on the host, or a key already in
`~/.ssh/known_hosts`, is accepted by `gssh` with no prompt. Anything else
raises `HostKeyPrompt`. This server answers **no** immediately:

- unknown key: refused, no trust-on-first-use
- changed key: refused (vault mismatch wins over `known_hosts`)

The fingerprint is in the tool error so it can be checked. This server
does not write a new fingerprint into the vault. Trust the key in the
g-ssh app, or have it in `known_hosts`, before an agent connects.

`AuthPrompt` (keyboard-interactive, one-time codes) is cancelled
immediately. Stdio is the protocol, so there is no human-in-the-loop on
this process. A host that needs a prompt will fail the tool.

## Process hardening

`gssh::vault::memory::disable_core_dumps` runs before the vault is
unlocked, same as the GUI. On Windows that function does nothing (dumps
are controlled outside the process). On macOS and Linux it sets the core
limit to 0, and on Linux it also marks the process not dumpable.

## Not in this spike

SFTP, remote and dynamic forwards, a full jump/proxy matrix beyond what
the saved host already stores, RDP/VNC, sync, and the GUI agent's
command allow-list. `ssh_exec` runs the command you pass.
