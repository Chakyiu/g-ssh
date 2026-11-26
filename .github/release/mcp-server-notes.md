## MCP server (`mcp-server`)

Release archives now ship the `mcp-server` binary next to `g-ssh` (`mcp-server.exe` on Windows). Tools: `list_hosts`, `ssh_exec`, and local port forwards (`start_forward` / `stop_forward`). Unlock the vault with `GSSH_VAULT_PASSWORD`. Unknown or changed host keys fail closed. The process can use every host in the data directory it is pointed at (default `~/.g-ssh`).