//! MCP stdio server. Logs go to stderr; stdout is the protocol.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use mcp_server::App;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::transport::stdio;
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData, ServerHandler, ServiceExt};
use secrecy::SecretString;

const PASSWORD_ENV: &str = "GSSH_VAULT_PASSWORD";

#[derive(Clone)]
struct Mcp {
    app: Arc<App>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ExecArgs {
    /// Saved host id (UUID) or its unique label.
    host: String,
    /// One remote command. Not an interactive shell.
    command: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ForwardArgs {
    /// Saved host id (UUID) or its unique label.
    host: String,
    /// Port to listen on locally.
    local_port: u16,
    /// Host the remote SSH server connects to, often 127.0.0.1 on that machine.
    remote_host: String,
    remote_port: u16,
    /// Loopback bind address. Defaults to 127.0.0.1.
    #[serde(default)]
    bind_address: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct StopArgs {
    /// `forward_id` returned by `start_forward`.
    forward_id: String,
}

#[tool_router]
impl Mcp {
    #[tool(
        description = "List saved hosts from the vault connections folder. Passwords, keys, and notes are omitted."
    )]
    async fn list_hosts(&self) -> Result<CallToolResult, ErrorData> {
        Ok(tool_text(self.app.list_hosts()))
    }

    #[tool(
        description = "Run one remote command on a saved host, including its jump hosts, and return stdout, stderr, and the exit code. Not an interactive shell."
    )]
    async fn ssh_exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(tool_text(self.app.exec(&args.host, &args.command).await))
    }

    #[tool(
        description = "Open a local port forward (-L) to a saved host. The bind address must be loopback. Returns forward_id."
    )]
    async fn start_forward(
        &self,
        Parameters(args): Parameters<ForwardArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(tool_text(
            self.app
                .start_forward(
                    &args.host,
                    args.local_port,
                    &args.remote_host,
                    args.remote_port,
                    args.bind_address.as_deref(),
                )
                .await,
        ))
    }

    #[tool(description = "Stop a local forward started by start_forward.")]
    async fn stop_forward(
        &self,
        Parameters(args): Parameters<StopArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(tool_text(self.app.stop_forward(&args.forward_id).await))
    }
}

#[tool_handler(
    name = "gssh",
    version = "0.1.0",
    instructions = "Headless g-ssh for saved hosts. Tools: list_hosts, ssh_exec, start_forward, stop_forward. No interactive shell. Unknown or changed host keys fail closed. Keyboard-interactive prompts are denied."
)]
impl ServerHandler for Mcp {}

fn tool_text(result: Result<String, String>) -> CallToolResult {
    match result {
        Ok(body) => CallToolResult::success(vec![ContentBlock::text(body)]),
        Err(message) => CallToolResult::error(vec![ContentBlock::text(message)]),
    }
}

fn main() -> anyhow::Result<()> {
    // Before the vault key exists in this process. On Windows the function
    // is a no-op; Unix builds match the GUI and disable core dumps.
    gssh::vault::memory::disable_core_dumps();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let app = unlock()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("tokio runtime")?;
    runtime.block_on(async {
        let running = Mcp { app: Arc::new(app) }
            .serve(stdio())
            .await
            .context("mcp stdio")?;
        running.waiting().await.context("mcp session")?;
        Ok(())
    })
}

fn unlock() -> anyhow::Result<App> {
    if let Some(dir) = std::env::var_os("GSSH_DATA_DIR") {
        let path = PathBuf::from(dir);
        if path.as_os_str().is_empty() {
            anyhow::bail!("GSSH_DATA_DIR is empty");
        }
        gssh::app::set_data_dir(path);
    }
    let password = take_password()?;
    let path = gssh::vault::default_vault_path().context("vault path")?;
    let vault = gssh::vault::VaultManager::unlock_with_password(&path, &password)
        .map_err(|e| anyhow::anyhow!("could not unlock {}: {e}", path.display()))?;
    drop(password);
    let hosts = vault
        .list_entries()
        .map(|entries| entries.len())
        .unwrap_or(0);
    tracing::info!(path = %path.display(), hosts, "vault unlocked");
    App::new(vault).map_err(anyhow::Error::msg)
}

fn take_password() -> anyhow::Result<SecretString> {
    let password =
        std::env::var(PASSWORD_ENV).map_err(|_| anyhow::anyhow!("{PASSWORD_ENV} is not set"))?;
    // Safety: startup, before the runtime or any other thread exists, so no
    // other thread is reading the environment. The client that spawned us
    // still has the value; this only stops later children from inheriting it.
    unsafe { std::env::remove_var(PASSWORD_ENV) };
    if password.is_empty() {
        anyhow::bail!("{PASSWORD_ENV} is empty");
    }
    Ok(SecretString::from(password))
}
