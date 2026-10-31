use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// `vault.json`. Version 3 was the single CBOR file `vault.bin`; that file is
/// still opened once and rewritten in this layout.
pub const VAULT_VERSION: u32 = 4;

pub(crate) const LEGACY_VAULT_VERSION: u32 = 3;

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub kdf_salt: [u8; 32],
    pub kdf_params: KdfParams,
    pub enc_dek_by_password: AeadBlob,
    pub enc_dek_by_recovery: AeadBlob,
    pub enc_payload: AeadBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 262_144, // 256 MiB
            t_cost: 3,
            p_cost: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AeadBlob {
    pub nonce: [u8; 24],
    /// Ciphertext with 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

/// `AeadBlob` as base64 fields, for JSON files. The CBOR vault keeps the raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct JsonAead {
    #[serde(with = "serde_b64::array24")]
    pub nonce: [u8; 24],
    #[serde(with = "serde_b64::bytes")]
    pub ciphertext: Vec<u8>,
}

impl From<&AeadBlob> for JsonAead {
    fn from(blob: &AeadBlob) -> Self {
        Self {
            nonce: blob.nonce,
            ciphertext: blob.ciphertext.clone(),
        }
    }
}

impl From<JsonAead> for AeadBlob {
    fn from(blob: JsonAead) -> Self {
        Self {
            nonce: blob.nonce,
            ciphertext: blob.ciphertext,
        }
    }
}

/// Base64 fields in `vault.json` and connection files. Standard encoding, no line breaks.
pub(crate) mod serde_b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub mod bytes {
        use super::*;

        pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&STANDARD.encode(bytes))
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<u8>, D::Error> {
            let text = String::deserialize(deserializer)?;
            STANDARD.decode(text).map_err(serde::de::Error::custom)
        }
    }

    pub mod array24 {
        use super::*;

        pub fn serialize<S: Serializer>(
            bytes: &[u8; 24],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            bytes::serialize(bytes, serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<[u8; 24], D::Error> {
            super::fixed(bytes::deserialize(deserializer)?)
        }
    }

    pub mod array32 {
        use super::*;

        pub fn serialize<S: Serializer>(
            bytes: &[u8; 32],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            bytes::serialize(bytes, serializer)
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<[u8; 32], D::Error> {
            super::fixed(bytes::deserialize(deserializer)?)
        }
    }

    fn fixed<const N: usize, E: serde::de::Error>(bytes: Vec<u8>) -> Result<[u8; N], E> {
        let len = bytes.len();
        bytes
            .try_into()
            .map_err(|_| E::custom(format!("expected {N} bytes, got {len}")))
    }
}

impl AeadBlob {
    /// The form the sync server stores: the nonce, then the ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.nonce.as_slice(), &self.ciphertext].concat()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (nonce, ciphertext) = bytes.split_first_chunk::<24>()?;
        Some(Self {
            nonce: *nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// Stored as CBOR, encrypted as `enc_payload`. New fields here and in the records
/// below must be `#[serde(default)]` so older vaults still load.
///
/// `entries` is empty in the saved blob. Each host is a JSON file under `connections/`.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultPayload {
    pub entries: Vec<ServerEntry>,
    pub keys: Vec<SshKey>,
    #[serde(deserialize_with = "deserialize_snippets")]
    pub snippets: Vec<Snippet>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub tags: Vec<Tag>,
    #[serde(default)]
    pub proxies: Vec<ProxyDef>,
    #[serde(default)]
    pub proxy_routing: ProxyRouting,
    /// `None` = local only, not signed in to sync.
    #[serde(default)]
    pub sync: Option<crate::vault::sync::SyncState>,
    /// Where this account joined each of its teams; synced with the personal vault.
    #[serde(default)]
    pub team_pins: Vec<crate::vault::sync::TeamPin>,
    /// Invites used and not accepted yet.
    #[serde(default)]
    pub joins: Vec<crate::vault::sync::PendingJoin>,
}

/// A host folder, for visual grouping only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    /// Parent folder for nesting; `None` = top-level.
    #[serde(default)]
    pub parent_id: Option<Uuid>,
}

/// A host label. Visual only, many-to-many.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: Uuid,
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProxyDef {
    pub id: Uuid,
    pub name: String,
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// SOCKS5 user/pass or HTTP Basic.
    pub auth: Option<ProxyAuth>,
}

impl fmt::Debug for ProxyDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyDef")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth", &self.auth.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyKind {
    Socks5,
    Http,
}

impl ProxyKind {
    pub fn display_label(self) -> &'static str {
        match self {
            ProxyKind::Socks5 => "SOCKS5",
            ProxyKind::Http => "HTTP",
        }
    }
}

/// A port forward saved on a host (`-L` / `-R` / `-D`). The SSH layer runs its
/// vault-free [`crate::ssh::connection::ForwardSpec`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    pub id: Uuid,
    pub name: String,
    pub kind: crate::ssh::connection::ForwardKind,
    pub bind_address: String,
    /// 0 on a `Remote` forward asks the server to pick a port.
    pub bind_port: u16,
    /// Empty on a `Dynamic` forward: each SOCKS5 client names its own target.
    pub target_host: String,
    /// 0 on a `Dynamic` forward, see `target_host`.
    pub target_port: u16,
    /// Started on every connect and reconnect.
    pub auto_start: bool,
}

impl PortForward {
    /// The one place the two shapes are mapped, so a new field cannot be forgotten.
    pub fn spec(&self) -> crate::ssh::connection::ForwardSpec {
        crate::ssh::connection::ForwardSpec {
            id: self.id.to_string(),
            kind: self.kind,
            bind_address: self.bind_address.clone(),
            bind_port: self.bind_port,
            target_host: self.target_host.clone(),
            target_port: self.target_port,
        }
    }
}

/// Proxy credentials. Never logged, see [`ProxyDef`]'s `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// Non-secret view of a [`ProxyDef`] for list/picker displays.
#[derive(Debug, Clone)]
pub struct ProxyDefSummary {
    pub id: Uuid,
    pub name: String,
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub has_auth: bool,
}

impl From<&ProxyDef> for ProxyDefSummary {
    fn from(p: &ProxyDef) -> Self {
        Self {
            id: p.id,
            name: p.name.clone(),
            kind: p.kind,
            host: p.host.clone(),
            port: p.port,
            has_auth: p.auth.is_some(),
        }
    }
}

/// Global rule deciding which hosts route through [`ProxyRouting::default_proxy`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyRouting {
    /// `None` = the rule proxies nothing.
    #[serde(default)]
    pub default_proxy: Option<Uuid>,
    #[serde(default)]
    pub mode: ProxyMode,
    /// Hosts excluded under `AllExcept`, included under `OnlySelected`.
    #[serde(default)]
    pub server_set: Vec<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProxyMode {
    #[default]
    AllExcept,
    OnlySelected,
}

/// Per-host proxy choice, overriding the global rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProxyChoice {
    /// Follow the global [`ProxyRouting`] rule.
    #[default]
    Default,
    Direct,
    Use(Uuid),
}

/// The per-host override wins over the global rule. `None` = connect directly.
pub fn resolve_proxy<'a>(
    entry: &ServerEntry,
    routing: &ProxyRouting,
    proxies: &'a [ProxyDef],
) -> Option<&'a ProxyDef> {
    let find = |id: Uuid| proxies.iter().find(|p| p.id == id);
    match entry.proxy {
        ProxyChoice::Direct => None,
        ProxyChoice::Use(id) => find(id),
        ProxyChoice::Default => {
            let in_set = routing.server_set.contains(&entry.id);
            let applies = match routing.mode {
                ProxyMode::AllExcept => !in_set,
                ProxyMode::OnlySelected => in_set,
            };
            if applies {
                routing.default_proxy.and_then(find)
            } else {
                None
            }
        }
    }
}

/// Real chains have one or two bastions; the cap only keeps the walk bounded.
pub const MAX_JUMP_HOSTS: usize = 4;

/// Each variant names the entry the user has to fix, so `Display` works as a status line.
#[derive(Debug, thiserror::Error)]
pub enum JumpChainError {
    #[error("'{0}' would be reached through itself")]
    Cycle(String),
    #[error("'{0}' is behind more than {1} jump hosts")]
    TooDeep(String, usize),
    #[error("'{0}' points at a jump host that no longer exists")]
    Missing(String),
}

/// Connect order: outermost bastion first, `entry` last (alone if no jump host).
pub fn resolve_jump_chain<'a>(
    entry: &'a ServerEntry,
    entries: &'a [ServerEntry],
) -> Result<Vec<&'a ServerEntry>, JumpChainError> {
    let mut chain = vec![entry];
    let mut seen = std::collections::HashSet::from([entry.id]);
    let mut cursor = entry.jump_host;

    while let Some(id) = cursor {
        if chain.len() > MAX_JUMP_HOSTS {
            return Err(JumpChainError::TooDeep(entry.label.clone(), MAX_JUMP_HOSTS));
        }
        let referrer = chain[chain.len() - 1].label.clone();
        let Some(hop) = entries.iter().find(|e| e.id == id) else {
            return Err(JumpChainError::Missing(referrer));
        };
        // Else a loop would only end at the depth cap, blaming the wrong host.
        if !seen.insert(id) {
            return Err(JumpChainError::Cycle(hop.label.clone()));
        }
        chain.push(hop);
        cursor = hop.jump_host;
    }

    chain.reverse();
    Ok(chain)
}

/// OpenSSH command for a chain: `ssh -J ops@bastion,ops@inner:2200 -p 2222 deploy@db`.
/// It is pasted into a shell and hosts may come from others, so shell syntax is quoted.
pub fn ssh_command(chain: &[&ServerEntry]) -> String {
    let Some((target, bastions)) = chain.split_last() else {
        return String::new();
    };
    let mut command = String::from("ssh");
    if !bastions.is_empty() {
        let hops: Vec<String> = bastions.iter().map(|hop| jump_spec(hop)).collect();
        command.push_str(&format!(" -J {}", shell_quote(&hops.join(","))));
    }
    if target.port != 22 {
        command.push_str(&format!(" -p {}", target.port));
    }
    let destination = user_at_host(&target.username, &target.host);
    // A destination that starts with '-' would be read as an option. After
    // "--" ssh reads no more options, which is why the port comes first.
    if destination.starts_with('-') {
        command.push_str(" --");
    }
    command.push(' ');
    command.push_str(&shell_quote(&destination));
    command
}

/// One `-J` hop: `[user@]host[:port]`.
fn jump_spec(hop: &ServerEntry) -> String {
    // ssh splits a hop on ':' to find the port, so an IPv6 address needs brackets.
    let host = if hop.host.contains(':') && !hop.host.starts_with('[') {
        format!("[{}]", hop.host)
    } else {
        hop.host.clone()
    };
    let spec = user_at_host(&hop.username, &host);
    if hop.port == 22 {
        return spec;
    }
    format!("{spec}:{}", hop.port)
}

fn user_at_host(username: &str, host: &str) -> String {
    if username.is_empty() {
        return host.to_string();
    }
    format!("{username}@{host}")
}

/// `word` as one shell word. Brackets are quoted too: zsh takes them for a
/// file pattern and refuses the command.
fn shell_quote(word: &str) -> String {
    let is_plain = |c: char| c.is_ascii_alphanumeric() || "._:@%+-,".contains(c);
    if !word.is_empty() && word.chars().all(is_plain) {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub id: Uuid,
    pub name: String,
    pub created_at: u64,
    pub fingerprint: String,
    pub key_type: String,
    pub pem: String,
    pub passphrase: Option<String>,
}

impl fmt::Debug for SshKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshKey")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("fingerprint", &self.fingerprint)
            .field("key_type", &self.key_type)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// Non-secret view of an SshKey for list displays.
#[derive(Debug, Clone)]
pub struct SshKeySummary {
    pub id: Uuid,
    pub name: String,
    pub key_type: String,
    pub created_at: u64,
}

impl From<&SshKey> for SshKeySummary {
    fn from(k: &SshKey) -> Self {
        Self {
            id: k.id,
            name: k.name.clone(),
            key_type: k.key_type.clone(),
            created_at: k.created_at,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snippet {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub body: SnippetBody,
    /// Last run per server; the palette's "recent" order prefers the active server.
    #[serde(default)]
    pub usages: Vec<SnippetUsage>,
}

/// A command that belongs to one host, kept in its entry: it syncs, is shared
/// and is deleted with the host. Not in the shared snippet list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostSnippet {
    pub id: Uuid,
    pub name: String,
    pub script: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnippetUsage {
    pub server_id: Uuid,
    /// Unix seconds of the last run.
    pub at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SnippetBody {
    Script { content: String },
}

/// Old vaults can hold `Workflow` bodies. A plain derive would fail the whole
/// payload on them, so they are skipped here and dropped on the next save.
fn deserialize_snippets<'de, D>(deserializer: D) -> Result<Vec<Snippet>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let stored = Vec::<StoredSnippet>::deserialize(deserializer)?;
    Ok(stored
        .into_iter()
        .filter_map(StoredSnippet::into_snippet)
        .collect())
}

#[derive(Deserialize)]
struct StoredSnippet {
    id: Uuid,
    name: String,
    description: Option<String>,
    created_at: i64,
    updated_at: i64,
    body: StoredBody,
    #[serde(default)]
    usages: Vec<SnippetUsage>,
}

impl StoredSnippet {
    fn into_snippet(self) -> Option<Snippet> {
        let StoredBody::Script { content } = self.body else {
            tracing::warn!(name = %self.name, "dropping snippet with an unsupported body");
            return None;
        };
        Some(Snippet {
            id: self.id,
            name: self.name,
            description: self.description,
            created_at: self.created_at,
            updated_at: self.updated_at,
            body: SnippetBody::Script { content },
            usages: self.usages,
        })
    }
}

enum StoredBody {
    Script { content: String },
    Unsupported,
}

impl<'de> Deserialize<'de> for StoredBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_enum("SnippetBody", &["Script"], StoredBodyVisitor)
    }
}

struct StoredBodyVisitor;

impl<'de> serde::de::Visitor<'de> for StoredBodyVisitor {
    type Value = StoredBody;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a snippet body")
    }

    fn visit_enum<A>(self, data: A) -> Result<StoredBody, A::Error>
    where
        A: serde::de::EnumAccess<'de>,
    {
        use serde::de::VariantAccess as _;

        let (tag, variant) = data.variant::<BodyTag>()?;
        match tag {
            // A struct variant and a newtype variant wrapping the same fields
            // share their encoding, so this reads `Script { content }`.
            BodyTag::Script => {
                let fields = variant.newtype_variant::<ScriptFields>()?;
                Ok(StoredBody::Script {
                    content: fields.content,
                })
            }
            BodyTag::Unsupported => {
                variant.newtype_variant::<serde::de::IgnoredAny>()?;
                Ok(StoredBody::Unsupported)
            }
        }
    }
}

#[derive(Deserialize)]
struct ScriptFields {
    content: String,
}

enum BodyTag {
    Script,
    Unsupported,
}

impl<'de> Deserialize<'de> for BodyTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(BodyTagVisitor)
    }
}

struct BodyTagVisitor;

impl serde::de::Visitor<'_> for BodyTagVisitor {
    type Value = BodyTag;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a snippet body variant name")
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<BodyTag, E> {
        Ok(match value {
            "Script" => BodyTag::Script,
            _ => BodyTag::Unsupported,
        })
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<BodyTag, E> {
        Ok(match value {
            0 => BodyTag::Script,
            _ => BodyTag::Unsupported,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    pub id: Uuid,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    pub notes: Option<String>,
    /// Detected on connect, e.g. "Ubuntu 22.04".
    #[serde(default)]
    pub os: Option<String>,
    /// Unix seconds, for the sidebar's "recent" order; `None` = never opened.
    #[serde(default)]
    pub last_opened_at: Option<i64>,
    /// SHA256 host key fingerprint, trusted on first connect (TOFU). `None` = the
    /// next connect prompts; a mismatch gives a hard warning.
    #[serde(default)]
    pub host_key_fingerprint: Option<String>,
    /// Last SFTP folder shown, reopened on restart or reconnect instead of home.
    /// Saved together with `last_local_dir`.
    #[serde(default)]
    pub last_remote_dir: Option<String>,
    /// Local counterpart of `last_remote_dir`.
    #[serde(default)]
    pub last_local_dir: Option<String>,
    /// `None` = ungrouped.
    #[serde(default)]
    pub group: Option<Uuid>,
    #[serde(default)]
    pub tags: Vec<Uuid>,
    #[serde(default)]
    pub proxy: ProxyChoice,
    /// ProxyJump entry; `None` = direct. The bastion's own credentials, host key
    /// and proxy are used, so a chain is just ids.
    #[serde(default)]
    pub jump_host: Option<Uuid>,
    #[serde(default)]
    pub forwards: Vec<PortForward>,
    /// Sent to the shell after every connect: a shared snippet or one of `snippets`.
    #[serde(default)]
    pub startup_snippet: Option<Uuid>,
    #[serde(default)]
    pub snippets: Vec<HostSnippet>,
    /// Place in the host's folder. `0` means it has never been placed, so it
    /// sorts by name after the hosts that have a place. Omitted from the file
    /// and from sync while it is `0`, so an older record stays the same bytes.
    #[serde(default, skip_serializing_if = "is_unset_order")]
    pub sort_order: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

fn is_unset_order(order: &i64) -> bool {
    *order == 0
}

impl fmt::Debug for ServerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerEntry")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth", &self.auth)
            // People keep passwords and tokens in the notes.
            .field("notes", &self.notes.as_ref().map(|_| "[redacted]"))
            .field("os", &self.os)
            .field("last_opened_at", &self.last_opened_at)
            .field("host_key_fingerprint", &self.host_key_fingerprint)
            .field("last_remote_dir", &self.last_remote_dir)
            .field("last_local_dir", &self.last_local_dir)
            .field("proxy", &self.proxy)
            .field("jump_host", &self.jump_host)
            // Forwards hold no secrets, but a count keeps the line readable.
            .field("forwards", &self.forwards.len())
            .field("startup_snippet", &self.startup_snippet)
            .field("snippets", &self.snippets.len())
            .field("sort_order", &self.sort_order)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    Password(String),
    PrivateKey { key_id: Uuid },
    Agent,
}

impl fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMethod::Password(_) => f.write_str("Password([redacted])"),
            AuthMethod::PrivateKey { .. } => f.write_str("PrivateKey([redacted])"),
            AuthMethod::Agent => f.write_str("Agent"),
        }
    }
}

/// Summary for list views, without credentials.
#[derive(Debug, Clone)]
pub struct ServerEntrySummary {
    pub id: Uuid,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub os: Option<String>,
    pub last_opened_at: Option<i64>,
    /// Sidebar place within the folder. `0` = not placed yet.
    pub sort_order: i64,
    /// Full folder path ("parent / child"), resolved by
    /// [`VaultManager::list_entries`]; `None` = ungrouped.
    pub group_name: Option<String>,
    /// Resolved by [`VaultManager::list_entries`].
    pub tag_names: Vec<String>,
    pub proxy: ProxyChoice,
    /// The team this host is shared with, and the vault when the team has
    /// several. Resolved by [`VaultManager::list_entries`]; `None` = personal.
    pub team_name: Option<String>,
}

impl From<&ServerEntry> for ServerEntrySummary {
    fn from(e: &ServerEntry) -> Self {
        Self {
            id: e.id,
            label: e.label.clone(),
            host: e.host.clone(),
            port: e.port,
            username: e.username.clone(),
            os: e.os.clone(),
            last_opened_at: e.last_opened_at,
            sort_order: e.sort_order,
            // The entry holds only ids; VaultManager::list_entries fills in names.
            group_name: None,
            tag_names: Vec::new(),
            proxy: e.proxy,
            team_name: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Snippet shape written by builds that still had workflows.
    #[derive(Serialize)]
    enum OldSnippetBody {
        Script {
            content: String,
        },
        Workflow {
            local_path: String,
            remote_path: String,
            steps: Vec<String>,
        },
    }

    #[derive(Serialize)]
    struct OldSnippet {
        id: Uuid,
        name: String,
        description: Option<String>,
        created_at: i64,
        updated_at: i64,
        body: OldSnippetBody,
        usages: Vec<SnippetUsage>,
    }

    #[derive(Serialize)]
    struct OldPayload {
        entries: Vec<ServerEntry>,
        keys: Vec<SshKey>,
        snippets: Vec<OldSnippet>,
        groups: Vec<Group>,
        tags: Vec<Tag>,
        proxies: Vec<ProxyDef>,
        proxy_routing: ProxyRouting,
    }

    fn old_snippet(name: &str, body: OldSnippetBody) -> OldSnippet {
        OldSnippet {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            created_at: 1,
            updated_at: 2,
            body,
            usages: Vec::new(),
        }
    }

    /// Host shape from before port forwarding, without any `#[serde(default)]` field.
    #[derive(Serialize)]
    struct OldServerEntry {
        id: Uuid,
        label: String,
        host: String,
        port: u16,
        username: String,
        auth: AuthMethod,
        notes: Option<String>,
        created_at: i64,
        updated_at: i64,
    }

    #[derive(Serialize)]
    struct PayloadWithOldEntries {
        entries: Vec<OldServerEntry>,
        keys: Vec<SshKey>,
        snippets: Vec<Snippet>,
        groups: Vec<Group>,
        tags: Vec<Tag>,
        proxies: Vec<ProxyDef>,
        proxy_routing: ProxyRouting,
    }

    #[test]
    fn hosts_saved_before_port_forwarding_still_load() {
        let payload = PayloadWithOldEntries {
            entries: vec![OldServerEntry {
                id: Uuid::new_v4(),
                label: "web".into(),
                host: "web.example.com".into(),
                port: 22,
                username: "deploy".into(),
                auth: AuthMethod::Agent,
                notes: None,
                created_at: 1,
                updated_at: 2,
            }],
            keys: Vec::new(),
            snippets: Vec::new(),
            groups: Vec::new(),
            tags: Vec::new(),
            proxies: Vec::new(),
            proxy_routing: ProxyRouting::default(),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        let loaded: VaultPayload = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.entries[0].forwards.is_empty());
        assert_eq!(loaded.entries[0].sort_order, 0);
    }

    #[test]
    fn workflow_snippets_are_dropped_instead_of_failing_the_load() {
        let payload = OldPayload {
            entries: Vec::new(),
            keys: Vec::new(),
            snippets: vec![
                old_snippet(
                    "deploy",
                    OldSnippetBody::Workflow {
                        local_path: "/tmp/app".into(),
                        remote_path: "/var/www".into(),
                        steps: vec!["upload".into()],
                    },
                ),
                old_snippet(
                    "restart",
                    OldSnippetBody::Script {
                        content: "systemctl restart app".into(),
                    },
                ),
            ],
            groups: Vec::new(),
            tags: Vec::new(),
            proxies: Vec::new(),
            proxy_routing: ProxyRouting::default(),
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).unwrap();

        let loaded: VaultPayload = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(loaded.snippets.len(), 1);
        assert_eq!(loaded.snippets[0].name, "restart");
        assert!(matches!(
            &loaded.snippets[0].body,
            SnippetBody::Script { content } if content == "systemctl restart app"
        ));
    }
}
