//! Password-sealed export of hosts.
//!
//! The file is JSON. Argon2id derives a key from the export password, and
//! XChaCha20-Poly1305 seals the hosts, their passwords, and the SSH keys they
//! use — the same pair the vault uses. The KDF is lighter than the vault's so
//! an export finishes in the dialog; the parameters ride in the file.
//!
//! Import skips a host that is already stored: the same id, or the same kind,
//! address, port, and username. It does not overwrite that host. Keys match on
//! fingerprint, folders and tags on name, proxies on name and endpoint, shared
//! snippets on id or name.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::model::{
    serde_b64, AuthMethod, Group, JsonAead, KdfParams, ProxyChoice, ProxyDef, ServerEntry, Snippet,
    SshKey, Tag,
};
use super::{crypto, storage, VaultError, VaultManager};

const FORMAT: &str = "g-ssh-export";
const VERSION: u32 = 1;
/// Larger files are refused before the KDF runs.
pub const MAX_EXPORT_BYTES: usize = 32 * 1024 * 1024;
/// Vault memory cost, in KiB. An export file is not allowed to ask for more.
const MAX_KDF_MEMORY_KIB: u32 = 262_144;

/// What to put in an export file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportScope {
    Connection(Uuid),
    Group(Uuid),
}

/// Plaintext of a sealed export. Holds connection passwords and key material.
pub struct ExportBundle {
    pub(crate) groups: Vec<Group>,
    pub(crate) tags: Vec<Tag>,
    pub(crate) proxies: Vec<ProxyDef>,
    pub(crate) snippets: Vec<Snippet>,
    pub(crate) keys: Vec<SshKey>,
    pub(crate) hosts: Vec<ServerEntry>,
}

impl ExportBundle {
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }
}

impl fmt::Debug for ExportBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportBundle")
            .field("hosts", &self.hosts.len())
            .field("keys", &self.keys.len())
            .field("groups", &self.groups.len())
            .finish()
    }
}

/// What an import changed. A skipped host was already in the vault and was left as it was.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub added: usize,
    pub skipped: usize,
    pub keys_added: usize,
    pub keys_failed: usize,
    pub jumps_dropped: usize,
    /// Set when the records are in memory but the vault file could not be written.
    pub save_error: Option<String>,
}

/// True when `bytes` is a version-1 g-ssh export. Does not check the password.
pub fn is_gssh_export(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_EXPORT_BYTES {
        return false;
    }
    serde_json::from_slice::<ExportPeek>(bytes)
        .is_ok_and(|peek| peek.format == FORMAT && peek.version == VERSION)
}

/// Seal `bundle` with `password`. The bytes are the file to write.
pub fn seal_export(password: &str, bundle: &ExportBundle) -> Result<Vec<u8>, VaultError> {
    seal_export_with_params(password, bundle, &export_kdf())
}

/// Open a file produced by [`seal_export`]. A wrong password is `InvalidPassword`.
pub fn open_export(password: &str, bytes: &[u8]) -> Result<ExportBundle, VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }
    if bytes.len() > MAX_EXPORT_BYTES {
        return Err(VaultError::Corrupted(
            "export file is larger than 32 MiB".into(),
        ));
    }
    let file: ExportFile = serde_json::from_slice(bytes)
        .map_err(|error| VaultError::Corrupted(format!("not a g-ssh export: {error}")))?;
    if file.format != FORMAT {
        return Err(VaultError::Corrupted("not a g-ssh export".into()));
    }
    if file.version != VERSION {
        return Err(VaultError::UnsupportedVersion(file.version));
    }
    accept_kdf(&file.kdf_params)?;
    let kek = crypto::derive_kek(password.as_bytes(), &file.kdf_salt, &file.kdf_params)?;
    let plain = crypto::open(
        &kek,
        export_aad(file.version).as_bytes(),
        &file.enc_payload.into(),
    )
    .map_err(|_| VaultError::InvalidPassword)?;
    let payload: SealedPayload = serde_json::from_slice(&plain)
        .map_err(|error| VaultError::Corrupted(format!("export payload: {error}")))?;
    Ok(payload.into())
}

/// Seal `bundle` and write it to `path`.
pub fn write_export(path: &Path, password: &str, bundle: &ExportBundle) -> Result<(), VaultError> {
    let bytes = seal_export(password, bundle)?;
    storage::write_atomic(path, &bytes)
}

/// Read a file written by [`write_export`].
pub fn read_export(path: &Path, password: &str) -> Result<ExportBundle, VaultError> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_EXPORT_BYTES as u64 {
        return Err(VaultError::Corrupted(
            "export file is larger than 32 MiB".into(),
        ));
    }
    open_export(password, &std::fs::read(path)?)
}

impl VaultManager {
    /// Hosts in `scope`, plus the jump hosts they need in order to connect,
    /// and the keys, folders, tags, proxies, and shared snippets those hosts use.
    pub fn export_bundle(&self, scope: ExportScope) -> Result<ExportBundle, VaultError> {
        let mut hosts = match scope {
            ExportScope::Connection(id) => vec![self.get_entry(id)?],
            ExportScope::Group(id) => {
                if !self.payload.groups.iter().any(|group| group.id == id) {
                    return Err(VaultError::GroupNotFound(id));
                }
                let ids = groups_under(&self.payload.groups, id);
                self.payload
                    .entries
                    .iter()
                    .filter(|entry| entry.group.is_some_and(|group| ids.contains(&group)))
                    .cloned()
                    .collect()
            }
        };
        include_jump_hosts(self, &mut hosts);

        let mut bundle = ExportBundle {
            groups: Vec::new(),
            tags: Vec::new(),
            proxies: Vec::new(),
            snippets: Vec::new(),
            keys: Vec::new(),
            hosts,
        };
        for host in &bundle.hosts {
            if let Some(group) = host.group {
                push_group_chain(&self.payload.groups, group, &mut bundle.groups);
            }
            push_unique(&mut bundle.tags, &self.payload.tags, &host.tags);
            if let ProxyChoice::Use(proxy_id) = host.proxy {
                if let Some(proxy) = self
                    .payload
                    .proxies
                    .iter()
                    .find(|proxy| proxy.id == proxy_id)
                {
                    if !bundle.proxies.iter().any(|kept| kept.id == proxy.id) {
                        bundle.proxies.push(proxy.clone());
                    }
                }
            }
            if let Some(snippet_id) = shared_snippet_id(host) {
                if !bundle
                    .snippets
                    .iter()
                    .any(|snippet| snippet.id == snippet_id)
                {
                    if let Some(snippet) = self
                        .payload
                        .snippets
                        .iter()
                        .find(|snippet| snippet.id == snippet_id)
                    {
                        let mut copy = snippet.clone();
                        copy.usages.clear();
                        bundle.snippets.push(copy);
                    }
                }
            }
            if let AuthMethod::PrivateKey { key_id } = host.auth {
                if bundle.keys.iter().any(|key| key.id == key_id) {
                    continue;
                }
                if let Ok(key) = self.get_key(key_id) {
                    bundle.keys.push(key.clone());
                }
            }
        }
        Ok(bundle)
    }

    /// Restore `bundle`. Hosts already stored are counted as skipped and not changed.
    pub fn import_bundle(&mut self, bundle: ExportBundle) -> ImportReport {
        let mut report = ImportReport::default();
        let save = self.batch(|vm| {
            report = vm.apply_import(bundle);
        });
        if let Err(error) = save {
            report.save_error = Some(error.to_string());
        }
        report
    }

    fn apply_import(&mut self, bundle: ExportBundle) -> ImportReport {
        let mut report = ImportReport::default();
        let mut host_ids: HashMap<Uuid, Uuid> = HashMap::new();
        let mut adding: Vec<ServerEntry> = Vec::new();
        for host in bundle.hosts {
            if let Some(existing) = self
                .payload
                .entries
                .iter()
                .find(|entry| entry.id == host.id)
            {
                host_ids.insert(host.id, existing.id);
                report.skipped += 1;
                continue;
            }
            if let Some(existing) = self
                .payload
                .entries
                .iter()
                .find(|entry| same_connection(entry, &host))
            {
                host_ids.insert(host.id, existing.id);
                report.skipped += 1;
                continue;
            }
            if let Some(first) = adding
                .iter()
                .find(|entry| entry.id == host.id || same_connection(entry, &host))
            {
                host_ids.insert(host.id, first.id);
                report.skipped += 1;
                continue;
            }
            host_ids.insert(host.id, host.id);
            adding.push(host);
        }

        let key_ids = self.import_keys(&adding, &bundle.keys, &mut report);
        let proxy_ids = self.import_proxies(&adding, &bundle.proxies);
        let snippet_ids = self.import_snippets(&adding, &bundle.snippets);
        let tag_ids = self.import_tags(&adding, &bundle.tags);

        let mut jumps = Vec::new();
        let mut group_ids = HashMap::new();
        for mut host in adding {
            host.group = host
                .group
                .and_then(|id| self.map_group(&bundle.groups, id, &mut group_ids, 0));
            host.tags = host
                .tags
                .iter()
                .filter_map(|id| tag_ids.get(id).copied())
                .collect();
            if let ProxyChoice::Use(id) = host.proxy {
                host.proxy = proxy_ids
                    .get(&id)
                    .copied()
                    .map(ProxyChoice::Use)
                    .unwrap_or_default();
            }
            if let AuthMethod::PrivateKey { key_id } = host.auth {
                if let Some(mapped) = key_ids.get(&key_id) {
                    host.auth = AuthMethod::PrivateKey { key_id: *mapped };
                }
            }
            if let Some(snippet_id) = host.startup_snippet {
                let owns_it = host.snippets.iter().any(|snippet| snippet.id == snippet_id);
                if !owns_it {
                    host.startup_snippet = snippet_ids.get(&snippet_id).copied();
                }
            }
            let id = host.id;
            let jump = host.jump_host.take();
            if let Err(error) = self.add_entry(host) {
                tracing::error!(?error, "could not import a connection");
                host_ids.remove(&id);
                continue;
            }
            report.added += 1;
            if let Some(jump) = jump {
                jumps.push((id, jump));
            }
        }
        for (id, jump) in jumps {
            let target = host_ids.get(&jump).copied().unwrap_or(jump);
            if self.set_entry_jump_host(id, Some(target)).is_err() {
                report.jumps_dropped += 1;
            }
        }
        report
    }

    fn import_keys(
        &mut self,
        hosts: &[ServerEntry],
        keys: &[SshKey],
        report: &mut ImportReport,
    ) -> HashMap<Uuid, Uuid> {
        let mut map = HashMap::new();
        for key in keys {
            if !hosts.iter().any(
                |host| matches!(host.auth, AuthMethod::PrivateKey { key_id } if key_id == key.id),
            ) {
                continue;
            }
            let old_id = key.id;
            match self.take_key(key) {
                Ok((new_id, added)) => {
                    if added {
                        report.keys_added += 1;
                    }
                    map.insert(old_id, new_id);
                }
                Err(VaultError::InvalidKey(message)) => {
                    tracing::warn!(%message, "could not import an SSH key");
                    report.keys_failed += 1;
                }
                Err(error) => tracing::error!(?error, "could not import an SSH key"),
            }
        }
        map
    }

    /// Insert `key` under its id, or return the id of a key with the same fingerprint.
    fn take_key(&mut self, key: &SshKey) -> Result<(Uuid, bool), VaultError> {
        let (fingerprint, key_type) =
            super::derive_key_metadata(&key.pem, key.passphrase.as_deref())?;
        if let Some(existing) = self
            .payload
            .keys
            .iter()
            .find(|stored| stored.fingerprint == fingerprint)
        {
            return Ok((existing.id, false));
        }
        let id = if self.payload.keys.iter().any(|stored| stored.id == key.id) {
            Uuid::new_v4()
        } else {
            key.id
        };
        self.payload.keys.push(SshKey {
            id,
            name: key.name.clone(),
            created_at: key.created_at,
            fingerprint,
            key_type,
            pem: key.pem.clone(),
            passphrase: key.passphrase.clone(),
        });
        Ok((id, true))
    }

    fn import_proxies(
        &mut self,
        hosts: &[ServerEntry],
        proxies: &[ProxyDef],
    ) -> HashMap<Uuid, Uuid> {
        let mut map = HashMap::new();
        for proxy in proxies {
            let used = hosts
                .iter()
                .any(|host| host.proxy == ProxyChoice::Use(proxy.id));
            if !used {
                continue;
            }
            if let Some(existing) = self
                .payload
                .proxies
                .iter()
                .find(|stored| stored.id == proxy.id)
            {
                map.insert(proxy.id, existing.id);
                continue;
            }
            if let Some(existing) = self
                .payload
                .proxies
                .iter()
                .find(|stored| same_proxy(stored, proxy))
            {
                map.insert(proxy.id, existing.id);
                continue;
            }
            map.insert(proxy.id, proxy.id);
            self.payload.proxies.push(proxy.clone());
        }
        map
    }

    fn import_snippets(
        &mut self,
        hosts: &[ServerEntry],
        snippets: &[Snippet],
    ) -> HashMap<Uuid, Uuid> {
        let mut map = HashMap::new();
        for snippet in snippets {
            let used = hosts
                .iter()
                .any(|host| shared_snippet_id(host) == Some(snippet.id));
            if !used {
                continue;
            }
            if self
                .payload
                .snippets
                .iter()
                .any(|stored| stored.id == snippet.id)
            {
                map.insert(snippet.id, snippet.id);
                continue;
            }
            if let Some(existing) = self.find_snippet_by_name(&snippet.name) {
                map.insert(snippet.id, existing);
                continue;
            }
            let mut copy = snippet.clone();
            copy.usages.clear();
            map.insert(snippet.id, copy.id);
            self.payload.snippets.push(copy);
        }
        map
    }

    fn import_tags(&mut self, hosts: &[ServerEntry], tags: &[Tag]) -> HashMap<Uuid, Uuid> {
        let mut map = HashMap::new();
        for tag in tags {
            if tag.name.trim().is_empty() {
                continue;
            }
            if !hosts.iter().any(|host| host.tags.contains(&tag.id)) {
                continue;
            }
            if let Ok(id) = self.find_or_create_tag(&tag.name) {
                map.insert(tag.id, id);
            }
        }
        map
    }

    fn map_group(
        &mut self,
        groups: &[Group],
        id: Uuid,
        map: &mut HashMap<Uuid, Uuid>,
        depth: usize,
    ) -> Option<Uuid> {
        if depth > 16 {
            return None;
        }
        if let Some(mapped) = map.get(&id) {
            return Some(*mapped);
        }
        let group = groups.iter().find(|group| group.id == id)?;
        let name = group.name.trim();
        if name.is_empty() {
            return None;
        }
        let parent = group
            .parent_id
            .filter(|parent| *parent != id)
            .and_then(|parent| self.map_group(groups, parent, map, depth + 1));
        let created = self.find_or_create_group(name, parent).ok()?;
        map.insert(id, created);
        Some(created)
    }
}

fn include_jump_hosts(vault: &VaultManager, hosts: &mut Vec<ServerEntry>) {
    let mut seen: HashSet<Uuid> = hosts.iter().map(|host| host.id).collect();
    let mut queue: Vec<Uuid> = hosts.iter().filter_map(|host| host.jump_host).collect();
    while let Some(id) = queue.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Ok(entry) = vault.get_entry(id) else {
            continue;
        };
        if let Some(next) = entry.jump_host {
            queue.push(next);
        }
        hosts.push(entry);
    }
}

fn groups_under(groups: &[Group], root: Uuid) -> HashSet<Uuid> {
    let mut set = HashSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !set.insert(id) {
            continue;
        }
        for group in groups {
            if group.parent_id == Some(id) {
                stack.push(group.id);
            }
        }
    }
    set
}

fn push_group_chain(groups: &[Group], id: Uuid, into: &mut Vec<Group>) {
    let mut chain = Vec::new();
    let mut cursor = Some(id);
    let mut guard = 0;
    while let Some(current) = cursor {
        if guard > 16 || chain.iter().any(|group: &Group| group.id == current) {
            break;
        }
        guard += 1;
        let Some(group) = groups.iter().find(|group| group.id == current) else {
            break;
        };
        chain.push(group.clone());
        cursor = group.parent_id;
    }
    chain.reverse();
    for group in chain {
        if !into.iter().any(|kept| kept.id == group.id) {
            into.push(group);
        }
    }
}

fn push_unique(into: &mut Vec<Tag>, tags: &[Tag], ids: &[Uuid]) {
    for id in ids {
        if into.iter().any(|tag| tag.id == *id) {
            continue;
        }
        if let Some(tag) = tags.iter().find(|tag| tag.id == *id) {
            into.push(tag.clone());
        }
    }
}

fn shared_snippet_id(host: &ServerEntry) -> Option<Uuid> {
    let id = host.startup_snippet?;
    if host.snippets.iter().any(|snippet| snippet.id == id) {
        None
    } else {
        Some(id)
    }
}

fn same_connection(left: &ServerEntry, right: &ServerEntry) -> bool {
    left.kind == right.kind
        && left.port == right.port
        && left.host.eq_ignore_ascii_case(&right.host)
        && left.username.eq_ignore_ascii_case(&right.username)
}

fn same_proxy(left: &ProxyDef, right: &ProxyDef) -> bool {
    left.kind == right.kind
        && left.port == right.port
        && left.host.eq_ignore_ascii_case(&right.host)
        && left.name.eq_ignore_ascii_case(&right.name)
}

/// shortcut: 19 MiB Argon2id instead of the vault's 256 MiB, so export finishes
/// in the dialog; raise it in a new file version if exports need that memory cost.
fn export_kdf() -> KdfParams {
    KdfParams {
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
    }
}

fn export_aad(version: u32) -> String {
    format!("g-ssh-export.v{version}")
}

fn accept_kdf(params: &KdfParams) -> Result<(), VaultError> {
    if params.m_cost == 0
        || params.m_cost > MAX_KDF_MEMORY_KIB
        || params.t_cost == 0
        || params.t_cost > 8
        || params.p_cost == 0
        || params.p_cost > 4
    {
        return Err(VaultError::Corrupted(
            "export KDF params are not allowed".into(),
        ));
    }
    Ok(())
}

fn seal_export_with_params(
    password: &str,
    bundle: &ExportBundle,
    params: &KdfParams,
) -> Result<Vec<u8>, VaultError> {
    if password.is_empty() {
        return Err(VaultError::EmptyPassword);
    }
    accept_kdf(params)?;
    let payload = SealedPayload::from(bundle);
    let plain = Zeroizing::new(
        serde_json::to_vec(&payload)
            .map_err(|error| VaultError::Corrupted(format!("export payload: {error}")))?,
    );
    let salt = crypto::generate_salt();
    let kek = crypto::derive_kek(password.as_bytes(), &salt, params)?;
    let blob = crypto::seal(&kek, export_aad(VERSION).as_bytes(), &plain);
    let file = ExportFile {
        format: FORMAT.to_string(),
        version: VERSION,
        kdf_salt: salt,
        kdf_params: params.clone(),
        enc_payload: JsonAead::from(&blob),
    };
    let mut bytes = serde_json::to_vec(&file)
        .map_err(|error| VaultError::Corrupted(format!("export file: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Deserialize)]
struct ExportPeek {
    format: String,
    version: u32,
}

#[derive(Serialize, Deserialize)]
struct ExportFile {
    format: String,
    version: u32,
    #[serde(with = "serde_b64::array32")]
    kdf_salt: [u8; 32],
    kdf_params: KdfParams,
    enc_payload: JsonAead,
}

#[derive(Serialize, Deserialize)]
struct SealedPayload {
    #[serde(default)]
    groups: Vec<Group>,
    #[serde(default)]
    tags: Vec<Tag>,
    #[serde(default)]
    proxies: Vec<ProxyDef>,
    #[serde(default)]
    snippets: Vec<Snippet>,
    #[serde(default)]
    keys: Vec<SshKey>,
    #[serde(default)]
    hosts: Vec<ServerEntry>,
}

impl From<&ExportBundle> for SealedPayload {
    fn from(bundle: &ExportBundle) -> Self {
        Self {
            groups: bundle.groups.clone(),
            tags: bundle.tags.clone(),
            proxies: bundle.proxies.clone(),
            snippets: bundle.snippets.clone(),
            keys: bundle.keys.clone(),
            hosts: bundle.hosts.clone(),
        }
    }
}

impl From<SealedPayload> for ExportBundle {
    fn from(payload: SealedPayload) -> Self {
        Self {
            groups: payload.groups,
            tags: payload.tags,
            proxies: payload.proxies,
            snippets: payload.snippets,
            keys: payload.keys,
            hosts: payload.hosts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::connection::ConnectionKind;
    use crate::vault::{
        AuthMethod, HostSnippet, ProxyAuth, ProxyChoice, ProxyKind, SnippetBody, VaultManager,
    };
    use secrecy::SecretString;

    const PLAIN_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDNCBAqbPr5W4GmLORUKjfNKAm4w1exA7cV631Qp+ehzgAAAIgdqxg9HasY
PQAAAAtzc2gtZWQyNTUxOQAAACDNCBAqbPr5W4GmLORUKjfNKAm4w1exA7cV631Qp+ehzg
AAAEBYVd5eVr/WVKNvr18oR7cHE3FAe9v0ttFY2vO9tSenEc0IECps+vlbgaYs5FQqN80o
CbjDV7EDtxXrfVCn56HOAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----
";

    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_cost: 256,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn pw(text: &str) -> SecretString {
        SecretString::from(text.to_string())
    }

    fn fresh(dir: &Path) -> VaultManager {
        VaultManager::create_with_params(&dir.join("vault.json"), &pw("hunter2"), fast_kdf())
            .unwrap()
            .0
    }

    fn host(label: &str, name: &str) -> ServerEntry {
        ServerEntry {
            id: Uuid::new_v4(),
            label: label.into(),
            host: name.into(),
            port: 22,
            kind: ConnectionKind::Ssh,
            username: "deploy".into(),
            auth: AuthMethod::Password("s3cr3t".into()),
            notes: None,
            os: None,
            last_opened_at: None,
            host_key_fingerprint: None,
            last_remote_dir: None,
            last_local_dir: None,
            group: None,
            tags: Vec::new(),
            proxy: ProxyChoice::Default,
            jump_host: None,
            forwards: Vec::new(),
            startup_snippet: None,
            snippets: Vec::new(),
            rdp: Default::default(),
            vnc: Default::default(),
            sort_order: 0,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        }
    }

    fn password_of(entry: &ServerEntry) -> &str {
        match &entry.auth {
            AuthMethod::Password(password) => password,
            other => panic!("expected a password, got {other:?}"),
        }
    }

    #[test]
    fn the_sealed_file_hides_secrets_and_opens_with_the_password() {
        let bundle = ExportBundle {
            groups: Vec::new(),
            tags: Vec::new(),
            proxies: Vec::new(),
            snippets: Vec::new(),
            keys: Vec::new(),
            hosts: vec![host("web", "web.example")],
        };
        let sealed = seal_export_with_params("export-pw", &bundle, &fast_kdf()).unwrap();
        let text = String::from_utf8(sealed.clone()).unwrap();
        assert!(text.contains("g-ssh-export"));
        assert!(!text.contains("s3cr3t"));
        assert!(!text.contains("web.example"));
        assert!(is_gssh_export(&sealed));

        let opened = open_export("export-pw", &sealed).unwrap();
        assert_eq!(password_of(&opened.hosts[0]), "s3cr3t");
        assert!(matches!(
            open_export("nope", &sealed),
            Err(VaultError::InvalidPassword)
        ));
        assert!(matches!(
            seal_export("", &bundle),
            Err(VaultError::EmptyPassword)
        ));

        let huge = text.replace("\"m_cost\":256", "\"m_cost\":99999999");
        assert!(matches!(
            open_export("export-pw", huge.as_bytes()),
            Err(VaultError::Corrupted(_))
        ));
        let future = text.replace("\"version\":1", "\"version\":99");
        assert!(matches!(
            open_export("export-pw", future.as_bytes()),
            Err(VaultError::UnsupportedVersion(99))
        ));
        assert!(!is_gssh_export(b"{\"format\":\"other\"}"));
    }

    #[test]
    fn a_group_export_restores_onto_a_fresh_vault_and_skips_duplicates() {
        let source_dir = tempfile::tempdir().unwrap();
        let mut source = fresh(source_dir.path());
        let work = source.find_or_create_group("Work", None).unwrap();
        let eu = source.find_or_create_group("EU", Some(work)).unwrap();
        let other = source.find_or_create_group("Other", None).unwrap();
        let tag = source.find_or_create_tag("prod").unwrap();
        let key_id = source
            .add_key("test".into(), PLAIN_KEY.into(), None)
            .unwrap();
        let proxy_id = source
            .add_proxy(
                "edge".into(),
                ProxyKind::Socks5,
                "127.0.0.1".into(),
                1080,
                Some(ProxyAuth {
                    username: "p".into(),
                    password: "proxy-secret".into(),
                }),
            )
            .unwrap();
        let snippet_id = source
            .add_snippet(
                "motd".into(),
                None,
                SnippetBody::Script {
                    content: "echo hi".into(),
                },
            )
            .unwrap();

        let mut bastion = host("bastion", "bastion.example");
        bastion.group = Some(other);
        bastion.auth = AuthMethod::PrivateKey { key_id };
        let bastion_id = bastion.id;
        source.add_entry(bastion).unwrap();

        let mut web = host("web", "web.example");
        web.group = Some(eu);
        web.tags = vec![tag];
        web.proxy = ProxyChoice::Use(proxy_id);
        web.jump_host = Some(bastion_id);
        web.startup_snippet = Some(snippet_id);
        web.snippets = vec![HostSnippet {
            id: Uuid::new_v4(),
            name: "up".into(),
            script: "uptime".into(),
        }];
        let own_snippet = web.snippets[0].id;
        let web_id = web.id;
        source.add_entry(web).unwrap();

        let mut stray = host("stray", "stray.example");
        stray.group = Some(other);
        source.add_entry(stray).unwrap();

        let group_file = source.export_bundle(ExportScope::Group(work)).unwrap();
        let mut labels: Vec<_> = group_file
            .hosts
            .iter()
            .map(|host| host.label.as_str())
            .collect();
        labels.sort();
        assert_eq!(labels, ["bastion", "web"]);
        let one = source
            .export_bundle(ExportScope::Connection(web_id))
            .unwrap();
        assert_eq!(one.host_count(), 2);

        let sealed = seal_export_with_params("export-pw", &group_file, &fast_kdf()).unwrap();
        let text = String::from_utf8(sealed.clone()).unwrap();
        assert!(!text.contains("s3cr3t"));
        assert!(!text.contains("proxy-secret"));
        assert!(!text.contains("OPENSSH"));
        let opened = open_export("export-pw", &sealed).unwrap();

        let dest_dir = tempfile::tempdir().unwrap();
        let mut dest = fresh(dest_dir.path());
        let report = dest.import_bundle(opened);
        assert_eq!(report.added, 2);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.keys_added, 1);
        assert_eq!(report.jumps_dropped, 0);
        assert!(report.save_error.is_none());

        let web = dest.get_entry(web_id).unwrap();
        assert_eq!(password_of(&web), "s3cr3t");
        assert_eq!(web.jump_host, Some(bastion_id));
        assert_eq!(web.snippets[0].script, "uptime");
        assert_eq!(
            dest.script_for_host(web_id, snippet_id).as_deref(),
            Some("echo hi")
        );
        assert_eq!(
            dest.script_for_host(web_id, own_snippet).as_deref(),
            Some("uptime")
        );
        let summaries = dest.list_entries().unwrap();
        let web_summary = summaries.iter().find(|entry| entry.id == web_id).unwrap();
        assert_eq!(web_summary.group_name.as_deref(), Some("Work / EU"));
        assert_eq!(web_summary.tag_names, ["prod"]);
        let ProxyChoice::Use(imported_proxy) = web.proxy else {
            panic!("web lost its proxy");
        };
        assert_eq!(
            dest.get_proxy(imported_proxy)
                .unwrap()
                .auth
                .as_ref()
                .unwrap()
                .password,
            "proxy-secret"
        );

        drop(dest);
        let mut dest =
            VaultManager::unlock_with_password(&dest_dir.path().join("vault.json"), &pw("hunter2"))
                .unwrap();
        assert_eq!(password_of(&dest.get_entry(web_id).unwrap()), "s3cr3t");
        let AuthMethod::PrivateKey { key_id } = dest.get_entry(bastion_id).unwrap().auth else {
            panic!("bastion lost its key");
        };
        assert_eq!(dest.get_key(key_id).unwrap().pem.as_str(), PLAIN_KEY);

        let again = dest.import_bundle(open_export("export-pw", &sealed).unwrap());
        assert_eq!(again.added, 0);
        assert_eq!(again.skipped, 2);
        assert_eq!(password_of(&dest.get_entry(web_id).unwrap()), "s3cr3t");

        let twin_dir = tempfile::tempdir().unwrap();
        let mut twin_vault = fresh(twin_dir.path());
        let mut twin = host("web", "web.example");
        twin.auth = AuthMethod::Password("keep-mine".into());
        let twin_id = twin.id;
        twin_vault.add_entry(twin).unwrap();
        let mixed = twin_vault.import_bundle(open_export("export-pw", &sealed).unwrap());
        assert_eq!(mixed.added, 1);
        assert_eq!(mixed.skipped, 1);
        assert_eq!(
            password_of(&twin_vault.get_entry(twin_id).unwrap()),
            "keep-mine"
        );
        let AuthMethod::PrivateKey { key_id } = twin_vault.get_entry(bastion_id).unwrap().auth
        else {
            panic!("bastion lost its key");
        };
        assert_eq!(twin_vault.get_key(key_id).unwrap().pem.as_str(), PLAIN_KEY);
    }
}
