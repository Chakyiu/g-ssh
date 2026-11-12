//! One JSON file per host, under `connections/<group>/`, so a host can be
//! copied out by copying its file. The password in the file is sealed with the
//! vault key. A file from another vault still opens as a host, but its password
//! stays ciphertext until someone types a new one.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::model::{
    AeadBlob, AuthMethod, Group, HostSnippet, JsonAead, PortForward, ProxyChoice, ServerEntry,
};
use super::storage;
use super::{crypto, VaultError};

const MAX_CONNECTION_FILE: u64 = 1024 * 1024;
const MAX_NAME_CHARS: usize = 80;
const MAX_GROUP_DEPTH: usize = 16;

pub(super) struct LoadedConnections {
    pub entries: Vec<ServerEntry>,
    pub paths: HashMap<Uuid, PathBuf>,
    pub extras: Vec<PathBuf>,
    /// The password ciphertext each host was loaded with, so a later save can
    /// write the same bytes when the password did not change.
    pub password_blobs: HashMap<Uuid, AeadBlob>,
}

pub(super) struct StoredConnections {
    pub paths: HashMap<Uuid, PathBuf>,
    pub password_blobs: HashMap<Uuid, AeadBlob>,
}

pub(super) fn load(
    dir: &Path,
    dek: &[u8; 32],
    groups: &mut Vec<Group>,
) -> Result<LoadedConnections, VaultError> {
    let found = scan(dir)?;
    let mut best: HashMap<Uuid, Candidate> = HashMap::new();
    let mut extras = Vec::new();

    for file in found {
        let Some(candidate) = read_candidate(&file, dek, groups) else {
            continue;
        };
        match best.remove(&candidate.entry.id) {
            None => {
                best.insert(candidate.entry.id, candidate);
            }
            Some(existing) => {
                let keep_new = candidate.entry.updated_at > existing.entry.updated_at
                    || (candidate.entry.updated_at == existing.entry.updated_at
                        && candidate.path < existing.path);
                if keep_new {
                    extras.push(existing.path);
                    best.insert(candidate.entry.id, candidate);
                } else {
                    extras.push(candidate.path);
                }
            }
        }
    }

    let mut entries = Vec::with_capacity(best.len());
    let mut paths = HashMap::with_capacity(best.len());
    let mut password_blobs = HashMap::new();
    for (id, candidate) in best {
        if let Some(blob) = candidate.password_blob {
            password_blobs.insert(id, blob);
        }
        paths.insert(id, candidate.path);
        entries.push(candidate.entry);
    }
    entries.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.id.cmp(&right.id))
    });

    Ok(LoadedConnections {
        entries,
        paths,
        extras,
        password_blobs,
    })
}

pub(super) fn store(
    dir: &Path,
    dek: &[u8; 32],
    groups: &[Group],
    entries: &[ServerEntry],
    previous: &HashMap<Uuid, PathBuf>,
    extras: &[PathBuf],
    loaded_blobs: &HashMap<Uuid, AeadBlob>,
) -> Result<StoredConnections, VaultError> {
    std::fs::create_dir_all(dir)?;

    let mut by_dir: HashMap<PathBuf, Vec<&ServerEntry>> = HashMap::new();
    for entry in entries {
        by_dir
            .entry(relative_dir(groups, entry.group))
            .or_default()
            .push(entry);
    }

    let mut paths = HashMap::with_capacity(entries.len());
    let mut password_blobs = HashMap::new();
    for (rel_dir, group_entries) in &by_dir {
        let names = file_names(group_entries);
        for entry in group_entries {
            let name = names
                .get(&entry.id)
                .expect("every entry in the group is named");
            let path = dir.join(rel_dir).join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let (file, blob) = connection_file(entry, dek, loaded_blobs);
            if let Some(blob) = blob {
                password_blobs.insert(entry.id, blob);
            }
            let mut bytes = serde_json::to_vec_pretty(&file)
                .map_err(|e| VaultError::Corrupted(format!("JSON encode: {e}")))?;
            bytes.push(b'\n');
            if std::fs::read(&path).ok().as_deref() != Some(bytes.as_slice()) {
                storage::write_atomic(&path, &bytes)?;
            }
            paths.insert(entry.id, path);
        }
    }

    let live: HashSet<&Path> = paths.values().map(PathBuf::as_path).collect();
    let mut removed = Vec::new();
    for old in previous.values().chain(extras.iter()) {
        if live.contains(old.as_path()) {
            continue;
        }
        remove_file_if_present(old)?;
        removed.push(old.clone());
    }
    for path in &removed {
        if let Some(parent) = path.parent() {
            remove_empty_parents(parent, dir);
        }
    }

    Ok(StoredConnections {
        paths,
        password_blobs,
    })
}

struct Found {
    path: PathBuf,
    rel_dir: PathBuf,
}

struct Candidate {
    entry: ServerEntry,
    path: PathBuf,
    password_blob: Option<AeadBlob>,
}

fn scan(dir: &Path) -> Result<Vec<Found>, VaultError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    if !dir.is_dir() {
        return Err(VaultError::Io(std::io::Error::other(
            "connections path is not a directory",
        )));
    }
    let mut found = Vec::new();
    walk(dir, Path::new(""), &mut found)?;
    Ok(found)
}

fn walk(dir: &Path, rel: &Path, out: &mut Vec<Found>) -> Result<(), VaultError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        // A link could point outside this folder. The file it names is not a host.
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if file_type.is_dir() {
            walk(&path, &rel.join(entry.file_name()), out)?;
        } else if file_type.is_file() && is_connection_file(&path) {
            out.push(Found {
                path,
                rel_dir: rel.to_path_buf(),
            });
        }
    }
    Ok(())
}

fn is_connection_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if name.starts_with('.') {
        return false;
    }
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
}

fn read_candidate(file: &Found, dek: &[u8; 32], groups: &mut Vec<Group>) -> Option<Candidate> {
    let data = read_file(&file.path)?;
    let parsed: ConnectionFile = match serde_json::from_slice(&data) {
        Ok(parsed) => parsed,
        Err(error) => {
            tracing::warn!(
                path = %file.path.display(),
                %error,
                "skipping a connection file that is not a host"
            );
            return None;
        }
    };
    let group = ensure_group(groups, &file.rel_dir);
    let (entry, password_blob) = entry_from_file(parsed, dek, group);
    Some(Candidate {
        entry,
        path: file.path.clone(),
        password_blob,
    })
}

fn read_file(path: &Path) -> Option<Vec<u8>> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) => {
            tracing::warn!(path = %path.display(), ?error, "skipping connection file");
            return None;
        }
    };
    if meta.len() > MAX_CONNECTION_FILE {
        tracing::warn!(
            path = %path.display(),
            bytes = meta.len(),
            "skipping a connection file larger than 1 MiB"
        );
        return None;
    }
    match std::fs::read(path) {
        Ok(data) => Some(data),
        Err(error) => {
            tracing::warn!(path = %path.display(), ?error, "skipping connection file");
            None
        }
    }
}

/// The folder the file sits in is the group, including a folder someone just
/// dropped a shared file into. Missing folders become groups.
fn ensure_group(groups: &mut Vec<Group>, rel: &Path) -> Option<Uuid> {
    if rel.as_os_str().is_empty() {
        return None;
    }
    let mut parent = None;
    for component in rel.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        let Some(name) = name.to_str() else {
            return parent;
        };
        if let Some(id) = segments_under(groups, parent)
            .into_iter()
            .find_map(|(id, segment)| segment.eq_ignore_ascii_case(name).then_some(id))
        {
            parent = Some(id);
            continue;
        }
        let id = Uuid::new_v4();
        groups.push(Group {
            id,
            name: name.to_string(),
            parent_id: parent,
        });
        parent = Some(id);
    }
    parent
}

fn relative_dir(groups: &[Group], group_id: Option<Uuid>) -> PathBuf {
    let Some(start) = group_id else {
        return PathBuf::new();
    };
    let mut parts = Vec::new();
    let mut cursor = start;
    for _ in 0..MAX_GROUP_DEPTH {
        let Some(group) = groups.iter().find(|group| group.id == cursor) else {
            return PathBuf::new();
        };
        let segment = segments_under(groups, group.parent_id)
            .get(&group.id)
            .cloned();
        let segment = segment.unwrap_or_else(|| sanitize_segment(&group.name));
        parts.push(segment);
        match group.parent_id {
            Some(parent) => cursor = parent,
            None => {
                parts.reverse();
                return parts.into_iter().collect();
            }
        }
    }
    PathBuf::new()
}

/// Folder name of each group under one parent. The lowest id keeps the plain
/// name; another group that would land on the same name gets its id appended.
fn segments_under(groups: &[Group], parent: Option<Uuid>) -> HashMap<Uuid, String> {
    let mut siblings: Vec<&Group> = groups
        .iter()
        .filter(|group| group.parent_id == parent)
        .collect();
    siblings.sort_by_key(|group| group.id);
    let mut used = HashSet::new();
    let mut out = HashMap::new();
    for group in siblings {
        let base = sanitize_segment(&group.name);
        let mut candidate = base.clone();
        if !used.insert(candidate.to_lowercase()) {
            candidate = format!("{base}-{}", short_id(group.id));
            if !used.insert(candidate.to_lowercase()) {
                candidate = format!("{base}-{}", group.id.simple());
                used.insert(candidate.to_lowercase());
            }
        }
        out.insert(group.id, candidate);
    }
    out
}

fn file_names(entries: &[&ServerEntry]) -> HashMap<Uuid, String> {
    let mut order: Vec<&ServerEntry> = entries.to_vec();
    order.sort_by_key(|entry| entry.id);
    let mut used = HashSet::new();
    let mut names = HashMap::new();
    for entry in order {
        let base = entry_stem(entry);
        let mut candidate = base.clone();
        if !used.insert(candidate.to_lowercase()) {
            candidate = format!("{base}-{}", short_id(entry.id));
            if !used.insert(candidate.to_lowercase()) {
                candidate = format!("{base}-{}", entry.id.simple());
                used.insert(candidate.to_lowercase());
            }
        }
        names.insert(entry.id, format!("{candidate}.json"));
    }
    names
}

fn entry_stem(entry: &ServerEntry) -> String {
    let label = entry.label.trim();
    let host = entry.host.trim();
    let source = if !label.is_empty() {
        label
    } else if !host.is_empty() {
        host
    } else {
        "connection"
    };
    sanitize_segment(source)
}

fn sanitize_segment(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().chars() {
        if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            out.push('-');
        } else {
            out.push(c);
        }
    }
    let trimmed = out.trim_matches(|c: char| c.is_whitespace() || c == '.' || c == '-');
    let mut result = if trimmed.is_empty() {
        "untitled".to_string()
    } else {
        truncate_chars(trimmed, MAX_NAME_CHARS)
    };
    if is_reserved(&result) {
        result.insert(0, '_');
    }
    result
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    text.chars().take(max).collect()
}

fn is_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM0"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT0"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn short_id(id: Uuid) -> String {
    let simple = id.simple().to_string();
    simple[..8].to_string()
}

fn remove_file_if_present(path: &Path) -> Result<(), VaultError> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(()) => Ok(()),
    }
}

/// After a host leaves a folder, drop the folder when nothing else is in it.
/// Stops at `root`, which is the `connections` directory itself.
fn remove_empty_parents(start: &Path, root: &Path) {
    let mut current = start.to_path_buf();
    loop {
        if current == root || !current.starts_with(root) {
            break;
        }
        if std::fs::remove_dir(&current).is_err() {
            break;
        }
        let Some(parent) = current.parent() else {
            break;
        };
        current = parent.to_path_buf();
    }
}

fn connection_file(
    entry: &ServerEntry,
    dek: &[u8; 32],
    loaded_blobs: &HashMap<Uuid, AeadBlob>,
) -> (ConnectionFile, Option<AeadBlob>) {
    let (auth, blob) = match &entry.auth {
        AuthMethod::Password(password) => {
            let blob = password_blob(dek, entry.id, password, loaded_blobs);
            (
                FileAuth::Password {
                    password: JsonAead::from(&blob),
                },
                Some(blob),
            )
        }
        AuthMethod::PrivateKey { key_id } => (FileAuth::PrivateKey { key_id: *key_id }, None),
        AuthMethod::Agent => (FileAuth::Agent, None),
    };
    (
        ConnectionFile {
            id: entry.id,
            label: entry.label.clone(),
            host: entry.host.clone(),
            port: entry.port,
            kind: entry.kind,
            username: entry.username.clone(),
            auth,
            notes: entry.notes.clone(),
            os: entry.os.clone(),
            last_opened_at: entry.last_opened_at,
            host_key_fingerprint: entry.host_key_fingerprint.clone(),
            last_remote_dir: entry.last_remote_dir.clone(),
            last_local_dir: entry.last_local_dir.clone(),
            tags: entry.tags.clone(),
            proxy: entry.proxy,
            jump_host: entry.jump_host,
            forwards: entry.forwards.clone(),
            startup_snippet: entry.startup_snippet,
            snippets: entry.snippets.clone(),
            rdp: entry.rdp,
            vnc: entry.vnc,
            sort_order: entry.sort_order,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        },
        blob,
    )
}

/// Reuse the ciphertext when it still opens to this password, or when it does
/// not open and the password is still empty: that file belongs to another vault
/// and a save must not replace its password with ours.
fn password_blob(
    dek: &[u8; 32],
    id: Uuid,
    password: &str,
    loaded_blobs: &HashMap<Uuid, AeadBlob>,
) -> AeadBlob {
    if let Some(blob) = loaded_blobs.get(&id) {
        match open_password(dek, id, blob) {
            Some(opened) if opened == password => return blob.clone(),
            None if password.is_empty() => return blob.clone(),
            _ => {}
        }
    }
    crypto::seal(dek, id.as_bytes(), password.as_bytes())
}

fn open_password(dek: &[u8; 32], id: Uuid, blob: &AeadBlob) -> Option<String> {
    let raw = crypto::open(dek, id.as_bytes(), blob).ok()?;
    String::from_utf8(raw.to_vec()).ok()
}

fn entry_from_file(
    file: ConnectionFile,
    dek: &[u8; 32],
    group: Option<Uuid>,
) -> (ServerEntry, Option<AeadBlob>) {
    let (auth, password_blob) = match file.auth {
        FileAuth::Password { password } => {
            let blob = AeadBlob::from(password);
            match open_password(dek, file.id, &blob) {
                Some(password) => (AuthMethod::Password(password), Some(blob)),
                None => {
                    tracing::warn!(
                        id = %file.id,
                        label = %file.label,
                        "connection password could not be opened; it stays encrypted"
                    );
                    (AuthMethod::Password(String::new()), Some(blob))
                }
            }
        }
        FileAuth::PrivateKey { key_id } => (AuthMethod::PrivateKey { key_id }, None),
        FileAuth::Agent => (AuthMethod::Agent, None),
    };
    (
        ServerEntry {
            id: file.id,
            label: file.label,
            host: file.host,
            port: file.port,
            kind: file.kind,
            username: file.username,
            auth,
            notes: file.notes,
            os: file.os,
            last_opened_at: file.last_opened_at,
            host_key_fingerprint: file.host_key_fingerprint,
            last_remote_dir: file.last_remote_dir,
            last_local_dir: file.last_local_dir,
            group,
            tags: file.tags,
            proxy: file.proxy,
            jump_host: file.jump_host,
            forwards: file.forwards,
            startup_snippet: file.startup_snippet,
            snippets: file.snippets,
            rdp: file.rdp,
            vnc: file.vnc,
            sort_order: file.sort_order,
            created_at: file.created_at,
            updated_at: file.updated_at,
        },
        password_blob,
    )
}

#[derive(Serialize, Deserialize)]
struct ConnectionFile {
    id: Uuid,
    label: String,
    host: String,
    port: u16,
    #[serde(
        default,
        skip_serializing_if = "crate::ssh::connection::ConnectionKind::is_ssh"
    )]
    kind: crate::ssh::connection::ConnectionKind,
    username: String,
    auth: FileAuth,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    last_opened_at: Option<i64>,
    #[serde(default)]
    host_key_fingerprint: Option<String>,
    #[serde(default)]
    last_remote_dir: Option<String>,
    #[serde(default)]
    last_local_dir: Option<String>,
    #[serde(default)]
    tags: Vec<Uuid>,
    #[serde(default)]
    proxy: ProxyChoice,
    #[serde(default)]
    jump_host: Option<Uuid>,
    #[serde(default)]
    forwards: Vec<PortForward>,
    #[serde(default)]
    startup_snippet: Option<Uuid>,
    #[serde(default)]
    snippets: Vec<HostSnippet>,
    /// See [`super::model::ServerEntry::rdp`].
    #[serde(default, skip_serializing_if = "crate::rdp::RdpSettings::is_default")]
    rdp: crate::rdp::RdpSettings,
    /// See [`super::model::ServerEntry::vnc`].
    #[serde(default, skip_serializing_if = "crate::vnc::VncSettings::is_default")]
    vnc: crate::vnc::VncSettings,
    /// See [`super::model::ServerEntry::sort_order`].
    #[serde(default, skip_serializing_if = "is_unset_order")]
    sort_order: i64,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
enum FileAuth {
    Password { password: JsonAead },
    PrivateKey { key_id: Uuid },
    Agent,
}

fn is_unset_order(order: &i64) -> bool {
    *order == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_names_drop_path_separators() {
        assert_eq!(sanitize_segment("A/B"), "A-B");
        assert_eq!(sanitize_segment("  "), "untitled");
        assert_eq!(sanitize_segment("CON"), "_CON");
        assert_eq!(sanitize_segment(".ssh"), "ssh");
        assert_eq!(sanitize_segment(".."), "untitled");
    }

    #[test]
    fn a_connection_file_without_an_order_stays_unset_and_omits_the_field() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "label": "web",
            "host": "web.example.com",
            "port": 22,
            "username": "me",
            "auth": { "method": "agent" }
        }"#;
        let file: ConnectionFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.sort_order, 0);
        let written = serde_json::to_string(&file).unwrap();
        assert!(
            !written.contains("sort_order"),
            "an unset order must not change the file: {written}"
        );

        let placed: ConnectionFile = serde_json::from_str(
            r#"{
                "id": "00000000-0000-0000-0000-000000000001",
                "label": "web",
                "host": "web.example.com",
                "port": 22,
                "username": "me",
                "auth": { "method": "agent" },
                "sort_order": 4
            }"#,
        )
        .unwrap();
        assert_eq!(placed.sort_order, 4);
        assert!(serde_json::to_string(&placed)
            .unwrap()
            .contains("\"sort_order\":4"));
    }

    #[test]
    fn a_connection_file_without_a_kind_is_ssh_and_omits_the_field() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "label": "web",
            "host": "web.example.com",
            "port": 22,
            "username": "me",
            "auth": { "method": "agent" }
        }"#;
        let file: ConnectionFile = serde_json::from_str(json).unwrap();
        assert!(file.kind.is_ssh());
        let written = serde_json::to_string(&file).unwrap();
        assert!(!written.contains("kind"), "{written}");

        let mut telnet: ConnectionFile = serde_json::from_str(json).unwrap();
        telnet.kind = crate::ssh::connection::ConnectionKind::Telnet;
        telnet.port = 23;
        let written = serde_json::to_string(&telnet).unwrap();
        assert!(written.contains("\"kind\":\"telnet\""), "{written}");
    }

    #[test]
    fn rdp_settings_are_omitted_at_the_default_and_kept_otherwise() {
        use crate::rdp::{RdpColorDepth, RdpResolution, RdpScale, RdpSettings};

        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "label": "desk",
            "host": "desk.example.com",
            "port": 3389,
            "kind": "rdp",
            "username": "me",
            "auth": { "method": "agent" }
        }"#;
        let mut file: ConnectionFile = serde_json::from_str(json).unwrap();
        assert!(file.rdp.is_default());
        let written = serde_json::to_string(&file).unwrap();
        assert!(!written.contains("\"rdp\":"), "{written}");

        let settings = RdpSettings {
            resolution: RdpResolution::Fixed {
                width: 1920,
                height: 1080,
            },
            color_depth: RdpColorDepth::Bits16,
            scale: RdpScale::Percent150,
            audio: true,
            clipboard: true,
        };
        file.rdp = settings;
        let written = serde_json::to_string(&file).unwrap();
        let read: ConnectionFile = serde_json::from_str(&written).unwrap();
        assert_eq!(read.rdp, settings);
    }

    #[test]
    fn vnc_hosts_round_trip_and_omit_default_settings() {
        use crate::vnc::{VncQuality, VncSettings};

        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000002",
            "label": "screen",
            "host": "screen.example.com",
            "port": 5900,
            "kind": "vnc",
            "username": "",
            "auth": { "method": "agent" }
        }"#;
        let mut file: ConnectionFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.kind, crate::ssh::connection::ConnectionKind::Vnc);
        assert!(file.vnc.is_default());
        let written = serde_json::to_string(&file).unwrap();
        assert!(!written.contains("\"vnc\":"), "{written}");

        let settings = VncSettings {
            quality: VncQuality::Lossless,
            resize_remote: true,
            view_only: false,
            clipboard: true,
        };
        file.vnc = settings;
        let written = serde_json::to_string(&file).unwrap();
        assert!(written.contains("\"quality\":\"lossless\""), "{written}");
        let read: ConnectionFile = serde_json::from_str(&written).unwrap();
        assert_eq!(read.vnc, settings);
    }
}
