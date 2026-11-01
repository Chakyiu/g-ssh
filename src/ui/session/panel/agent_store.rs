//! Agent chats for one host. The file sits beside preferences.json: it
//! belongs to this computer and is never synced. The bytes are sealed with
//! [`AgentChatKey`], which the master password unlocks. A missing or broken
//! file opens one empty chat. An older plaintext file is sealed the next
//! time it is read. A file sealed for another vault is moved aside, so this
//! vault can keep its own chats and the old bytes stay on disk.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gssh::vault::AgentChatKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

pub(super) const NEW_CHAT: &str = "New chat";
const MAX_CLOSED: usize = 40;
const FILE_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedCite {
    pub session: String,
    pub tab: String,
    pub lines: String,
    pub text: String,
}

/// A pasted picture, stored as standard base64 so an older chat file still loads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedImage {
    pub mime: String,
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum SavedBubble {
    User {
        text: String,
        #[serde(default)]
        cite: Option<SavedCite>,
        #[serde(default)]
        images: Vec<SavedImage>,
    },
    Agent {
        text: String,
        #[serde(default)]
        tokens: Option<u32>,
        #[serde(default)]
        millis: Option<u64>,
    },
    Command {
        command: String,
        #[serde(default)]
        reason: String,
        outcome: SavedOutcome,
    },
    Answer {
        question: String,
        answer: String,
        #[serde(default)]
        skipped: bool,
    },
    Note {
        text: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum SavedOutcome {
    Output { text: String },
    Denied,
    Failed { text: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub(super) enum SavedTurn {
    User {
        text: String,
        #[serde(default)]
        images: Vec<SavedImage>,
    },
    Assistant {
        #[serde(default)]
        text: String,
        #[serde(default)]
        calls: Vec<SavedCall>,
    },
    Tool {
        id: String,
        name: String,
        content: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedPendingCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub result: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedPending {
    pub text: String,
    pub calls: Vec<SavedPendingCall>,
    pub at: usize,
    #[serde(default)]
    pub fenced: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedChat {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub draft: String,
    #[serde(default)]
    pub rounds: u32,
    #[serde(default)]
    pub bubbles: Vec<SavedBubble>,
    #[serde(default)]
    pub transcript: Vec<SavedTurn>,
    #[serde(default)]
    pub pending: Option<SavedPending>,
    #[serde(default)]
    pub attachment: Option<SavedCite>,
    /// Pictures pasted into the composer and not yet sent.
    #[serde(default)]
    pub images: Vec<SavedImage>,
    /// Follow-ups the user sent while the agent was working.
    #[serde(default)]
    pub queue: Vec<SavedQueued>,
    #[serde(default)]
    pub phase: SavedPhase,
    #[serde(default)]
    pub error: Option<String>,
    /// The agent bubble a live reply is still writing.
    #[serde(default)]
    pub live_reply: Option<usize>,
    /// When the current model request started, as unix milliseconds.
    #[serde(default)]
    pub wait_started_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SavedPhase {
    #[default]
    Idle,
    Waiting,
    Approval,
    Running,
    /// A question card is waiting for an answer.
    Question,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(super) struct SavedQueued {
    pub text: String,
    #[serde(default)]
    pub cite: Option<SavedCite>,
    #[serde(default)]
    pub images: Vec<SavedImage>,
}

impl SavedChat {
    pub(super) fn fresh() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            title: NEW_CHAT.to_string(),
            draft: String::new(),
            rounds: 0,
            bubbles: Vec::new(),
            transcript: Vec::new(),
            pending: None,
            attachment: None,
            images: Vec::new(),
            queue: Vec::new(),
            phase: SavedPhase::Idle,
            error: None,
            live_reply: None,
            wait_started_ms: None,
        }
    }

    pub(super) fn is_blank(&self) -> bool {
        self.bubbles.is_empty()
            && self.transcript.is_empty()
            && self.pending.is_none()
            && self.attachment.is_none()
            && self.images.is_empty()
            && self.draft.trim().is_empty()
            && self.queue.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct ChatFile {
    #[serde(default = "file_version")]
    version: u32,
    #[serde(default)]
    open: Vec<SavedChat>,
    #[serde(default)]
    active: usize,
    #[serde(default)]
    closed: Vec<SavedChat>,
}

fn file_version() -> u32 {
    FILE_VERSION
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct ChatBook {
    pub open: Vec<SavedChat>,
    pub active: usize,
    pub closed: Vec<SavedChat>,
    /// False when a sealed file could not be moved aside. Saving would erase
    /// chats this vault cannot read.
    writable: bool,
}

impl ChatBook {
    pub(super) fn fresh() -> Self {
        Self {
            open: vec![SavedChat::fresh()],
            active: 0,
            closed: Vec::new(),
            writable: true,
        }
    }

    /// The file on disk belongs to another vault and could not be moved.
    /// A save would replace chats this vault cannot read.
    pub(super) fn can_save(&self) -> bool {
        self.writable
    }

    pub(super) fn load(host_id: &str, key: &AgentChatKey) -> Self {
        match chat_path(host_id) {
            Some(path) => Self::load_from(&path, key),
            None => Self::fresh(),
        }
    }

    pub(super) fn save(&self, host_id: &str, key: &AgentChatKey) {
        let Some(path) = chat_path(host_id) else {
            return;
        };
        if let Err(error) = self.save_to(&path, key) {
            tracing::warn!(?error, path = %path.display(), "could not save agent chats");
        }
    }

    pub(super) fn active_chat(&self) -> &SavedChat {
        &self.open[self.active]
    }

    /// `false` when the chat in front is already empty.
    pub(super) fn start_new(&mut self) -> bool {
        if self.active_chat().is_blank() {
            return false;
        }
        self.open.push(SavedChat::fresh());
        self.active = self.open.len() - 1;
        true
    }

    pub(super) fn close(&mut self, ix: usize) {
        if ix >= self.open.len() {
            return;
        }
        let chat = self.open.remove(ix);
        if !chat.is_blank() {
            self.closed.insert(0, chat);
            self.closed.truncate(MAX_CLOSED);
        }
        if self.open.is_empty() {
            self.open.push(SavedChat::fresh());
            self.active = 0;
            return;
        }
        if ix < self.active {
            self.active -= 1;
        } else if ix == self.active {
            self.active = ix.min(self.open.len() - 1);
        }
    }

    /// Drop a chat from the open tabs or from history. It is not kept.
    pub(super) fn forget(&mut self, id: &str) -> bool {
        if let Some(ix) = self.open.iter().position(|chat| chat.id == id) {
            self.open.remove(ix);
            if self.open.is_empty() {
                self.open.push(SavedChat::fresh());
                self.active = 0;
            } else if ix < self.active {
                self.active -= 1;
            } else if self.active >= self.open.len() {
                self.active = self.open.len() - 1;
            }
            return true;
        }
        if let Some(ix) = self.closed.iter().position(|chat| chat.id == id) {
            self.closed.remove(ix);
            return true;
        }
        false
    }

    pub(super) fn restore(&mut self, id: &str) -> bool {
        if let Some(ix) = self.open.iter().position(|chat| chat.id == id) {
            self.active = ix;
            return true;
        }
        let Some(pos) = self.closed.iter().position(|chat| chat.id == id) else {
            return false;
        };
        let chat = self.closed.remove(pos);
        self.open.push(chat);
        self.active = self.open.len() - 1;
        true
    }

    fn load_from(path: &Path, key: &AgentChatKey) -> Self {
        match Self::read_file(path, key) {
            Opened::Ready(book) => book,
            Opened::Unreadable => Self::unreadable(),
            Opened::Missing => Self::adopt_parked(path, key).unwrap_or_else(Self::fresh),
            Opened::Foreign => {
                if Self::park_foreign(path) {
                    Self::adopt_parked(path, key).unwrap_or_else(Self::fresh)
                } else {
                    Self::unreadable()
                }
            }
        }
    }

    fn unreadable() -> Self {
        let mut book = Self::fresh();
        book.writable = false;
        book
    }

    fn read_file(path: &Path, key: &AgentChatKey) -> Opened {
        let mut data = match std::fs::read(path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Opened::Missing,
            Err(error) => {
                tracing::warn!(?error, path = %path.display(), "failed to read agent chats");
                return Opened::Unreadable;
            }
        };
        let Some(host_id) = file_host_id(path) else {
            return Opened::Unreadable;
        };
        if AgentChatKey::is_sealed(&data) {
            return match key.open_file(host_id, &data) {
                Some(plain) => Opened::Ready(Self::parse_plain(&plain).unwrap_or_else(Self::fresh)),
                None => Opened::Foreign,
            };
        }
        let parsed = Self::parse_plain(&data);
        data.zeroize();
        match parsed {
            Some(book) => {
                // Replace the plaintext file now, so a later crash does not
                // leave the transcript sitting in the clear.
                if let Err(error) = book.save_to(path, key) {
                    tracing::warn!(?error, path = %path.display(), "could not seal agent chats");
                }
                Opened::Ready(book)
            }
            None => Opened::Ready(Self::fresh()),
        }
    }

    fn parse_plain(data: &[u8]) -> Option<Self> {
        let file: ChatFile = match serde_json::from_slice(data) {
            Ok(file) => file,
            Err(error) => {
                tracing::warn!(?error, "invalid agent chats, opening a new chat");
                return None;
            }
        };
        if file.version != FILE_VERSION || file.open.is_empty() {
            return None;
        }
        let active = file.active.min(file.open.len() - 1);
        Some(Self {
            open: file.open,
            active,
            closed: file.closed,
            writable: true,
        })
    }

    /// Move a file this vault cannot open to `<name>.sealed`, leaving the
    /// usual path free. A later unlock of the vault that wrote it can adopt
    /// the parked file.
    fn park_foreign(path: &Path) -> bool {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return false;
        };
        let Some(parent) = path.parent() else {
            return false;
        };
        for n in 0..1000 {
            let parked = if n == 0 {
                parent.join(format!("{name}.sealed"))
            } else {
                parent.join(format!("{name}.{n}.sealed"))
            };
            if parked.exists() {
                continue;
            }
            match std::fs::rename(path, &parked) {
                Ok(()) => {
                    tracing::warn!(
                        path = %path.display(),
                        kept = %parked.display(),
                        "agent chats are sealed for another vault and were kept aside"
                    );
                    return true;
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        path = %path.display(),
                        "could not move agent chats sealed for another vault"
                    );
                    return false;
                }
            }
        }
        false
    }

    /// A parked file this key can open becomes the live file again.
    fn adopt_parked(path: &Path, key: &AgentChatKey) -> Option<Self> {
        let host_id = file_host_id(path)?;
        let name = path.file_name().and_then(|name| name.to_str())?;
        let parent = path.parent()?;
        let prefix = format!("{name}.");
        let read = std::fs::read_dir(parent).ok()?;
        for entry in read.flatten() {
            let candidate = entry.path();
            let candidate_name = entry.file_name();
            let Some(candidate_name) = candidate_name.to_str() else {
                continue;
            };
            if !candidate_name.starts_with(&prefix) || !candidate_name.ends_with(".sealed") {
                continue;
            }
            let Ok(data) = std::fs::read(&candidate) else {
                continue;
            };
            let Some(plain) = key.open_file(host_id, &data) else {
                continue;
            };
            let book = Self::parse_plain(&plain).unwrap_or_else(Self::fresh);
            if book.save_to(path, key).is_ok() {
                let _ = std::fs::remove_file(&candidate);
            }
            return Some(book);
        }
        None
    }

    fn save_to(&self, path: &Path, key: &AgentChatKey) -> std::io::Result<()> {
        if !self.writable {
            return Ok(());
        }
        let Some(host_id) = file_host_id(path) else {
            return Err(std::io::Error::other("agent chat file has no host id"));
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = ChatFile {
            version: FILE_VERSION,
            open: self.open.clone(),
            active: self.active,
            closed: self.closed.clone(),
        };
        let mut json = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
        let sealed = key.seal_file(host_id, &json);
        json.zeroize();
        let unfinished = path.with_extension("json.new");
        write_private(&unfinished, &sealed)?;
        std::fs::rename(&unfinished, path)
    }
}

enum Opened {
    Ready(ChatBook),
    /// Not on disk.
    Missing,
    /// Sealed, and this vault's key does not open it.
    Foreign,
    /// Present, but a read error or a move failure means it must stay put.
    Unreadable,
}

pub(super) fn chat_title(question: &str, fallback: &str) -> String {
    let line = question
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("");
    if !line.is_empty() {
        return clip_title(line);
    }
    let fallback = fallback.trim();
    if fallback.is_empty() {
        NEW_CHAT.to_string()
    } else {
        clip_title(fallback)
    }
}

fn clip_title(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(42).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

static CHAT_RECORD_EPOCH: AtomicU64 = AtomicU64::new(0);

pub(crate) fn chat_record_epoch() -> u64 {
    CHAT_RECORD_EPOCH.load(Ordering::Relaxed)
}

fn bump_chat_records() {
    CHAT_RECORD_EPOCH.fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    pub host_id: String,
    pub chat_id: String,
    pub title: String,
}

pub fn list_session_records(key: &AgentChatKey) -> Vec<SessionRecord> {
    let Some(dir) = chats_dir() else {
        return Vec::new();
    };
    let Ok(read) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(host_id) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let book = ChatBook::load_from(&path, key);
        if !book.can_save() {
            continue;
        }
        for chat in book.open.iter().chain(&book.closed) {
            if chat.is_blank() {
                continue;
            }
            records.push(SessionRecord {
                host_id: host_id.to_string(),
                chat_id: chat.id.clone(),
                title: chat.title.clone(),
            });
        }
    }
    records.sort_by(|a, b| {
        a.host_id
            .cmp(&b.host_id)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.chat_id.cmp(&b.chat_id))
    });
    records
}

pub fn remove_session(key: &AgentChatKey, host_id: &str, chat_id: &str) {
    let Some(path) = chat_path(host_id) else {
        return;
    };
    let mut book = ChatBook::load_from(&path, key);
    if !book.can_save() || !book.forget(chat_id) {
        return;
    }
    if book
        .open
        .iter()
        .chain(&book.closed)
        .all(|chat| chat.is_blank())
    {
        let _ = std::fs::remove_file(&path);
    } else if book.save_to(&path, key).is_err() {
        return;
    }
    bump_chat_records();
}

pub fn clear_host_sessions(host_id: &str) {
    let Some(path) = chat_path(host_id) else {
        return;
    };
    let removed = std::fs::remove_file(&path).is_ok();
    let parked = remove_parked(&path);
    if removed || parked {
        bump_chat_records();
    }
}

pub fn clear_session_records() {
    let Some(dir) = chats_dir() else {
        return;
    };
    let Ok(read) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut removed = false;
    for entry in read.flatten() {
        let path = entry.path();
        if !is_chat_file(&path) {
            continue;
        }
        if std::fs::remove_file(&path).is_ok() {
            removed = true;
        }
    }
    if removed {
        bump_chat_records();
    }
}

fn file_host_id(path: &Path) -> Option<&str> {
    path.file_stem().and_then(|stem| stem.to_str())
}

fn is_chat_file(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("json")
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".sealed"))
}

fn remove_parked(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Ok(read) = std::fs::read_dir(parent) else {
        return false;
    };
    let prefix = format!("{name}.");
    let mut removed = false;
    for entry in read.flatten() {
        let candidate = entry.path();
        let candidate_name = entry.file_name();
        let Some(candidate_name) = candidate_name.to_str() else {
            continue;
        };
        if candidate_name.starts_with(&prefix) && candidate_name.ends_with(".sealed") {
            removed |= std::fs::remove_file(&candidate).is_ok();
        }
    }
    removed
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

fn chats_dir() -> Option<PathBuf> {
    Some(gssh::vault::app_data_dir()?.join("agent-chats"))
}

fn chat_path(host_id: &str) -> Option<PathBuf> {
    let safe: String = host_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe.is_empty() {
        return None;
    }
    Some(
        gssh::vault::app_data_dir()?
            .join("agent-chats")
            .join(format!("{safe}.json")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chat_key() -> AgentChatKey {
        let dir = tempfile::tempdir().unwrap();
        let manager = gssh::vault::VaultManager::create_with_params(
            &dir.path().join("vault.json"),
            &secrecy::SecretString::from("test-password".to_string()),
            gssh::vault::model::KdfParams {
                m_cost: 256,
                t_cost: 1,
                p_cost: 1,
            },
        )
        .unwrap()
        .0;
        manager.agent_chat_key()
    }

    fn titled(title: &str) -> SavedChat {
        let mut chat = SavedChat::fresh();
        chat.title = title.to_string();
        chat.bubbles.push(SavedBubble::User {
            text: title.to_string(),
            cite: None,
            images: Vec::new(),
        });
        chat
    }

    #[test]
    fn a_new_chat_keeps_the_one_already_open() {
        let mut book = ChatBook::fresh();
        book.open[0] = titled("disk");
        assert!(book.start_new());
        assert_eq!(book.open.len(), 2);
        assert_eq!(book.active, 1);
        assert_eq!(book.open[0].title, "disk");
        assert!(book.open[1].is_blank());
        assert!(!book.start_new());
    }

    #[test]
    fn closing_a_chat_keeps_it_to_restore() {
        let mut book = ChatBook::fresh();
        book.open[0] = titled("disk");
        assert!(book.start_new());
        book.open[1] = titled("ports");
        book.close(0);
        assert_eq!(book.open.len(), 1);
        assert_eq!(book.open[0].title, "ports");
        assert_eq!(book.closed[0].title, "disk");
        let id = book.closed[0].id.clone();
        assert!(book.restore(&id));
        assert_eq!(book.active_chat().title, "disk");
        assert!(book.closed.is_empty());
    }

    #[test]
    fn closing_the_last_chat_leaves_a_new_one() {
        let mut book = ChatBook::fresh();
        book.open[0] = titled("disk");
        book.close(0);
        assert_eq!(book.open.len(), 1);
        assert!(book.open[0].is_blank());
        assert_eq!(book.closed[0].title, "disk");
    }

    #[test]
    fn saved_chats_load_back_for_that_host_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.json");
        let key = chat_key();
        let mut book = ChatBook::fresh();
        book.open[0] = titled("secret-disk-usage");
        book.closed.push(titled("older"));
        book.save_to(&path, &key).unwrap();
        let stored = std::fs::read(&path).unwrap();
        assert!(AgentChatKey::is_sealed(&stored));
        assert!(!stored
            .windows(b"secret-disk-usage".len())
            .any(|w| w == b"secret-disk-usage"));
        let loaded = ChatBook::load_from(&path, &key);
        assert_eq!(loaded.open[0].title, "secret-disk-usage");
        assert_eq!(loaded.closed[0].title, "older");
        assert_eq!(loaded, book);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_queued_message_is_saved_with_the_chat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.json");
        let key = chat_key();
        let mut book = ChatBook::fresh();
        book.open[0].queue.push(SavedQueued {
            text: "check the disk next".into(),
            cite: None,
            images: Vec::new(),
        });
        book.save_to(&path, &key).unwrap();
        let loaded = ChatBook::load_from(&path, &key);
        assert_eq!(loaded.open[0].queue[0].text, "check the disk next");
        assert!(!loaded.open[0].is_blank());
    }

    #[test]
    fn an_older_plaintext_file_is_sealed_when_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.json");
        let key = chat_key();
        let mut book = ChatBook::fresh();
        book.open[0] = titled("legacy-chat");
        let file = ChatFile {
            version: FILE_VERSION,
            open: book.open.clone(),
            active: 0,
            closed: Vec::new(),
        };
        let mut value = serde_json::to_value(&file).unwrap();
        value["open"][0].as_object_mut().unwrap().remove("queue");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let loaded = ChatBook::load_from(&path, &key);
        assert_eq!(loaded.open[0].title, "legacy-chat");
        assert!(loaded.open[0].queue.is_empty());
        let stored = std::fs::read(&path).unwrap();
        assert!(AgentChatKey::is_sealed(&stored));
        assert!(!stored
            .windows(b"legacy-chat".len())
            .any(|w| w == b"legacy-chat"));
    }

    #[test]
    fn a_file_sealed_for_another_vault_is_kept_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.json");
        let ours = chat_key();
        let theirs = chat_key();
        let mut book = ChatBook::fresh();
        book.open[0] = titled("kept-for-the-first-vault");
        book.save_to(&path, &ours).unwrap();

        let loaded = ChatBook::load_from(&path, &theirs);
        assert!(loaded.open[0].is_blank());
        assert!(loaded.can_save());
        assert!(!path.exists());
        let parked = dir.path().join("local.json.sealed");
        assert!(parked.exists());
        assert!(ours
            .open_file("local", &std::fs::read(&parked).unwrap())
            .is_some());

        let mut theirs_book = ChatBook::fresh();
        theirs_book.open[0] = titled("second-vault-chat");
        theirs_book.save_to(&path, &theirs).unwrap();

        let restored = ChatBook::load_from(&path, &ours);
        assert_eq!(restored.open[0].title, "kept-for-the-first-vault");
        let kept_for_theirs = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .any(|entry| {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    return false;
                };
                name.ends_with(".sealed")
                    && theirs
                        .open_file("local", &std::fs::read(entry.path()).unwrap())
                        .is_some()
            });
        assert!(kept_for_theirs);
    }

    #[test]
    fn a_missing_or_broken_file_opens_a_new_chat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.json");
        let key = chat_key();
        let loaded = ChatBook::load_from(&path, &key);
        assert_eq!(loaded.open.len(), 1);
        assert!(loaded.open[0].is_blank());
        std::fs::write(&path, "{not json").unwrap();
        assert!(ChatBook::load_from(&path, &key).open[0].is_blank());
    }

    #[test]
    fn forgetting_a_chat_does_not_keep_it() {
        let mut book = ChatBook::fresh();
        book.open[0] = titled("disk");
        book.start_new();
        book.open[1] = titled("ports");
        let id = book.open[0].id.clone();
        assert!(book.forget(&id));
        assert!(book.open.iter().all(|chat| chat.title != "disk"));
        assert!(book.closed.is_empty());
        let closed = titled("old");
        let closed_id = closed.id.clone();
        book.closed.push(closed);
        assert!(book.forget(&closed_id));
        assert!(book.closed.is_empty());
    }

    #[test]
    fn the_title_is_the_first_line_of_the_question() {
        assert_eq!(
            chat_title("  how full is the disk?\nmore", ""),
            "how full is the disk?"
        );
        assert_eq!(chat_title("   ", "Terminal (4-9)"), "Terminal (4-9)");
        assert_eq!(chat_title("", ""), NEW_CHAT);
        let long = "a".repeat(50);
        assert!(chat_title(&long, "").ends_with('…'));
        assert_eq!(chat_title(&long, "").chars().count(), 43);
    }
}
