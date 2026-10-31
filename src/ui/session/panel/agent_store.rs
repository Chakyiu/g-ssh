//! Agent chats for one host. The file sits beside preferences.json: it
//! belongs to this computer and is never synced. A missing or broken file
//! opens one empty chat.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
}

impl ChatBook {
    pub(super) fn fresh() -> Self {
        Self {
            open: vec![SavedChat::fresh()],
            active: 0,
            closed: Vec::new(),
        }
    }

    pub(super) fn load(host_id: &str) -> Self {
        match chat_path(host_id) {
            Some(path) => Self::load_from(&path),
            None => Self::fresh(),
        }
    }

    pub(super) fn save(&self, host_id: &str) {
        let Some(path) = chat_path(host_id) else {
            return;
        };
        if let Err(error) = self.save_to(&path) {
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

    fn load_from(path: &Path) -> Self {
        let data = match std::fs::read(path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Self::fresh(),
            Err(error) => {
                tracing::warn!(?error, path = %path.display(), "failed to read agent chats");
                return Self::fresh();
            }
        };
        let file: ChatFile = match serde_json::from_slice(&data) {
            Ok(file) => file,
            Err(error) => {
                tracing::warn!(?error, "invalid agent chats, opening a new chat");
                return Self::fresh();
            }
        };
        if file.version != FILE_VERSION || file.open.is_empty() {
            return Self::fresh();
        }
        let active = file.active.min(file.open.len() - 1);
        Self {
            open: file.open,
            active,
            closed: file.closed,
        }
    }

    fn save_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = ChatFile {
            version: FILE_VERSION,
            open: self.open.clone(),
            active: self.active,
            closed: self.closed.clone(),
        };
        let json = serde_json::to_vec_pretty(&file).map_err(std::io::Error::other)?;
        let unfinished = path.with_extension("json.new");
        std::fs::write(&unfinished, json)?;
        std::fs::rename(&unfinished, path)
    }
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

pub fn list_session_records() -> Vec<SessionRecord> {
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
        let book = ChatBook::load_from(&path);
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

pub fn remove_session(host_id: &str, chat_id: &str) {
    let Some(path) = chat_path(host_id) else {
        return;
    };
    let mut book = ChatBook::load_from(&path);
    if !book.forget(chat_id) {
        return;
    }
    if book
        .open
        .iter()
        .chain(&book.closed)
        .all(|chat| chat.is_blank())
    {
        let _ = std::fs::remove_file(&path);
    } else if book.save_to(&path).is_err() {
        return;
    }
    bump_chat_records();
}

pub fn clear_host_sessions(host_id: &str) {
    let Some(path) = chat_path(host_id) else {
        return;
    };
    if std::fs::remove_file(&path).is_ok() {
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
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
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
        let mut book = ChatBook::fresh();
        book.open[0] = titled("disk");
        book.closed.push(titled("older"));
        book.save_to(&path).unwrap();
        let loaded = ChatBook::load_from(&path);
        assert_eq!(loaded.open[0].title, "disk");
        assert_eq!(loaded.closed[0].title, "older");
        assert_eq!(loaded, book);
    }

    #[test]
    fn a_queued_message_is_saved_with_the_chat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.json");
        let mut book = ChatBook::fresh();
        book.open[0].queue.push(SavedQueued {
            text: "check the disk next".into(),
            cite: None,
            images: Vec::new(),
        });
        book.save_to(&path).unwrap();
        let loaded = ChatBook::load_from(&path);
        assert_eq!(loaded.open[0].queue[0].text, "check the disk next");
        assert!(!loaded.open[0].is_blank());

        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["open"][0].as_object_mut().unwrap().remove("queue");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = ChatBook::load_from(&path);
        assert!(loaded.open[0].queue.is_empty());
    }

    #[test]
    fn a_missing_or_broken_file_opens_a_new_chat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.json");
        let loaded = ChatBook::load_from(&path);
        assert_eq!(loaded.open.len(), 1);
        assert!(loaded.open[0].is_blank());
        std::fs::write(&path, "{not json").unwrap();
        assert!(ChatBook::load_from(&path).open[0].is_blank());
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
