//! The update check and the download of a newer build.
//!
//! Both use the GitHub release page of this repository. [`latest_release`]
//! reads the latest release, and [`download`] fetches the archive for this
//! computer from that release. [`newer_release`] and [`download_offer`] are
//! built from these two. The check sends no account, no version, and no
//! device. Blocking: call them from a worker thread.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

/// A build above this size is not what a release would ever publish.
pub const MAX_DOWNLOAD_BYTES: u64 = 300 * 1024 * 1024;
const MAX_FILE_NAME_CHARS: usize = 100;
/// Release notes are cut down to this before they are shown.
const MAX_NOTES_CHARS: usize = 2000;
const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
const PART_SUFFIX: &str = ".g-ssh-part";
/// A running download writes to its part file all the time. One that was not
/// written to for this long belongs to a download that died.
const STALE_PART_AGE: Duration = Duration::from_secs(60 * 60);
/// How many times a download may be sent on to another address.
const MAX_REDIRECTS: u8 = 5;

/// The repository whose release page publishes the builds.
const GITHUB_REPOSITORY: &str = "Chakyiu/g-ssh";

/// The latest release, as the releases API reports it. The page itself is
/// `https://github.com/Chakyiu/g-ssh/releases/latest`.
fn github_latest_url() -> String {
    format!("https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/latest")
}

/// Download links on the release page:
/// `https://github.com/Chakyiu/g-ssh/releases/download/<tag>/<file>`.
fn github_download_base() -> String {
    format!("https://github.com/{GITHUB_REPOSITORY}/releases/download")
}

/// The archive name GitHub is asked for. `None` where there are no builds to
/// offer, and then nothing is ever asked. The name is the `<os-arch>` piece
/// of `g-ssh-<version>-<os-arch>.<ext>` on the release page: `.dmg` on macOS,
/// `.zip` on Windows.
pub fn platform() -> Option<&'static str> {
    // macOS sets this variable for an app that runs in the sandbox.
    let is_sandboxed = std::env::var_os("APP_SANDBOX_CONTAINER_ID").is_some();
    platform_for(std::env::consts::OS, std::env::consts::ARCH, is_sandboxed)
}

fn platform_for(os: &str, arch: &str, is_sandboxed: bool) -> Option<&'static str> {
    // The Mac App Store build is the sandboxed one. It may not write to
    // Downloads, and the store is the only place it may update from.
    if is_sandboxed {
        return None;
    }
    // Intel Macs are not published, so there is no archive to ask for.
    match (os, arch) {
        ("macos", "aarch64") => Some("macos-aarch64"),
        ("windows", "x86_64") => Some("windows-x86_64"),
        _ => None,
    }
}

/// The build the release page offers for one platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    /// Plain text from the release notes. Never shown as markup.
    pub notes: String,
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    /// The tag on the release page, such as `v0.2.0`. The download link is
    /// built from this and [`Release::filename`].
    pub tag: String,
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("could not reach GitHub: {0}")]
    Network(String),
    #[error("GitHub answered with status {0}")]
    Status(u16),
    #[error("GitHub sent an answer g-ssh does not understand")]
    BadAnswer,
    #[error("the file is larger than g-ssh accepts")]
    TooLarge,
    #[error("the file is not the size GitHub announced, so it was not kept")]
    WrongSize,
    #[error("the file does not match the checksum GitHub announced, so it was not kept")]
    WrongChecksum,
    #[error("this build is no longer on the GitHub release")]
    Withdrawn,
    #[error("the download was sent somewhere other than GitHub, so it was not kept")]
    OffSite,
    #[error("cancelled")]
    Cancelled,
    #[error("could not save the file: {0}")]
    Io(#[from] std::io::Error),
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_send_body(Some(Duration::from_secs(30)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        // The sync client names its version here. This one must not: the
        // request is the same from every copy of the app.
        .user_agent("g-ssh")
        // Redirects are followed by hand, and only to GitHub's own hosts.
        // A 3xx is a normal response so its Location header can be read.
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into()
}

fn request_error(error: ureq::Error) -> UpdateError {
    match error {
        ureq::Error::StatusCode(status) => UpdateError::Status(status),
        other => UpdateError::Network(other.to_string()),
    }
}

fn status_code(response: &ureq::http::Response<ureq::Body>) -> u16 {
    response.status().as_u16()
}

fn header_str<'a>(response: &'a ureq::http::Response<ureq::Body>, name: &str) -> Option<&'a str> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// The current release's build for `platform`. `None` when there is no
/// release, or none for this computer.
pub fn latest_release(platform: &str) -> Result<Option<Release>, UpdateError> {
    latest_release_at(&github_latest_url(), platform)
}

fn latest_release_at(latest_url: &str, platform: &str) -> Result<Option<Release>, UpdateError> {
    let mut response = match agent()
        .get(latest_url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .config()
        .timeout_global(Some(CHECK_TIMEOUT))
        .build()
        .call()
    {
        Ok(response) => response,
        Err(error) => return Err(request_error(error)),
    };
    let status = status_code(&response);
    if status == 404 {
        return Ok(None);
    }
    if status != 200 {
        return Err(UpdateError::Status(status));
    }
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|_| UpdateError::BadAnswer)?;
    release_from_github(&text, platform)
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    size: u64,
    #[serde(default)]
    digest: Option<String>,
}

/// The release page's latest release, reduced to the one archive this
/// computer can install. The download address is not taken from the answer:
/// it is built later from the tag and the file name.
fn release_from_github(text: &str, platform: &str) -> Result<Option<Release>, UpdateError> {
    let page: GithubRelease = serde_json::from_str(text).map_err(|_| UpdateError::BadAnswer)?;
    if page.draft || page.prerelease {
        return Ok(None);
    }
    let Some(version) = version_of_tag(&page.tag_name) else {
        return Ok(None);
    };
    let Some(tag) = safe_tag(&page.tag_name) else {
        return Err(UpdateError::BadAnswer);
    };
    let Some(asset) = matching_asset(&page.assets, platform)? else {
        return Ok(None);
    };
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(sha256_of_digest)
        .ok_or(UpdateError::BadAnswer)?;
    if asset.size > MAX_DOWNLOAD_BYTES {
        return Err(UpdateError::TooLarge);
    }
    Ok(Some(Release {
        version,
        notes: plain_text(page.body.as_deref().unwrap_or("")),
        filename: asset.name.clone(),
        size_bytes: asset.size,
        sha256,
        tag: tag.to_string(),
    }))
}

/// `v0.2.0` and `0.2.0` are versions. Anything else is not a release this
/// app can compare, so it is not offered.
fn version_of_tag(tag: &str) -> Option<String> {
    let bare = tag
        .strip_prefix('v')
        .or_else(|| tag.strip_prefix('V'))
        .unwrap_or(tag);
    crate::version::Version::parse(bare)?;
    Some(bare.to_string())
}

/// One archive whose name contains `-<platform>.`. A second one, or a name
/// that is not safe to save, is a broken release.
fn matching_asset<'a>(
    assets: &'a [GithubAsset],
    platform: &str,
) -> Result<Option<&'a GithubAsset>, UpdateError> {
    let marker = format!("-{platform}.");
    let mut chosen = None;
    for asset in assets {
        if !asset.name.contains(&marker) {
            continue;
        }
        let is_archive = asset.name.ends_with(".tar.gz")
            || asset.name.ends_with(".zip")
            || asset.name.ends_with(".dmg");
        if !is_archive {
            continue;
        }
        if safe_file_name(&asset.name).as_deref() != Some(asset.name.as_str()) {
            return Err(UpdateError::BadAnswer);
        }
        if chosen.is_some() {
            return Err(UpdateError::BadAnswer);
        }
        chosen = Some(asset);
    }
    Ok(chosen)
}

/// GitHub's `sha256:<hex>` digest, as hex.
fn sha256_of_digest(digest: &str) -> Option<String> {
    let (algo, hex) = digest.split_once(':')?;
    let hex = hex.trim();
    let is_sha256 = algo.eq_ignore_ascii_case("sha256")
        && hex.len() == 64
        && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
    is_sha256.then(|| hex.to_ascii_lowercase())
}

/// A tag that can be one path segment of the download link.
fn safe_tag(tag: &str) -> Option<&str> {
    let is_safe = (1..=MAX_FILE_NAME_CHARS).contains(&tag.len())
        && !tag.contains("..")
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    is_safe.then_some(tag)
}

/// Notes of a sane length, without invisible characters.
fn plain_text(text: &str) -> String {
    text.trim()
        .chars()
        .filter(|&c| matches!(c, '\n' | '\t') || !(c.is_control() || is_invisible(c)))
        .take(MAX_NOTES_CHARS)
        .collect()
}

/// Zero-width characters and the ones that turn the direction of text.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'
    )
}

/// The current release, when it is a later version than `current`. This is
/// the build the app tells the user about.
pub fn newer_release(platform: &str, current: &str) -> Result<Option<Release>, UpdateError> {
    Ok(latest_release(platform)?
        .filter(|release| crate::version::is_newer(&release.version, current)))
}

#[cfg(test)]
fn newer_release_at(
    latest_url: &str,
    platform: &str,
    current: &str,
) -> Result<Option<Release>, UpdateError> {
    let offered = latest_release_at(latest_url, platform)?;
    Ok(offered.filter(|release| crate::version::is_newer(&release.version, current)))
}

/// [`download`] of the build the user was offered. The offer can be hours
/// old: when the release has been replaced since, the file GitHub sends does
/// not match the offer. Then the release page is read again and its current
/// build is fetched, if it is still newer than `current`.
///
/// Returns the build that was saved and where. `on_progress` gets the bytes
/// received so far and the size of the build being fetched.
pub fn download_offer(
    platform: &str,
    offered: &Release,
    current: &str,
    folder: &Path,
    is_cancelled: &AtomicBool,
    on_progress: impl FnMut(u64, u64),
) -> Result<(Release, PathBuf), UpdateError> {
    resolve_offer(
        offered,
        is_cancelled,
        on_progress,
        |release, progress| download(release, folder, is_cancelled, progress),
        || newer_release(platform, current),
    )
}

#[cfg(test)]
fn download_offer_at(
    latest_url: &str,
    download_base: &str,
    platform: &str,
    offered: &Release,
    current: &str,
    folder: &Path,
    is_cancelled: &AtomicBool,
    on_progress: impl FnMut(u64, u64),
) -> Result<(Release, PathBuf), UpdateError> {
    resolve_offer(
        offered,
        is_cancelled,
        on_progress,
        |release, progress| download_at(download_base, release, folder, is_cancelled, progress),
        || newer_release_at(latest_url, platform, current),
    )
}

/// Shared by the real download and the tests, which point the same steps at
/// a local server.
fn resolve_offer(
    offered: &Release,
    is_cancelled: &AtomicBool,
    mut on_progress: impl FnMut(u64, u64),
    mut fetch: impl FnMut(&Release, &mut dyn FnMut(u64)) -> Result<PathBuf, UpdateError>,
    mut lookup: impl FnMut() -> Result<Option<Release>, UpdateError>,
) -> Result<(Release, PathBuf), UpdateError> {
    let mut report = |received| on_progress(received, offered.size_bytes);
    let mismatch = match fetch(offered, &mut report) {
        Ok(path) => return Ok((offered.clone(), path)),
        Err(e @ (UpdateError::WrongSize | UpdateError::WrongChecksum)) => e,
        // The asset is gone from the release.
        Err(UpdateError::Status(404)) => return Err(UpdateError::Withdrawn),
        Err(e) => return Err(e),
    };
    if is_cancelled.load(Ordering::Relaxed) {
        return Err(UpdateError::Cancelled);
    }
    let Some(replacement) = lookup()? else {
        return Err(UpdateError::Withdrawn);
    };
    if replacement == *offered {
        // Not replaced: the file really is broken.
        return Err(mismatch);
    }
    tracing::info!(version = %replacement.version, "the offered build was replaced on the GitHub release");
    let mut report = |received| on_progress(received, replacement.size_bytes);
    let path = fetch(&replacement, &mut report)?;
    Ok((replacement, path))
}

/// Fetch the build into `folder` and check it against the release. Returns
/// where the file is. Nothing is opened or run.
///
/// `on_progress` gets the number of bytes received so far.
pub fn download(
    release: &Release,
    folder: &Path,
    is_cancelled: &AtomicBool,
    on_progress: impl FnMut(u64),
) -> Result<PathBuf, UpdateError> {
    download_at(
        &github_download_base(),
        release,
        folder,
        is_cancelled,
        on_progress,
    )
}

fn download_at(
    download_base: &str,
    release: &Release,
    folder: &Path,
    is_cancelled: &AtomicBool,
    on_progress: impl FnMut(u64),
) -> Result<PathBuf, UpdateError> {
    let name = safe_file_name(&release.filename).ok_or(UpdateError::BadAnswer)?;
    if name != release.filename {
        return Err(UpdateError::BadAnswer);
    }
    let url = download_url(download_base, &release.tag, &name).ok_or(UpdateError::BadAnswer)?;
    if release.size_bytes > MAX_DOWNLOAD_BYTES {
        return Err(UpdateError::TooLarge);
    }
    // Downloaded before, for example from the dialog an hour ago.
    let target = folder.join(&name);
    if is_file_as_announced(&target, release) {
        return Ok(target);
    }

    std::fs::create_dir_all(folder)?;
    remove_stale_parts(folder, STALE_PART_AGE);
    let part = part_path(folder, &name);
    let placed = fetch_to(&url, &part, release, is_cancelled, on_progress).and_then(|()| {
        let path = free_path(folder, &name);
        std::fs::rename(&part, &path)?;
        mark_as_downloaded(&path);
        Ok(path)
    });
    if placed.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    placed
}

/// Tell the OS the file came from the internet, as a browser does for its
/// downloads. Opening it then goes through Gatekeeper or SmartScreen, which
/// is the only check left if the release itself was replaced. Best effort:
/// a file system without these marks still gets the file.
#[cfg(target_os = "macos")]
fn mark_as_downloaded(path: &Path) {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    // flags; time of download in hex; the app that fetched it; an id.
    let mark = format!("0081;{seconds:x};g-ssh;{}", uuid::Uuid::new_v4());
    let marked = std::process::Command::new("/usr/bin/xattr")
        .args(["-w", "com.apple.quarantine", &mark])
        .arg(path)
        .status();
    if !marked.is_ok_and(|status| status.success()) {
        tracing::warn!(path = %path.display(), "could not mark the download as quarantined");
    }
}

#[cfg(windows)]
fn mark_as_downloaded(path: &Path) {
    // The "mark of the web": a second stream of the file, zone 3 = internet.
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    if let Err(e) = std::fs::write(&stream, "[ZoneTransfer]\r\nZoneId=3\r\n") {
        tracing::warn!(?e, path = %path.display(), "could not mark the download as from the internet");
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn mark_as_downloaded(_path: &Path) {}

/// A name of its own for every attempt. A cancelled download can still be
/// running when the next one starts, and must not share its file.
fn part_path(folder: &Path, name: &str) -> PathBuf {
    folder.join(format!(
        "{name}.{}{PART_SUFFIX}",
        uuid::Uuid::new_v4().simple()
    ))
}

/// g-ssh was quit or killed in the middle of a download: its part file is
/// still there and nothing else would ever remove it.
fn remove_stale_parts(folder: &Path, stale_age: Duration) {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        let is_part = entry.file_name().to_string_lossy().ends_with(PART_SUFFIX);
        if !is_part || !is_older_than(&entry, stale_age) {
            continue;
        }
        if let Err(e) = std::fs::remove_file(entry.path()) {
            tracing::debug!(?e, path = %entry.path().display(), "could not remove an old part file");
        }
    }
}

fn is_older_than(entry: &std::fs::DirEntry, age: Duration) -> bool {
    let Ok(modified) = entry.metadata().and_then(|file| file.modified()) else {
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|since| since > age)
}

fn fetch_to(
    url: &str,
    part: &Path,
    release: &Release,
    is_cancelled: &AtomicBool,
    on_progress: impl FnMut(u64),
) -> Result<(), UpdateError> {
    if is_cancelled.load(Ordering::Relaxed) {
        return Err(UpdateError::Cancelled);
    }
    let response = open_download(url)?;
    let announced = header_str(&response, "content-length").and_then(|length| length.parse::<u64>().ok());
    if announced.is_some_and(|length| length != release.size_bytes) {
        return Err(UpdateError::WrongSize);
    }
    // One byte more than expected is enough to see that the file is too long.
    let body = response.into_body().into_reader().take(release.size_bytes + 1);
    let mut file = File::create_new(part)?;
    let (size, checksum) = copy_and_hash(body, &mut file, is_cancelled, on_progress)?;
    file.sync_all()?;
    check_file(size, &checksum, release)
}

/// GET `url`, following redirects that stay on the host the download started
/// on. A download that started on github.com may also move to GitHub's asset
/// hosts, which is where the release page sends a browser.
fn open_download(start: &str) -> Result<ureq::http::Response<ureq::Body>, UpdateError> {
    let origin_host = parse_http_url(start).ok_or(UpdateError::BadAnswer)?.host;
    if !is_allowed_download_url(&origin_host, start) {
        return Err(UpdateError::OffSite);
    }
    let mut url = start.to_string();
    let mut redirects = 0u8;
    loop {
        // With no automatic redirects, ureq returns the 3xx as a normal
        // response. Some versions report it as a status error instead.
        let response = agent()
            .get(&url)
            .header("Accept", "application/octet-stream")
            .call()
            .map_err(request_error)?;
        if is_redirect(status_code(&response)) {
            if redirects == MAX_REDIRECTS {
                return Err(UpdateError::BadAnswer);
            }
            let next = header_str(&response, "location")
                .and_then(|location| redirect_target(&url, location))
                .ok_or(UpdateError::BadAnswer)?;
            if !is_allowed_download_url(&origin_host, &next) {
                tracing::warn!(url = %next, "update download redirect was refused");
                return Err(UpdateError::OffSite);
            }
            redirects += 1;
            url = next;
            continue;
        }
        let status = status_code(&response);
        if status != 200 {
            return Err(UpdateError::Status(status));
        }
        return Ok(response);
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn check_file(size: u64, checksum: &str, release: &Release) -> Result<(), UpdateError> {
    if size != release.size_bytes {
        return Err(UpdateError::WrongSize);
    }
    if !checksum.eq_ignore_ascii_case(&release.sha256) {
        return Err(UpdateError::WrongChecksum);
    }
    Ok(())
}

/// Copy everything, and return how many bytes there were and their SHA-256
/// as hex.
fn copy_and_hash(
    mut from: impl Read,
    mut to: impl Write,
    is_cancelled: &AtomicBool,
    mut on_progress: impl FnMut(u64),
) -> Result<(u64, String), UpdateError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        if is_cancelled.load(Ordering::Relaxed) {
            return Err(UpdateError::Cancelled);
        }
        let count = from
            .read(&mut buffer)
            .map_err(|e| UpdateError::Network(e.to_string()))?;
        if count == 0 {
            break;
        }
        to.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
        size += count as u64;
        on_progress(size);
    }
    let checksum = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((size, checksum))
}

/// Whether the file at `path` is exactly the build the release announced.
fn is_file_as_announced(path: &Path, release: &Release) -> bool {
    let has_the_size = path
        .metadata()
        .is_ok_and(|file| file.is_file() && file.len() == release.size_bytes);
    if !has_the_size {
        return false;
    }
    let Ok(file) = File::open(path) else {
        return false;
    };
    copy_and_hash(file, std::io::sink(), &AtomicBool::new(false), |_| {})
        .is_ok_and(|(size, checksum)| check_file(size, &checksum, release).is_ok())
}

/// The file name, made safe to create in a folder: the last path component
/// only, in letters, digits, `.`, `_` and `-`. `None` when nothing usable is
/// left.
fn safe_file_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    // No hidden file, no "..", and no trailing dot, which Windows drops.
    let cleaned = cleaned.trim_matches('.');
    let is_usable = !cleaned.is_empty()
        && cleaned.len() <= MAX_FILE_NAME_CHARS
        && !is_windows_device_name(cleaned);
    is_usable.then(|| cleaned.to_string())
}

/// "NUL", "con.dmg", "COM1.exe": Windows opens a device for these names, with
/// any extension, and not a file.
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    let is_numbered_port = stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.ends_with(|c: char| c.is_ascii_digit());
    is_numbered_port || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
}

/// `name` in `folder`, or "name (1).ext", "name (2).ext" and so on when the
/// names before it are taken.
fn free_path(folder: &Path, name: &str) -> PathBuf {
    let plain = folder.join(name);
    if !plain.exists() {
        return plain;
    }
    let (stem, extension) = match name.rfind('.') {
        Some(dot) if dot > 0 => name.split_at(dot),
        _ => (name, ""),
    };
    let mut number = 1;
    loop {
        let path = folder.join(format!("{stem} ({number}){extension}"));
        if !path.exists() {
            return path;
        }
        number += 1;
    }
}

/// The address of the build on the release page. The host comes from
/// `download_base`, which the app chooses, so the release cannot point the
/// download somewhere else.
fn download_url(download_base: &str, tag: &str, filename: &str) -> Option<String> {
    let tag = safe_tag(tag)?;
    if safe_file_name(filename).as_deref() != Some(filename) {
        return None;
    }
    let base = download_base.trim_end_matches('/');
    if base.contains('?') || base.contains('#') {
        return None;
    }
    let parsed = parse_http_url(base)?;
    if !is_allowed_download_url(&parsed.host, base) {
        return None;
    }
    let url = format!("{base}/{tag}/{filename}");
    is_allowed_download_url(&parsed.host, &url).then_some(url)
}

struct HttpUrl {
    /// `scheme://host` or `scheme://host:port`, with no path.
    origin: String,
    host: String,
    scheme: String,
}

fn parse_http_url(url: &str) -> Option<HttpUrl> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    if rest.is_empty() || rest.contains('@') || rest.contains('\\') || rest.contains('#') {
        return None;
    }
    let authority = rest
        .split_once('/')
        .map(|(authority, _)| authority)
        .unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let host = match authority.split_once(':') {
        Some((host, port)) => {
            if host.is_empty() || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            host
        }
        None => authority,
    };
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(HttpUrl {
        origin: format!("{scheme}://{authority}"),
        host,
        scheme: scheme.to_string(),
    })
}

/// `next` may be requested while a download that started on `origin_host` is
/// in progress. Loopback is allowed so tests can serve the file. github.com
/// may move to the hosts the release page uses for the file itself.
fn is_allowed_download_url(origin_host: &str, next: &str) -> bool {
    let Some(parsed) = parse_http_url(next) else {
        return false;
    };
    let same_host = parsed.host.eq_ignore_ascii_case(origin_host);
    if origin_host.eq_ignore_ascii_case("github.com") {
        return parsed.scheme == "https" && (same_host || is_github_asset_host(&parsed.host));
    }
    same_host && is_loopback(&parsed.host)
}

fn is_github_asset_host(host: &str) -> bool {
    matches!(
        host,
        "release-assets.github.com"
            | "objects.githubusercontent.com"
            | "github-releases.githubusercontent.com"
    )
}

fn is_loopback(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn redirect_target(current: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if location.is_empty()
        || location
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return None;
    }
    if location.starts_with("https://") || location.starts_with("http://") {
        return Some(location.to_string());
    }
    // Another scheme, or a protocol-relative URL (`//host/path`).
    if location.contains(':') || location.starts_with("//") {
        return None;
    }
    let current_url = parse_http_url(current)?;
    if let Some(path) = location.strip_prefix('/') {
        return Some(format!("{}/{path}", current_url.origin));
    }
    let without_query = current.split('?').next().unwrap_or(current);
    let slash = without_query.rfind('/')?;
    let scheme_sep = without_query.find("://")? + 3;
    if slash < scheme_sep {
        return Some(format!("{}/{location}", current_url.origin));
    }
    Some(format!("{}/{location}", &without_query[..slash]))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader};
    use std::net::TcpListener;

    use super::*;

    const PLATFORM: &str = "macos-aarch64";
    const HELLO_FILE: &str = "g-ssh-0.2.0-macos-aarch64.tar.gz";
    const WORLD_FILE: &str = "g-ssh-0.3.0-macos-aarch64.tar.gz";
    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn hello_release() -> Release {
        Release {
            version: "0.2.0".into(),
            notes: String::new(),
            filename: HELLO_FILE.into(),
            size_bytes: 5,
            sha256: HELLO_SHA256.into(),
            tag: "v0.2.0".into(),
        }
    }

    fn not_cancelled() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn latest_url(origin: &str) -> String {
        format!("{origin}/repos/{GITHUB_REPOSITORY}/releases/latest")
    }

    fn download_base(origin: &str) -> String {
        format!("{origin}/{GITHUB_REPOSITORY}/releases/download")
    }

    fn latest_line() -> String {
        format!("GET /repos/{GITHUB_REPOSITORY}/releases/latest HTTP/1.1")
    }

    fn download_line(tag: &str, file: &str) -> String {
        format!("GET /{GITHUB_REPOSITORY}/releases/download/{tag}/{file} HTTP/1.1")
    }

    /// A server that answers one request with `answer` and hands back the
    /// request it got. Returns the origin to build the release URLs from.
    fn serve_once(answer: Vec<u8>) -> (String, std::thread::JoinHandle<String>) {
        serve_once_after(answer, || {})
    }

    /// The same, and `before_answer` runs when the request has arrived.
    fn serve_once_after(
        answer: Vec<u8>,
        before_answer: impl FnOnce() + Send + 'static,
    ) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let served = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line.trim().is_empty() {
                    break;
                }
                request.push_str(&line);
            }
            before_answer();
            stream.write_all(&answer).unwrap();
            request
        });
        (origin, served)
    }

    /// The same, for several requests in a row: one answer for each.
    fn serve_each(answers: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let served = std::thread::spawn(move || {
            let mut request_lines = Vec::new();
            for answer in answers {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first_line = String::new();
                reader.read_line(&mut first_line).unwrap();
                let mut line = first_line.clone();
                while !line.trim().is_empty() {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                }
                stream.write_all(&answer).unwrap();
                request_lines.push(first_line.trim().to_string());
            }
            request_lines
        });
        (origin, served)
    }

    fn release_answer(release: &Release) -> Vec<u8> {
        let body = serde_json::json!({
            "tag_name": release.tag,
            "body": release.notes,
            "assets": [{
                "name": release.filename,
                "size": release.size_bytes,
                "digest": format!("sha256:{}", release.sha256),
                "browser_download_url": "https://evil.example/do-not-fetch",
            }],
        });
        file_answer(body.to_string().as_bytes())
    }

    fn http(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut answer =
            format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n").into_bytes();
        answer.extend_from_slice(body);
        answer
    }

    fn file_answer(body: &[u8]) -> Vec<u8> {
        http(
            "200 OK",
            &format!("Content-Length: {}\r\n", body.len()),
            body,
        )
    }

    #[test]
    fn the_sandboxed_store_build_has_no_platform_to_ask_for() {
        assert_eq!(
            platform_for("macos", "aarch64", false),
            Some("macos-aarch64")
        );
        assert_eq!(platform_for("macos", "x86_64", false), None);
        assert_eq!(
            platform_for("windows", "x86_64", false),
            Some("windows-x86_64")
        );
        assert_eq!(platform_for("windows", "aarch64", false), None);
        assert_eq!(platform_for("linux", "x86_64", false), None);
        assert_eq!(platform_for("linux", "aarch64", false), None);
        assert_eq!(platform_for("macos", "aarch64", true), None);
    }

    #[test]
    fn updates_come_from_the_github_release_page() {
        assert_eq!(
            github_latest_url(),
            "https://api.github.com/repos/Chakyiu/g-ssh/releases/latest"
        );
        assert_eq!(
            github_download_base(),
            "https://github.com/Chakyiu/g-ssh/releases/download"
        );
        assert_eq!(
            download_url(&github_download_base(), "v0.2.0", HELLO_FILE).as_deref(),
            Some(
                "https://github.com/Chakyiu/g-ssh/releases/download/v0.2.0/g-ssh-0.2.0-macos-aarch64.tar.gz"
            )
        );
    }

    #[test]
    fn a_windows_device_name_is_refused() {
        for name in [
            "NUL",
            "nul",
            "CON.dmg",
            "aux.tar.gz",
            "PRN.exe",
            "COM1",
            "com9.dmg",
            "LPT1.exe",
        ] {
            assert_eq!(safe_file_name(name), None, "{name:?}");
        }
        for name in [
            "CONSOLE.dmg",
            "nullable.exe",
            "COM.exe",
            "COM10.exe",
            "g-ssh-CON.dmg",
        ] {
            assert!(safe_file_name(name).is_some(), "{name:?}");
        }
    }

    #[test]
    fn a_file_name_keeps_its_base_name_only() {
        assert_eq!(
            safe_file_name("g-ssh-0.2.0.dmg").as_deref(),
            Some("g-ssh-0.2.0.dmg")
        );
        assert_eq!(
            safe_file_name("../../etc/passwd").as_deref(),
            Some("passwd")
        );
        assert_eq!(
            safe_file_name("/Applications/g-ssh.app").as_deref(),
            Some("g-ssh.app")
        );
        assert_eq!(
            safe_file_name(r"C:\Windows\g-ssh_setup.exe").as_deref(),
            Some("g-ssh_setup.exe")
        );
        assert_eq!(
            safe_file_name(r"..\..\evil.exe").as_deref(),
            Some("evil.exe")
        );
    }

    #[test]
    fn a_file_name_is_cleaned_to_a_small_set_of_characters() {
        assert_eq!(
            safe_file_name("g-ssh 0.2.0 (arm).dmg").as_deref(),
            Some("g-ssh-0.2.0--arm-.dmg")
        );
        assert_eq!(
            safe_file_name("ab\u{202e}cd.exe").as_deref(),
            Some("ab-cd.exe")
        );
        assert_eq!(safe_file_name("a:b|c?.zip").as_deref(), Some("a-b-c-.zip"));
        assert_eq!(safe_file_name("日本語.dmg").as_deref(), Some("---.dmg"));
        assert_eq!(safe_file_name(".hidden").as_deref(), Some("hidden"));
        assert_eq!(safe_file_name("setup.exe.").as_deref(), Some("setup.exe"));
    }

    #[test]
    fn a_file_name_with_nothing_usable_is_refused() {
        for name in ["", ".", "..", "/", "dir/", "...", r"a\.."] {
            assert_eq!(safe_file_name(name), None, "{name:?}");
        }
        assert_eq!(safe_file_name(&"a".repeat(101)), None);
        assert!(safe_file_name(&"a".repeat(100)).is_some());
    }

    #[test]
    fn a_safe_file_name_stays_inside_the_folder() {
        let folder = Path::new("/home/me/Downloads");
        for name in [
            "../../x",
            "/etc/passwd",
            r"..\..\x",
            "a/../../b",
            "..",
            "~/x",
        ] {
            let Some(safe) = safe_file_name(name) else {
                continue;
            };
            assert_eq!(folder.join(&safe).parent(), Some(folder), "{name:?}");
        }
    }

    #[test]
    fn a_free_name_is_the_plain_one_or_the_next_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);

        assert_eq!(
            free_path(dir.path(), "g-ssh-0.2.0.dmg"),
            path("g-ssh-0.2.0.dmg")
        );
        std::fs::write(path("g-ssh-0.2.0.dmg"), "old").unwrap();
        assert_eq!(
            free_path(dir.path(), "g-ssh-0.2.0.dmg"),
            path("g-ssh-0.2.0 (1).dmg")
        );
        std::fs::write(path("g-ssh-0.2.0 (1).dmg"), "old").unwrap();
        assert_eq!(
            free_path(dir.path(), "g-ssh-0.2.0.dmg"),
            path("g-ssh-0.2.0 (2).dmg")
        );

        std::fs::write(path("setup"), "old").unwrap();
        assert_eq!(free_path(dir.path(), "setup"), path("setup (1)"));
    }

    #[test]
    fn a_download_address_that_could_leave_github_is_refused() {
        let bad_tags = [
            "",
            "..",
            "v0.2.0/../x",
            "v0.2.0?x=1",
            "https://evil.example",
            "v0.2.0 ",
            "../v0.2.0",
        ];
        for tag in bad_tags {
            assert_eq!(
                download_url(&github_download_base(), tag, HELLO_FILE),
                None,
                "{tag:?}"
            );
        }
        for name in [
            "",
            "../x.tar.gz",
            "g-ssh 0.2.0.tar.gz",
            &format!("../{HELLO_FILE}"),
        ] {
            assert_eq!(
                download_url(&github_download_base(), "v0.2.0", name),
                None,
                "{name:?}"
            );
        }
        assert_eq!(
            download_url(
                "https://evil.example/releases/download",
                "v0.2.0",
                HELLO_FILE
            ),
            None
        );
        assert_eq!(
            download_url(
                "http://github.com/Chakyiu/g-ssh/releases/download",
                "v0.2.0",
                HELLO_FILE
            ),
            None
        );
        assert_eq!(
            download_url(
                "github.com/Chakyiu/g-ssh/releases/download",
                "v0.2.0",
                HELLO_FILE
            ),
            None
        );
    }

    #[test]
    fn a_github_download_may_only_move_to_githubs_asset_hosts() {
        let start = "https://github.com/Chakyiu/g-ssh/releases/download/v0.2.0/g-ssh.tar.gz";
        let origin = parse_http_url(start).unwrap().host;
        assert_eq!(origin, "github.com");
        assert!(is_allowed_download_url(&origin, start));
        assert!(is_allowed_download_url(
            &origin,
            "https://release-assets.github.com/github-production-release-asset/1?token=abc"
        ));
        assert!(is_allowed_download_url(
            &origin,
            "https://objects.githubusercontent.com/github-production-release-asset-2e65be/1"
        ));
        assert!(is_allowed_download_url(
            &origin,
            "https://github-releases.githubusercontent.com/1"
        ));
        assert!(!is_allowed_download_url(
            &origin,
            "https://evil.example/g-ssh.tar.gz"
        ));
        assert!(!is_allowed_download_url(
            &origin,
            "http://release-assets.github.com/a"
        ));
        assert!(!is_allowed_download_url(
            &origin,
            "https://user.github.com/a"
        ));
        assert!(!is_allowed_download_url(
            "127.0.0.1",
            "http://localhost:1/a"
        ));
        assert!(is_allowed_download_url(
            "127.0.0.1",
            "http://127.0.0.1:9/the-file"
        ));
    }

    #[test]
    fn a_relative_redirect_stays_on_the_same_origin() {
        let current = "http://127.0.0.1:9/Chakyiu/g-ssh/releases/download/v0.2.0/a.tar.gz";
        assert_eq!(
            redirect_target(current, "/the-file").as_deref(),
            Some("http://127.0.0.1:9/the-file")
        );
        assert_eq!(
            redirect_target(current, "https://release-assets.github.com/a?x=1").as_deref(),
            Some("https://release-assets.github.com/a?x=1")
        );
        assert_eq!(redirect_target(current, "//evil.example/a"), None);
        assert_eq!(
            redirect_target(current, "http://evil.example/a\r\nX: y"),
            None
        );
    }

    #[test]
    fn copying_counts_the_bytes_and_hashes_them() {
        let mut copy = Vec::new();
        let mut seen = Vec::new();

        let (size, checksum) =
            copy_and_hash(&b"hello"[..], &mut copy, &not_cancelled(), |so_far| {
                seen.push(so_far)
            })
            .unwrap();

        assert_eq!((size, checksum.as_str()), (5, HELLO_SHA256));
        assert_eq!(copy, b"hello");
        assert_eq!(seen.last(), Some(&5));
    }

    #[test]
    fn a_cancelled_copy_stops() {
        let stopped = copy_and_hash(
            &b"hello"[..],
            std::io::sink(),
            &AtomicBool::new(true),
            |_| {},
        );
        assert!(matches!(stopped, Err(UpdateError::Cancelled)));
    }

    #[test]
    fn a_file_is_checked_by_size_and_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("build.dmg");
        let release = hello_release();

        assert!(!is_file_as_announced(&path, &release));
        std::fs::write(&path, "hello").unwrap();
        assert!(is_file_as_announced(&path, &release));
        // The checksum is compared without regard to case.
        let upper = Release {
            sha256: HELLO_SHA256.to_uppercase(),
            ..release.clone()
        };
        assert!(is_file_as_announced(&path, &upper));

        std::fs::write(&path, "hellp").unwrap();
        assert!(!is_file_as_announced(&path, &release));
        std::fs::write(&path, "hello!").unwrap();
        assert!(!is_file_as_announced(&path, &release));
        assert!(!is_file_as_announced(dir.path(), &release));
    }

    #[test]
    fn the_check_asks_github_for_the_latest_release_and_nothing_about_the_user() {
        let (origin, served) = serve_once(release_answer(&hello_release()));

        let release = latest_release_at(&latest_url(&origin), PLATFORM)
            .unwrap()
            .unwrap();
        let request = served.join().unwrap();

        assert_eq!(release.version, "0.2.0");
        assert_eq!(release.tag, "v0.2.0");
        assert_eq!(release.filename, HELLO_FILE);
        assert_eq!(release.sha256, HELLO_SHA256);
        assert_eq!(release.size_bytes, 5);
        let mut lines = request.lines();
        assert_eq!(lines.next(), Some(latest_line().as_str()));
        let mut headers: Vec<String> = lines
            .map(|line| line.split(':').next().unwrap().to_ascii_lowercase())
            .collect();
        headers.sort();
        assert_eq!(
            headers,
            [
                "accept",
                "accept-encoding",
                "host",
                "user-agent",
                "x-github-api-version",
            ],
            "{request}"
        );
        assert!(request.contains("User-Agent: g-ssh\r\n"), "{request}");
        assert!(
            request.contains("Accept: application/vnd.github+json\r\n"),
            "{request}"
        );
        assert!(!request.contains(crate::version::CURRENT), "{request}");
        assert!(
            !request.to_ascii_lowercase().contains("authorization"),
            "{request}"
        );
        assert!(!request.contains("evil.example"), "{request}");
    }

    #[test]
    fn notes_from_the_release_are_cut_down_to_what_can_be_shown() {
        let sent = Release {
            notes: format!(
                "  Fast\u{202e}er.\r\n\u{200b}Small\u{7}er.\n{}",
                "x".repeat(5000)
            ),
            ..hello_release()
        };
        let (origin, served) = serve_once(release_answer(&sent));

        let release = latest_release_at(&latest_url(&origin), PLATFORM)
            .unwrap()
            .unwrap();
        served.join().unwrap();

        assert!(
            release.notes.starts_with("Faster.\nSmaller.\nxxx"),
            "{:?}",
            &release.notes[..40]
        );
        assert_eq!(release.notes.chars().count(), MAX_NOTES_CHARS);
        assert_eq!(release.filename, HELLO_FILE);
    }

    #[test]
    fn a_build_with_no_usable_file_name_is_a_broken_answer() {
        let sent = Release {
            filename: format!("dir/{HELLO_FILE}"),
            ..hello_release()
        };
        let (origin, served) = serve_once(release_answer(&sent));

        assert!(matches!(
            latest_release_at(&latest_url(&origin), PLATFORM),
            Err(UpdateError::BadAnswer)
        ));
        served.join().unwrap();
    }

    #[test]
    fn an_asset_for_another_platform_is_not_an_offer() {
        let release = Release {
            filename: "g-ssh-0.2.0-windows-x86_64.zip".into(),
            ..hello_release()
        };
        let (origin, served) = serve_once(release_answer(&release));

        assert_eq!(
            latest_release_at(&latest_url(&origin), PLATFORM).unwrap(),
            None
        );
        served.join().unwrap();
    }

    #[test]
    fn an_asset_without_a_checksum_is_a_broken_answer() {
        let body = serde_json::json!({
            "tag_name": "v0.2.0",
            "assets": [{ "name": HELLO_FILE, "size": 5 }],
        });
        let (origin, served) = serve_once(file_answer(body.to_string().as_bytes()));

        assert!(matches!(
            latest_release_at(&latest_url(&origin), PLATFORM),
            Err(UpdateError::BadAnswer)
        ));
        served.join().unwrap();
    }

    #[test]
    fn two_archives_for_one_platform_are_a_broken_answer() {
        let body = serde_json::json!({
            "tag_name": "v0.2.0",
            "assets": [
                {
                    "name": HELLO_FILE,
                    "size": 5,
                    "digest": format!("sha256:{HELLO_SHA256}"),
                },
                {
                    "name": "g-ssh-0.2.0-macos-aarch64.zip",
                    "size": 5,
                    "digest": format!("sha256:{HELLO_SHA256}"),
                },
            ],
        });
        let (origin, served) = serve_once(file_answer(body.to_string().as_bytes()));

        assert!(matches!(
            latest_release_at(&latest_url(&origin), PLATFORM),
            Err(UpdateError::BadAnswer)
        ));
        served.join().unwrap();
    }

    #[test]
    fn a_checksum_file_beside_the_archive_is_not_the_build() {
        let body = serde_json::json!({
            "tag_name": "v0.2.0",
            "assets": [
                {
                    "name": format!("{HELLO_FILE}.sha256"),
                    "size": 64,
                    "digest": format!("sha256:{HELLO_SHA256}"),
                },
                {
                    "name": HELLO_FILE,
                    "size": 5,
                    "digest": format!("sha256:{HELLO_SHA256}"),
                },
            ],
        });
        let (origin, served) = serve_once(file_answer(body.to_string().as_bytes()));

        let release = latest_release_at(&latest_url(&origin), PLATFORM)
            .unwrap()
            .unwrap();
        served.join().unwrap();

        assert_eq!(release.filename, HELLO_FILE);
    }

    #[test]
    fn a_repository_with_no_release_is_not_an_error() {
        let (origin, served) = serve_once(http("404 Not Found", "", br#"{"message":"Not Found"}"#));

        assert_eq!(
            latest_release_at(&latest_url(&origin), PLATFORM).unwrap(),
            None
        );
        served.join().unwrap();
    }

    #[test]
    fn a_broken_answer_to_the_check_is_an_error() {
        let (origin, served) = serve_once(file_answer(b"<html>captive portal</html>"));
        assert!(matches!(
            latest_release_at(&latest_url(&origin), PLATFORM),
            Err(UpdateError::BadAnswer)
        ));
        served.join().unwrap();

        let (origin, served) = serve_once(http("500 Internal Server Error", "", b""));
        assert!(matches!(
            latest_release_at(&latest_url(&origin), PLATFORM),
            Err(UpdateError::Status(500))
        ));
        served.join().unwrap();
    }

    #[test]
    fn a_download_lands_in_the_folder_and_leaves_no_part_file() {
        let dir = tempfile::tempdir().unwrap();
        let (origin, served) = serve_once(file_answer(b"hello"));
        let mut received = 0;

        let path = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |so_far| received = so_far,
        )
        .unwrap();
        let request = served.join().unwrap();

        assert_eq!(path, dir.path().join(HELLO_FILE));
        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert_eq!(received, 5);
        assert_eq!(files_in(&dir), [HELLO_FILE]);
        assert!(
            request.starts_with(&download_line("v0.2.0", HELLO_FILE)),
            "{request}"
        );
        assert!(
            !request.to_ascii_lowercase().contains("authorization"),
            "{request}"
        );
        assert!(!request.contains("evil.example"), "{request}");
    }

    #[test]
    fn a_build_that_is_already_there_is_used_again_without_a_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HELLO_FILE);
        std::fs::write(&path, "hello").unwrap();

        // Nothing listens on this address: a request would fail.
        let found = download_at(
            "http://127.0.0.1:1/Chakyiu/g-ssh/releases/download",
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        );

        assert_eq!(found.unwrap(), path);
    }

    #[test]
    fn another_file_of_the_same_name_is_kept_and_the_build_gets_a_free_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(HELLO_FILE), "an older file").unwrap();
        let (origin, served) = serve_once(file_answer(b"hello"));

        let path = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        )
        .unwrap();
        served.join().unwrap();

        assert_eq!(
            path,
            dir.path().join("g-ssh-0.2.0-macos-aarch64.tar (1).gz")
        );
        assert_eq!(
            std::fs::read(dir.path().join(HELLO_FILE)).unwrap(),
            b"an older file"
        );
    }

    fn assert_nothing_left(dir: &tempfile::TempDir) {
        let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn a_file_with_the_wrong_checksum_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let (origin, served) = serve_once(file_answer(b"hellp"));

        let failed = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        );
        served.join().unwrap();

        assert!(
            matches!(failed, Err(UpdateError::WrongChecksum)),
            "{failed:?}"
        );
        assert_nothing_left(&dir);
    }

    #[test]
    fn a_content_length_that_disagrees_is_refused_before_anything_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let (origin, served) = serve_once(file_answer(b"hello, and more"));

        let failed = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        );
        served.join().unwrap();

        assert!(matches!(failed, Err(UpdateError::WrongSize)), "{failed:?}");
        assert_nothing_left(&dir);
    }

    #[test]
    fn a_body_longer_than_announced_is_refused_even_without_a_length() {
        let dir = tempfile::tempdir().unwrap();
        // No Content-Length: the body runs until the server closes.
        let (origin, served) = serve_once(http("200 OK", "", b"hello, and more"));

        let failed = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        );
        served.join().unwrap();

        assert!(matches!(failed, Err(UpdateError::WrongSize)), "{failed:?}");
        assert_nothing_left(&dir);
    }

    #[test]
    fn a_redirect_to_another_site_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let redirect = http(
            "302 Found",
            "Location: http://localhost:1/elsewhere\r\nContent-Length: 0\r\n",
            b"",
        );
        let (origin, served) = serve_once(redirect);

        let failed = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        );
        served.join().unwrap();

        assert!(matches!(failed, Err(UpdateError::OffSite)), "{failed:?}");
        assert_nothing_left(&dir);
    }

    #[test]
    fn a_redirect_on_the_same_host_is_followed() {
        let dir = tempfile::tempdir().unwrap();
        let redirect = http(
            "302 Found",
            "Location: /the-file\r\nContent-Length: 0\r\n",
            b"",
        );
        let (origin, served) = serve_each(vec![redirect, file_answer(b"hello")]);

        let path = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        )
        .unwrap();
        let requests = served.join().unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"hello");
        assert_eq!(
            requests,
            [
                download_line("v0.2.0", HELLO_FILE),
                "GET /the-file HTTP/1.1".to_string(),
            ]
        );
    }

    #[test]
    fn a_build_that_is_too_large_or_badly_named_is_refused_without_a_request() {
        let dir = tempfile::tempdir().unwrap();
        let nowhere = "http://127.0.0.1:1/Chakyiu/g-ssh/releases/download";

        let huge = Release {
            size_bytes: MAX_DOWNLOAD_BYTES + 1,
            ..hello_release()
        };
        let failed = download_at(nowhere, &huge, dir.path(), &not_cancelled(), |_| {});
        assert!(matches!(failed, Err(UpdateError::TooLarge)), "{failed:?}");

        let unnamed = Release {
            filename: "../".into(),
            ..hello_release()
        };
        let failed = download_at(nowhere, &unnamed, dir.path(), &not_cancelled(), |_| {});
        assert!(matches!(failed, Err(UpdateError::BadAnswer)), "{failed:?}");

        let elsewhere = Release {
            tag: "v0.2.0/../../evil".into(),
            ..hello_release()
        };
        let failed = download_at(nowhere, &elsewhere, dir.path(), &not_cancelled(), |_| {});
        assert!(matches!(failed, Err(UpdateError::BadAnswer)), "{failed:?}");
    }

    #[test]
    fn a_download_cancelled_on_the_way_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let (origin, served) = serve_once(file_answer(b"hello"));
        let is_cancelled = not_cancelled();

        // Cancelled when the first bytes have arrived.
        let failed = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &is_cancelled,
            |_| is_cancelled.store(true, Ordering::Relaxed),
        );
        served.join().unwrap();

        assert!(matches!(failed, Err(UpdateError::Cancelled)), "{failed:?}");
        assert_nothing_left(&dir);
    }

    #[test]
    fn a_download_cancelled_before_it_starts_makes_no_request() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());

        let failed = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &AtomicBool::new(true),
            |_| {},
        );

        assert!(matches!(failed, Err(UpdateError::Cancelled)), "{failed:?}");
        assert!(listener.accept().is_err(), "a request was made");
        assert_nothing_left(&dir);
    }

    #[test]
    fn a_cancel_after_a_wrong_file_stops_before_the_release_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let is_cancelled = std::sync::Arc::new(not_cancelled());
        let flag = is_cancelled.clone();
        // The file has another size, and the cancel comes while it is on its way.
        let (origin, served) = serve_once_after(file_answer(b"hello, and more"), move || {
            flag.store(true, Ordering::Relaxed)
        });

        let done = download_offer_at(
            &latest_url(&origin),
            &download_base(&origin),
            PLATFORM,
            &hello_release(),
            "0.1.0",
            dir.path(),
            &is_cancelled,
            |_, _| {},
        );
        served.join().unwrap();

        // Asking again would be a network error: nothing listens any more.
        assert!(matches!(done, Err(UpdateError::Cancelled)), "{done:?}");
        assert_nothing_left(&dir);
    }

    #[test]
    fn every_attempt_writes_to_a_part_file_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let first = part_path(dir.path(), "g-ssh-0.2.0.dmg");
        let second = part_path(dir.path(), "g-ssh-0.2.0.dmg");
        assert_ne!(first, second);
        assert_eq!(first.parent(), Some(dir.path()));
        assert!(first.to_string_lossy().ends_with(PART_SUFFIX));

        // The part file of another download that is still running, and a
        // file of the user's that only looks like a part file.
        std::fs::write(&first, "another download").unwrap();
        std::fs::write(dir.path().join("g-ssh-0.2.0.dmg.part"), "not ours").unwrap();
        let (origin, served) = serve_once(file_answer(b"hellp"));

        let failed = download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        );
        served.join().unwrap();

        assert!(
            matches!(failed, Err(UpdateError::WrongChecksum)),
            "{failed:?}"
        );
        assert_eq!(std::fs::read(&first).unwrap(), b"another download");
        assert_eq!(
            std::fs::read(dir.path().join("g-ssh-0.2.0.dmg.part")).unwrap(),
            b"not ours"
        );
        assert_eq!(files_in(&dir).len(), 2);
    }

    #[test]
    fn a_part_file_left_by_a_download_that_died_is_removed_by_the_next_one() {
        let dir = tempfile::tempdir().unwrap();
        let dead = part_path(dir.path(), "g-ssh-0.1.9.dmg");
        let running = part_path(dir.path(), "g-ssh-0.2.0.dmg");
        let other = dir.path().join("report.part");
        for path in [&dead, &running, &other] {
            std::fs::write(path, "half").unwrap();
        }
        let long_ago = SystemTime::now() - 2 * STALE_PART_AGE;
        for path in [&dead, &other] {
            File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(long_ago)
                .unwrap();
        }
        let (origin, served) = serve_once(file_answer(b"hello"));

        download_at(
            &download_base(&origin),
            &hello_release(),
            dir.path(),
            &not_cancelled(),
            |_| {},
        )
        .unwrap();
        served.join().unwrap();

        assert!(!dead.exists());
        assert!(running.exists());
        assert!(other.exists());
    }

    #[test]
    fn only_a_later_version_is_an_offer() {
        let offer = |tag: &str, current: &str| {
            let release = Release {
                tag: tag.into(),
                version: String::new(),
                ..hello_release()
            };
            let (origin, served) = serve_once(release_answer(&release));
            let offered = newer_release_at(&latest_url(&origin), PLATFORM, current).unwrap();
            served.join().unwrap();
            offered.map(|release| release.version)
        };

        assert_eq!(offer("v0.2.0", "0.1.0").as_deref(), Some("0.2.0"));
        assert_eq!(offer("v0.10.0", "0.9.9").as_deref(), Some("0.10.0"));
        assert_eq!(offer("v0.1.0", "0.1.0"), None);
        assert_eq!(offer("v0.0.9", "0.1.0"), None);
        // A tag that is not a version is never an offer. `v2.0.0` is.
        assert_eq!(offer("v2.0.0", "0.1.0").as_deref(), Some("2.0.0"));
        for tag in ["", "v2.0", "2.0.0-beta", "latest"] {
            assert_eq!(offer(tag, "0.1.0"), None, "{tag:?}");
        }
    }

    type Saved = Result<(Release, PathBuf), UpdateError>;

    /// Fetch the offer "hello" from a server that gives `answers`, one for
    /// each request. Returns the first line of every request too.
    fn fetch_offer(
        answers: Vec<Vec<u8>>,
        current: &str,
    ) -> (Saved, Vec<String>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let (origin, served) = serve_each(answers);
        let offered = hello_release();
        let done = download_offer_at(
            &latest_url(&origin),
            &download_base(&origin),
            PLATFORM,
            &offered,
            current,
            dir.path(),
            &not_cancelled(),
            |_, _| {},
        );
        (done, served.join().unwrap(), dir)
    }

    const WORLD_SHA256: &str = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";

    fn world_release() -> Release {
        Release {
            version: "0.3.0".into(),
            filename: WORLD_FILE.into(),
            sha256: WORLD_SHA256.into(),
            tag: "v0.3.0".into(),
            ..hello_release()
        }
    }

    #[test]
    fn an_offer_replaced_on_the_release_is_asked_for_again_and_the_new_build_is_saved() {
        let answers = vec![
            file_answer(b"world"),
            release_answer(&world_release()),
            file_answer(b"world"),
        ];

        let (done, requests, dir) = fetch_offer(answers, "0.1.0");

        let (saved, path) = done.unwrap();
        assert_eq!(saved, world_release());
        assert_eq!(path, dir.path().join(WORLD_FILE));
        assert_eq!(std::fs::read(&path).unwrap(), b"world");
        assert_eq!(
            requests,
            [
                download_line("v0.2.0", HELLO_FILE),
                latest_line(),
                download_line("v0.3.0", WORLD_FILE),
            ]
        );
    }

    #[test]
    fn a_broken_file_of_an_offer_that_still_stands_is_not_fetched_twice() {
        let answers = vec![file_answer(b"hellp"), release_answer(&hello_release())];

        let (done, _, dir) = fetch_offer(answers, "0.1.0");

        assert!(matches!(done, Err(UpdateError::WrongChecksum)), "{done:?}");
        assert_nothing_left(&dir);
    }

    #[test]
    fn an_offer_replaced_by_nothing_newer_is_withdrawn() {
        let no_release = http("404 Not Found", "", br#"{"message":"Not Found"}"#);
        let (done, _, dir) = fetch_offer(vec![file_answer(b"world"), no_release], "0.1.0");
        assert!(matches!(done, Err(UpdateError::Withdrawn)), "{done:?}");
        assert_nothing_left(&dir);

        // The replacement is the version this app already is.
        let answers = vec![file_answer(b"world"), release_answer(&world_release())];
        let (done, _, dir) = fetch_offer(answers, "0.3.0");
        assert!(matches!(done, Err(UpdateError::Withdrawn)), "{done:?}");
        assert_nothing_left(&dir);

        // The build was deleted: the download itself says so.
        let (done, requests, dir) = fetch_offer(vec![http("404 Not Found", "", b"{}")], "0.1.0");
        assert!(matches!(done, Err(UpdateError::Withdrawn)), "{done:?}");
        assert_eq!(requests.len(), 1);
        assert_nothing_left(&dir);
    }

    #[test]
    fn an_offer_that_is_still_right_is_saved_with_one_request() {
        let (done, requests, dir) = fetch_offer(vec![file_answer(b"hello")], "0.1.0");

        let (saved, path) = done.unwrap();
        assert_eq!(saved, hello_release());
        assert_eq!(path, dir.path().join(HELLO_FILE));
        assert_eq!(requests.len(), 1);
    }

    fn files_in(dir: &tempfile::TempDir) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_saved_build_carries_the_quarantine_mark() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HELLO_FILE);
        std::fs::write(&path, b"build").unwrap();

        mark_as_downloaded(&path);

        let mark = std::process::Command::new("/usr/bin/xattr")
            .args(["-p", "com.apple.quarantine"])
            .arg(&path)
            .output()
            .unwrap();
        let mark = String::from_utf8_lossy(&mark.stdout);
        assert!(
            mark.starts_with("0081;") && mark.contains(";g-ssh;"),
            "{mark}"
        );
    }
}
