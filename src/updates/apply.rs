//! Replace the running app with a build that [`super::download`] already
//! checked, then reopen it.
//!
//! The files of a running app cannot be swapped out from under it. Download
//! stays in the cache. This copies the new app beside the old one, starts a
//! second copy of g-ssh, and the caller quits. That second copy waits until
//! this process is gone, moves the new app into place, and opens it.
//!
//! macOS publishes a disk image of `g-ssh.app`. Windows publishes a zip of
//! `g-ssh.exe`. The signature on the Mac build is ad-hoc, so Gatekeeper
//! would refuse to reopen a quarantined copy. The archive was already
//! checked against the checksum GitHub announced, and only then is the
//! quarantine mark removed.

use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime};

use super::UpdateError;

const BUNDLE_ID: &str = "app.g-ssh";
const BUNDLE_EXE: &str = "g-ssh";
const READY: &str = "ready";
/// How long the installer waits for this process to quit.
const QUIT_WAIT: Duration = Duration::from_secs(60);
const READY_WAIT: Duration = Duration::from_secs(10);
const STALE_AFTER: Duration = Duration::from_secs(60 * 60);

/// Run the installer when this process was started as one, and do not return.
/// A normal launch returns immediately.
pub fn finish_if_requested() {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(OsStr::new("--finish-update")) {
        return;
    }
    let code = match finish_from_args(args) {
        Ok(()) => 0,
        Err(error) => {
            log_line(&error.to_string());
            1
        }
    };
    std::process::exit(code);
}

/// Copy `archive` over this app and arm the installer. The caller quits when
/// this returns. Nothing is replaced while this process is still running.
pub fn install(archive: &Path, is_cancelled: &AtomicBool, token: &str) -> Result<(), UpdateError> {
    if is_cancelled.load(Ordering::Relaxed) {
        return Err(UpdateError::Cancelled);
    }
    if !is_token(token) {
        return Err(UpdateError::Install("could not start the installer".into()));
    }
    #[cfg(target_os = "macos")]
    {
        return install_macos(archive, is_cancelled, token);
    }
    #[cfg(windows)]
    {
        return install_windows(archive, is_cancelled, token);
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (archive, token);
        Err(UpdateError::NotInstalled)
    }
}

#[cfg(target_os = "macos")]
fn install_macos(
    archive: &Path,
    is_cancelled: &AtomicBool,
    token: &str,
) -> Result<(), UpdateError> {
    expect_extension(archive, "dmg")?;
    let dest = install_destination()?;
    let Some(parent) = dest.parent().map(Path::to_path_buf) else {
        return Err(UpdateError::NotWritable);
    };
    remove_stale_leftovers(&parent);
    detach_remembered_mount();
    if is_cancelled.load(Ordering::Relaxed) {
        return Err(UpdateError::Cancelled);
    }

    let mounted = attach_image(archive)?;
    if is_cancelled.load(Ordering::Relaxed) {
        return Err(UpdateError::Cancelled);
    }
    let source = mounted.mount_point.join("g-ssh.app");
    validate_bundle(&source)?;

    let staged = stage_dir(&parent)?;
    let payload = staged.dir.join("g-ssh.app");
    copy_app(&source, &payload)?;
    // The image is done. Dropping it detaches the disk.
    drop(mounted);
    // The mark would make Gatekeeper refuse the relaunch. The checksum
    // already decided this file is the build GitHub announced.
    clear_quarantine(&payload)?;
    verify_signature(&payload)?;
    if is_cancelled.load(Ordering::Relaxed) {
        return Err(UpdateError::Cancelled);
    }

    let request = SwapRequest {
        pid: std::process::id(),
        dest,
        staged: payload,
        stage_dir: staged.dir.clone(),
        archive: archive.to_path_buf(),
        token: token.to_string(),
    };
    spawn_installer(&request)?;
    staged.keep();
    Ok(())
}

#[cfg(windows)]
fn install_windows(
    archive: &Path,
    is_cancelled: &AtomicBool,
    token: &str,
) -> Result<(), UpdateError> {
    expect_extension(archive, "zip")?;
    let dest = std::env::current_exe()
        .map_err(|e| UpdateError::Install(format!("could not find this app: {e}")))?;
    let dest = dest.canonicalize().unwrap_or(dest);
    if dest.file_name() != Some(OsStr::new("g-ssh.exe")) || !is_real_file(&dest) {
        return Err(UpdateError::NotInstalled);
    }
    if !parent_is_writable(&dest) {
        return Err(UpdateError::NotWritable);
    }
    let Some(parent) = dest.parent().map(Path::to_path_buf) else {
        return Err(UpdateError::NotWritable);
    };
    remove_stale_leftovers(&parent);
    if is_cancelled.load(Ordering::Relaxed) {
        return Err(UpdateError::Cancelled);
    }

    let staged = stage_dir(&parent)?;
    let unpack = staged.dir.join("unpack");
    fs::create_dir(&unpack)
        .map_err(|e| UpdateError::Install(format!("could not unpack the build: {e}")))?;
    unpack_zip(archive, &unpack)?;
    let exe = find_named_file(&unpack, "g-ssh.exe")?;
    let payload = staged.dir.join("g-ssh.exe");
    fs::copy(&exe, &payload)
        .map_err(|e| UpdateError::Install(format!("could not copy the new app: {e}")))?;
    let _ = fs::remove_dir_all(&unpack);
    if is_cancelled.load(Ordering::Relaxed) {
        return Err(UpdateError::Cancelled);
    }

    let request = SwapRequest {
        pid: std::process::id(),
        dest,
        staged: payload,
        stage_dir: staged.dir.clone(),
        archive: archive.to_path_buf(),
        token: token.to_string(),
    };
    spawn_installer(&request)?;
    staged.keep();
    Ok(())
}

struct SwapRequest {
    pid: u32,
    dest: PathBuf,
    staged: PathBuf,
    stage_dir: PathBuf,
    archive: PathBuf,
    /// Names the cancel file. Hex only, so it cannot be a path.
    token: String,
}

/// Ask a running installer for `token` to stop. The app keeps running.
pub fn cancel_installer(token: &str) {
    let Some(path) = cancel_path(token) else {
        return;
    };
    let _ = fs::write(path, b"");
}

fn finish_from_args(mut args: impl Iterator<Item = OsString>) -> Result<(), UpdateError> {
    let request = SwapRequest {
        pid: parse_pid(args.next())?,
        dest: args
            .next()
            .map(PathBuf::from)
            .ok_or_else(bad_installer_args)?,
        staged: args
            .next()
            .map(PathBuf::from)
            .ok_or_else(bad_installer_args)?,
        stage_dir: args
            .next()
            .map(PathBuf::from)
            .ok_or_else(bad_installer_args)?,
        archive: args
            .next()
            .map(PathBuf::from)
            .ok_or_else(bad_installer_args)?,
        token: args
            .next()
            .and_then(|text| text.into_string().ok())
            .ok_or_else(bad_installer_args)?,
    };
    if args.next().is_some() {
        return Err(bad_installer_args());
    }
    let Some(cache) = super::cache_dir() else {
        return Err(UpdateError::Install(
            "could not find a place to store the update".into(),
        ));
    };
    if !swap_request_is_safe(&request, &cache)? {
        return Err(UpdateError::Install(
            "refused to replace a folder that is not this app".into(),
        ));
    }
    // The parent quits when it sees this. Say it only after the request is
    // one this process is willing to carry out.
    tell_parent_ready()?;
    log_line(&format!(
        "waiting for {} to quit, then replacing {}",
        request.pid,
        request.dest.display()
    ));
    match wait_for_parent(request.pid, &request.token) {
        Wait::Quit => {}
        Wait::Cancelled => {
            let _ = fs::remove_dir_all(&request.stage_dir);
            if let Some(path) = cancel_path(&request.token) {
                let _ = fs::remove_file(path);
            }
            return Ok(());
        }
        Wait::TimedOut => {
            let _ = fs::remove_dir_all(&request.stage_dir);
            return Err(UpdateError::Install(
                "g-ssh did not quit, so the update was not applied".into(),
            ));
        }
    }
    // Checked again in this process. The staged copy is the only thing that
    // is allowed to take the app's place.
    if !staged_payload_is_safe(&request.staged) {
        let _ = fs::remove_dir_all(&request.stage_dir);
        return Err(UpdateError::NotAnApp);
    }
    let trash = match swap_in(&request.dest, &request.staged) {
        Ok(trash) => trash,
        Err(error) => {
            let _ = fs::remove_dir_all(&request.stage_dir);
            return Err(error);
        }
    };
    // The mark was already removed on the staged copy. Rename keeps it off.
    // A failure here must not leave the new app unopened.
    #[cfg(target_os = "macos")]
    if let Err(error) = clear_quarantine(&request.dest) {
        log_line(&error.to_string());
    }
    let reopened = relaunch(&request.dest);
    let mut leftovers = vec![request.stage_dir, request.archive];
    if let Some(trash) = trash {
        leftovers.push(trash);
    }
    remove_leftovers(&leftovers);
    reopened
}

fn tell_parent_ready() -> Result<(), UpdateError> {
    let mut out = std::io::stdout();
    writeln!(out, "{READY}").map_err(|e| UpdateError::Install(e.to_string()))?;
    out.flush()
        .map_err(|e| UpdateError::Install(e.to_string()))?;
    Ok(())
}

fn bad_installer_args() -> UpdateError {
    UpdateError::Install("the installer was started with the wrong arguments".into())
}

fn parse_pid(text: Option<OsString>) -> Result<u32, UpdateError> {
    let text = text.ok_or_else(bad_installer_args)?;
    text.to_str()
        .and_then(|text| text.parse().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(bad_installer_args)
}

/// The app this process should replace.
#[cfg(target_os = "macos")]
fn install_destination() -> Result<PathBuf, UpdateError> {
    let exe = std::env::current_exe()
        .map_err(|e| UpdateError::Install(format!("could not find this app: {e}")))?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let Some(bundle) = bundle_from_exe_path(&exe) else {
        return Err(UpdateError::NotInstalled);
    };
    // Opened from the disk image. macOS is running a read-only copy. Put the
    // real one in Applications, which is where the image itself points.
    if is_translocated_path(&exe) {
        return applications_destination();
    }
    if parent_is_writable(&bundle) {
        return Ok(bundle);
    }
    Err(UpdateError::NotWritable)
}

#[cfg(target_os = "macos")]
fn applications_destination() -> Result<PathBuf, UpdateError> {
    let mut folders = vec![PathBuf::from("/Applications")];
    if let Some(home) = dirs::home_dir() {
        folders.push(home.join("Applications"));
    }
    for folder in folders {
        if folder == Path::new("/Applications") && !folder.is_dir() {
            continue;
        }
        if !folder.exists() && fs::create_dir_all(&folder).is_err() {
            continue;
        }
        let dest = folder.join("g-ssh.app");
        if parent_is_writable(&dest) {
            return Ok(dest);
        }
    }
    Err(UpdateError::NotWritable)
}

fn parent_is_writable(dest: &Path) -> bool {
    let Some(parent) = dest.parent() else {
        return false;
    };
    if !parent.is_dir() {
        return false;
    }
    let probe = parent.join(format!(".g-ssh-write-{}", std::process::id()));
    match OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// A directory of our own, next to the app, so the rename stays on one volume.
fn stage_dir(parent: &Path) -> Result<Staged, UpdateError> {
    let dir = parent.join(format!(".g-ssh-update-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir(&dir).map_err(|e| {
        UpdateError::Install(format!("could not make a place for the new app: {e}"))
    })?;
    Ok(Staged { dir, keep: false })
}

struct Staged {
    dir: PathBuf,
    keep: bool,
}

impl Staged {
    /// The installer now owns this directory.
    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

#[cfg(target_os = "macos")]
struct Mounted {
    mount_point: PathBuf,
    root: PathBuf,
}

#[cfg(target_os = "macos")]
impl Drop for Mounted {
    fn drop(&mut self) {
        if detach_image(&self.mount_point) {
            forget_mount();
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[cfg(target_os = "macos")]
fn attach_image(archive: &Path) -> Result<Mounted, UpdateError> {
    let Some(cache) = super::cache_dir() else {
        return Err(UpdateError::Install(
            "could not find a place to store the update".into(),
        ));
    };
    let root = cache.join(format!("mount-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir(&root)
        .map_err(|e| UpdateError::Install(format!("could not open the disk image: {e}")))?;
    let output = Command::new("/usr/bin/hdiutil")
        .args(["attach", "-nobrowse", "-readonly", "-plist", "-mountrandom"])
        .arg(&root)
        .arg(archive)
        .output()
        .map_err(|e| UpdateError::Install(format!("could not open the disk image: {e}")))?;
    if !output.status.success() {
        let _ = fs::remove_dir_all(&root);
        return Err(command_error("could not open the disk image", &output));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(mount_point) = mount_point_inside(&text, &root) else {
        let _ = fs::remove_dir_all(&root);
        return Err(UpdateError::Install("could not open the disk image".into()));
    };
    remember_mount(&mount_point);
    Ok(Mounted { mount_point, root })
}

#[cfg(target_os = "macos")]
fn detach_image(mount_point: &Path) -> bool {
    Command::new("/usr/bin/hdiutil")
        .args(["detach", "-quiet", "-force"])
        .arg(mount_point)
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(target_os = "macos")]
fn mount_record() -> Option<PathBuf> {
    Some(super::cache_dir()?.join("mounted-image"))
}

#[cfg(target_os = "macos")]
fn remember_mount(mount_point: &Path) {
    let Some(record) = mount_record() else {
        return;
    };
    let _ = fs::write(record, mount_point.as_os_str().as_encoded_bytes());
}

#[cfg(target_os = "macos")]
fn forget_mount() {
    if let Some(record) = mount_record() {
        let _ = fs::remove_file(record);
    }
}

/// A previous install died after attaching the image. Detach it if it is
/// still one of ours.
#[cfg(target_os = "macos")]
fn detach_remembered_mount() {
    let Some(record) = mount_record() else {
        return;
    };
    let Ok(bytes) = fs::read(&record) else {
        return;
    };
    let path = path_from_bytes(&bytes);
    if let Some(cache) = super::cache_dir() {
        if path_is_inside(&path, &cache) {
            let _ = detach_image(&path);
        }
    }
    let _ = fs::remove_file(record);
}

#[cfg(target_os = "macos")]
fn copy_app(source: &Path, dest: &Path) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/ditto")
        .arg(source)
        .arg(dest)
        .output()
        .map_err(|e| UpdateError::Install(format!("could not copy the new app: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error("could not copy the new app", &output))
    }
}

#[cfg(target_os = "macos")]
fn clear_quarantine(app: &Path) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/xattr")
        .args(["-dr", "com.apple.quarantine"])
        .arg(app)
        .output()
        .map_err(|e| UpdateError::Install(format!("could not prepare the new app: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error("could not prepare the new app", &output))
    }
}

#[cfg(target_os = "macos")]
fn verify_signature(app: &Path) -> Result<(), UpdateError> {
    let output = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(app)
        .output()
        .map_err(|e| UpdateError::Install(format!("could not check the new app: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(
            "the new app's signature does not check out",
            &output,
        ))
    }
}

#[cfg(windows)]
fn unpack_zip(archive: &Path, dest: &Path) -> Result<(), UpdateError> {
    archive_listing_is_safe(archive)?;
    let output = Command::new("tar")
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(dest)
        .output()
        .map_err(|e| UpdateError::Install(format!("could not unpack the build: {e}")))?;
    if !output.status.success() {
        return Err(command_error("could not unpack the build", &output));
    }
    if tree_stays_inside(dest).is_err() {
        let _ = fs::remove_dir_all(dest);
        return Err(UpdateError::NotAnApp);
    }
    Ok(())
}

/// Refuse a listing that could write outside the unpack folder.
#[cfg(windows)]
fn archive_listing_is_safe(archive: &Path) -> Result<(), UpdateError> {
    let output = Command::new("tar")
        .arg("-tf")
        .arg(archive)
        .output()
        .map_err(|e| UpdateError::Install(format!("could not unpack the build: {e}")))?;
    if !output.status.success() {
        return Err(command_error("could not unpack the build", &output));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let path = Path::new(line.trim());
        let escapes = path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir));
        if escapes {
            return Err(UpdateError::NotAnApp);
        }
    }
    Ok(())
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn command_error(what: &str, output: &std::process::Output) -> UpdateError {
    let detail = String::from_utf8_lossy(&output.stderr);
    let detail = detail.trim();
    if detail.is_empty() {
        return UpdateError::Install(what.into());
    }
    let detail: String = detail.chars().take(200).collect();
    UpdateError::Install(format!("{what}: {detail}"))
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn spawn_installer(request: &SwapRequest) -> Result<(), UpdateError> {
    let exe = std::env::current_exe()
        .map_err(|e| UpdateError::Install(format!("could not find this app: {e}")))?;
    let (reader, writer) = std::io::pipe()
        .map_err(|e| UpdateError::Install(format!("could not start the installer: {e}")))?;
    let mut cmd = Command::new(exe);
    cmd.arg("--finish-update")
        .arg(request.pid.to_string())
        .arg(&request.dest)
        .arg(&request.staged)
        .arg(&request.stage_dir)
        .arg(&request.archive)
        .arg(&request.token)
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(swap_log());
    detach(&mut cmd);
    let mut child = cmd
        .spawn()
        .map_err(|e| UpdateError::Install(format!("could not start the installer: {e}")))?;
    if !installer_is_ready(reader) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(UpdateError::Install("could not start the installer".into()));
    }
    tracing::info!(dest = %request.dest.display(), "update installer is waiting for g-ssh to quit");
    Ok(())
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn installer_is_ready(reader: std::io::PipeReader) -> bool {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let ok = BufReader::new(reader).read_line(&mut line).is_ok() && line.starts_with(READY);
        let _ = tx.send(ok);
    });
    rx.recv_timeout(READY_WAIT).unwrap_or(false)
}

fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Safety: runs after fork and only calls setsid, which is
        // async-signal-safe. A new session is what keeps the installer
        // alive when the app quits.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn swap_log() -> Stdio {
    let Some(dir) = super::cache_dir() else {
        return Stdio::null();
    };
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("swap.log"))
        .map(Stdio::from)
        .unwrap_or_else(|_| Stdio::null())
}

fn log_line(text: &str) {
    let Some(dir) = super::cache_dir() else {
        return;
    };
    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("swap.log"))
    else {
        return;
    };
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let _ = writeln!(file, "{stamp} {text}");
}

/// `true` when every path we were given is this app, the staged copy, and
/// the archive in the cache. A request that fails this does not move files.
fn swap_request_is_safe(request: &SwapRequest, cache: &Path) -> Result<bool, UpdateError> {
    let paths = [
        &request.dest,
        &request.staged,
        &request.stage_dir,
        &request.archive,
    ];
    if paths.iter().any(|path| !is_absolute_normal(path)) {
        return Ok(false);
    }
    let stage_name = request.stage_dir.file_name().and_then(|name| name.to_str());
    let stage_ok = stage_name.is_some_and(is_stage_name)
        && request.staged.parent() == Some(request.stage_dir.as_path())
        && request.stage_dir.parent() == request.dest.parent();
    if !stage_ok
        || !is_token(&request.token)
        || !dest_is_safe(&request.dest)
        || !staged_payload_is_safe(&request.staged)
    {
        return Ok(false);
    }
    Ok(archive_is_safe(&request.archive, cache))
}

fn is_absolute_normal(path: &Path) -> bool {
    path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir))
}

fn is_stage_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(".g-ssh-update-") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit())
}

fn dest_is_safe(dest: &Path) -> bool {
    #[cfg(windows)]
    {
        dest.file_name() == Some(OsStr::new("g-ssh.exe")) && (!dest.exists() || is_real_file(dest))
    }
    #[cfg(not(windows))]
    {
        match dest.file_name().and_then(|name| name.to_str()) {
            Some("g-ssh.app") => !dest.exists() || is_real_dir(dest),
            Some(name) if name.ends_with(".app") => validate_bundle(dest).is_ok(),
            _ => false,
        }
    }
}

fn staged_payload_is_safe(staged: &Path) -> bool {
    #[cfg(windows)]
    {
        staged.file_name() == Some(OsStr::new("g-ssh.exe")) && is_real_file(staged)
    }
    #[cfg(not(windows))]
    {
        staged.file_name() == Some(OsStr::new("g-ssh.app")) && validate_bundle(staged).is_ok()
    }
}

fn archive_is_safe(archive: &Path, cache: &Path) -> bool {
    let name = archive
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let ext_ok = name.ends_with(".dmg") || name.ends_with(".zip");
    ext_ok && is_real_file(archive) && path_is_inside(archive, cache)
}

/// Move `staged` onto `dest`. The old app, when there was one, is left at
/// the returned path so the caller can delete it after this process exits.
fn swap_in(dest: &Path, staged: &Path) -> Result<Option<PathBuf>, UpdateError> {
    if dest == staged {
        return Err(UpdateError::Install(
            "could not move the new app into place".into(),
        ));
    }
    let Some(parent) = dest.parent() else {
        return Err(UpdateError::NotWritable);
    };
    let trash = parent.join(format!(".g-ssh-old-{}", uuid::Uuid::new_v4().simple()));
    let had_dest = dest.exists();
    if had_dest && fs::rename(dest, &trash).is_err() {
        return Err(UpdateError::Install(
            "could not move the current app aside".into(),
        ));
    }
    if let Err(error) = fs::rename(staged, dest) {
        if had_dest {
            let _ = fs::rename(&trash, dest);
        }
        return Err(UpdateError::Install(format!(
            "could not move the new app into place: {error}"
        )));
    }
    Ok(had_dest.then_some(trash))
}

fn relaunch(dest: &Path) -> Result<(), UpdateError> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("/usr/bin/open")
            .arg(dest)
            .output()
            .map_err(|e| UpdateError::Install(format!("could not reopen g-ssh: {e}")))?;
        if output.status.success() {
            return Ok(());
        }
        return Err(command_error("could not reopen g-ssh", &output));
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        return Command::new(dest)
            .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .spawn()
            .map(|_| ())
            .map_err(|e| UpdateError::Install(format!("could not reopen g-ssh: {e}")));
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = dest;
        Err(UpdateError::NotInstalled)
    }
}

fn remove_leftovers(paths: &[PathBuf]) {
    let mut pending: Vec<PathBuf> = paths.iter().filter(|path| path.exists()).cloned().collect();
    for _ in 0..5 {
        pending.retain(|path| {
            if path.is_dir() {
                fs::remove_dir_all(path).is_err()
            } else {
                fs::remove_file(path).is_err()
            }
        });
        if pending.is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    // The installer is still running from the old copy, so that folder
    // cannot be deleted yet. A second process deletes it after we exit.
    schedule_cleanup(&pending);
}

fn schedule_cleanup(paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    #[cfg(unix)]
    {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("sleep 1; for p in \"$@\"; do rm -rf -- \"$p\"; done")
            .arg("g-ssh-cleanup");
        for path in paths {
            cmd.arg(path);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        detach(&mut cmd);
        let _ = cmd.spawn();
    }
    #[cfg(windows)]
    {
        let Some(dir) = super::cache_dir() else {
            return;
        };
        let list_path = dir.join(format!("cleanup-{}", uuid::Uuid::new_v4().simple()));
        let mut text = String::new();
        for path in paths {
            let line = path.to_string_lossy();
            if line.contains('\n') {
                continue;
            }
            text.push_str(&line);
            text.push('\n');
        }
        if fs::write(&list_path, text).is_err() {
            return;
        }
        let mut cmd = Command::new("powershell.exe");
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Start-Sleep -Seconds 1; Get-Content -LiteralPath $env:GSSH_CLEANUP | ForEach-Object { if ($_) { Remove-Item -LiteralPath $_ -Recurse -Force -ErrorAction SilentlyContinue } }; Remove-Item -LiteralPath $env:GSSH_CLEANUP -Force -ErrorAction SilentlyContinue",
        ])
        .env("GSSH_CLEANUP", &list_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        detach(&mut cmd);
        let _ = cmd.spawn();
    }
}

enum Wait {
    Quit,
    Cancelled,
    TimedOut,
}

fn wait_for_parent(pid: u32, token: &str) -> Wait {
    let started = SystemTime::now();
    while started.elapsed().unwrap_or(QUIT_WAIT) < QUIT_WAIT {
        if cancel_path(token).is_some_and(|path| path.is_file()) {
            return Wait::Cancelled;
        }
        if !process_exists(pid) {
            return Wait::Quit;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if !process_exists(pid) {
        Wait::Quit
    } else {
        Wait::TimedOut
    }
}

fn is_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 64 && token.chars().all(|c| c.is_ascii_hexdigit())
}

fn cancel_path(token: &str) -> Option<PathBuf> {
    if !is_token(token) {
        return None;
    }
    Some(super::cache_dir()?.join(format!("cancel-{token}")))
}

fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if pid == 0 || pid > i32::MAX as u32 {
            return false;
        }
        let rc = unsafe { libc::kill(pid as i32, 0) };
        if rc == 0 {
            return true;
        }
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
            fn CloseHandle(handle: isize) -> i32;
            fn GetLastError() -> u32;
        }
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        const ERROR_ACCESS_DENIED: u32 = 5;
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle != 0 {
                CloseHandle(handle);
                return true;
            }
            GetLastError() == ERROR_ACCESS_DENIED
        }
    }
}

fn remove_stale_leftovers(parent: &Path) {
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !is_leftover_name(&name) {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) else {
            continue;
        };
        let Ok(age) = SystemTime::now().duration_since(modified) else {
            continue;
        };
        if age <= STALE_AFTER {
            continue;
        }
        let path = entry.path();
        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_file(&path);
    }
}

fn is_leftover_name(name: &str) -> bool {
    for prefix in [".g-ssh-update-", ".g-ssh-old-", "mount-"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit());
        }
    }
    false
}

/// The `.app` that contains `exe`, when `exe` is `Something.app/Contents/MacOS/g-ssh`.
fn bundle_from_exe_path(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    if macos.file_name() != Some(OsStr::new("MacOS")) {
        return None;
    }
    let contents = macos.parent()?;
    if contents.file_name() != Some(OsStr::new("Contents")) {
        return None;
    }
    let app = contents.parent()?;
    if app.extension() != Some(OsStr::new("app")) {
        return None;
    }
    Some(app.to_path_buf())
}

fn is_translocated_path(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str() == "AppTranslocation")
}

fn expect_extension(archive: &Path, ext: &str) -> Result<(), UpdateError> {
    if archive.extension() == Some(OsStr::new(ext)) && is_real_file(archive) {
        Ok(())
    } else {
        Err(UpdateError::NotAnApp)
    }
}

/// `g-ssh.app` with this app's bundle id and a real executable, not a link.
fn validate_bundle(app: &Path) -> Result<(), UpdateError> {
    if !is_real_dir(app) {
        return Err(UpdateError::NotAnApp);
    }
    let plist_path = app.join("Contents/Info.plist");
    if !is_real_file(&plist_path) {
        return Err(UpdateError::NotAnApp);
    }
    let plist = fs::read_to_string(&plist_path).map_err(|_| UpdateError::NotAnApp)?;
    if string_after_key(&plist, "CFBundleIdentifier").as_deref() != Some(BUNDLE_ID) {
        return Err(UpdateError::NotAnApp);
    }
    if string_after_key(&plist, "CFBundleExecutable").as_deref() != Some(BUNDLE_EXE) {
        return Err(UpdateError::NotAnApp);
    }
    let exe = app.join("Contents/MacOS").join(BUNDLE_EXE);
    if !is_real_file(&exe) {
        return Err(UpdateError::NotAnApp);
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn find_named_file(root: &Path, name: &str) -> Result<PathBuf, UpdateError> {
    let mut found = Vec::new();
    visit_files(root, name, &mut found)?;
    match found.len() {
        1 => Ok(found.remove(0)),
        _ => Err(UpdateError::NotAnApp),
    }
}

#[cfg(any(windows, test))]
fn visit_files(dir: &Path, name: &str, found: &mut Vec<PathBuf>) -> Result<(), UpdateError> {
    let entries = fs::read_dir(dir).map_err(|_| UpdateError::NotAnApp)?;
    for entry in entries {
        let entry = entry.map_err(|_| UpdateError::NotAnApp)?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|_| UpdateError::NotAnApp)?;
        if meta.file_type().is_symlink() {
            return Err(UpdateError::NotAnApp);
        }
        if meta.is_dir() {
            visit_files(&path, name, found)?;
        } else if meta.is_file() && entry.file_name() == name {
            found.push(path);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn tree_stays_inside(root: &Path) -> Result<(), UpdateError> {
    let root = root.canonicalize().map_err(|_| UpdateError::NotAnApp)?;
    visit_confined(&root, &root)
}

#[cfg(windows)]
fn visit_confined(dir: &Path, root: &Path) -> Result<(), UpdateError> {
    let entries = fs::read_dir(dir).map_err(|_| UpdateError::NotAnApp)?;
    for entry in entries {
        let entry = entry.map_err(|_| UpdateError::NotAnApp)?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|_| UpdateError::NotAnApp)?;
        if meta.file_type().is_symlink() {
            return Err(UpdateError::NotAnApp);
        }
        let canon = path.canonicalize().map_err(|_| UpdateError::NotAnApp)?;
        if !canon.starts_with(root) {
            return Err(UpdateError::NotAnApp);
        }
        if meta.is_dir() {
            visit_confined(&canon, root)?;
        }
    }
    Ok(())
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

fn is_real_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

fn path_is_inside(path: &Path, root: &Path) -> bool {
    let (Ok(path), Ok(root)) = (path.canonicalize(), root.canonicalize()) else {
        return false;
    };
    path.starts_with(&root) && path != root
}

/// The `<string>` that follows `<key>name</key>`, with the usual entities decoded.
fn string_after_key(xml: &str, key: &str) -> Option<String> {
    let marker = format!("<key>{key}</key>");
    let after = xml.split_once(&marker)?.1.trim_start();
    let value = after.strip_prefix("<string>")?;
    let end = value.find("</string>")?;
    decode_xml_text(&value[..end])
}

fn mount_point_inside(plist: &str, root: &Path) -> Option<PathBuf> {
    let mut rest = plist;
    while let Some((_, after)) = rest.split_once("<key>mount-point</key>") {
        let after = after.trim_start();
        let Some(value) = after.strip_prefix("<string>") else {
            return None;
        };
        let Some(end) = value.find("</string>") else {
            return None;
        };
        let point = decode_xml_text(&value[..end])?;
        let path = PathBuf::from(&point);
        if path_is_inside(&path, root) {
            return Some(path);
        }
        rest = &value[end..];
    }
    None
}

fn decode_xml_text(text: &str) -> Option<String> {
    if text.chars().any(|c| c.is_control()) {
        return None;
    }
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let end = rest.find(';')?;
        let entity = &rest[..=end];
        let decoded = match entity {
            "&amp;" => "&",
            "&lt;" => "<",
            "&gt;" => ">",
            "&quot;" => "\"",
            "&apos;" => "'",
            _ => return None,
        };
        out.push_str(decoded);
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return PathBuf::from(OsStr::from_bytes(bytes));
    }
    #[cfg(not(unix))]
    {
        PathBuf::from(String::from_utf8_lossy(bytes).as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key>
  <string>g-ssh</string>
  <key>CFBundleIdentifier</key>
  <string>app.g-ssh</string>
</dict></plist>"#;

    fn write_app(path: &Path) {
        fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
        fs::write(path.join("Contents/Info.plist"), PLIST).unwrap();
        fs::write(path.join("Contents/MacOS/g-ssh"), b"bin").unwrap();
    }

    #[test]
    fn the_running_app_is_the_bundle_around_the_executable() {
        let exe = Path::new("/Applications/g-ssh.app/Contents/MacOS/g-ssh");
        assert_eq!(
            bundle_from_exe_path(exe).as_deref(),
            Some(Path::new("/Applications/g-ssh.app"))
        );
        assert_eq!(
            bundle_from_exe_path(Path::new("/usr/local/bin/g-ssh")),
            None
        );
        assert_eq!(
            bundle_from_exe_path(Path::new("/Applications/g-ssh.app/MacOS/g-ssh")),
            None
        );
        assert!(is_translocated_path(Path::new(
            "/private/var/folders/ab/AppTranslocation/ABC/d/g-ssh.app/Contents/MacOS/g-ssh"
        )));
        assert!(!is_translocated_path(exe));
    }

    #[test]
    fn the_string_after_a_plist_key_is_read() {
        assert_eq!(
            string_after_key(PLIST, "CFBundleIdentifier").as_deref(),
            Some("app.g-ssh")
        );
        let indented = "<key>mount-point</key>\n\t\t\t<string>/private/tmp/dmg.abc</string>";
        assert_eq!(
            string_after_key(indented, "mount-point").as_deref(),
            Some("/private/tmp/dmg.abc")
        );
        assert_eq!(
            string_after_key(
                "<key>mount-point</key><string>a&amp;b</string>",
                "mount-point"
            )
            .as_deref(),
            Some("a&b")
        );
        assert_eq!(string_after_key(PLIST, "CFBundleName"), None);
        assert_eq!(
            string_after_key("<key>mount-point</key><string>a&b</string>", "mount-point"),
            None
        );
    }

    #[test]
    fn a_mount_point_has_to_stay_inside_the_folder_we_chose() {
        let root = tempfile::tempdir().unwrap();
        let inside = root.path().join("dmg.abc");
        fs::create_dir(&inside).unwrap();
        let plist = format!(
            "<key>dev-entry</key><string>/dev/disk0</string>\
             <key>mount-point</key><string>{}</string>",
            inside.display()
        );
        assert_eq!(mount_point_inside(&plist, root.path()), Some(inside));

        let outside = format!(
            "<key>mount-point</key><string>{}</string>",
            root.path().display()
        );
        assert_eq!(mount_point_inside(&outside, root.path()), None);
    }

    #[test]
    fn only_this_apps_bundle_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("g-ssh.app");
        write_app(&app);
        assert!(validate_bundle(&app).is_ok());

        let mut wrong = PLIST.replace("app.g-ssh", "com.example.other");
        fs::write(app.join("Contents/Info.plist"), &wrong).unwrap();
        assert!(matches!(validate_bundle(&app), Err(UpdateError::NotAnApp)));

        wrong = PLIST.replace("g-ssh</string>", "other</string>");
        // The executable name in the plist is what changed. Put the id back.
        let wrong = wrong.replace("com.example.other", "app.g-ssh");
        fs::write(app.join("Contents/Info.plist"), wrong).unwrap();
        assert!(validate_bundle(&app).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_executable_is_not_the_app() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("g-ssh.app");
        write_app(&app);
        let exe = app.join("Contents/MacOS/g-ssh");
        fs::remove_file(&exe).unwrap();
        std::os::unix::fs::symlink("/tmp/other", &exe).unwrap();
        assert!(matches!(validate_bundle(&app), Err(UpdateError::NotAnApp)));
    }

    #[test]
    fn one_executable_in_the_archive_is_the_build() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("g-ssh-0.2.0-windows-x86_64");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("g-ssh.exe"), b"exe").unwrap();
        fs::write(nested.join("LICENSE.txt"), b"license").unwrap();
        assert_eq!(
            find_named_file(dir.path(), "g-ssh.exe").unwrap(),
            nested.join("g-ssh.exe")
        );

        fs::write(dir.path().join("g-ssh.exe"), b"second").unwrap();
        assert!(matches!(
            find_named_file(dir.path(), "g-ssh.exe"),
            Err(UpdateError::NotAnApp)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_in_the_archive_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/tmp", dir.path().join("elsewhere")).unwrap();
        assert!(matches!(
            find_named_file(dir.path(), "g-ssh.exe"),
            Err(UpdateError::NotAnApp)
        ));
    }

    #[test]
    fn the_new_bundle_takes_the_old_ones_place() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("g-ssh.app");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("old"), "old").unwrap();
        let stage = dir.path().join(".g-ssh-update-abc");
        fs::create_dir(&stage).unwrap();
        let staged = stage.join("g-ssh.app");
        fs::create_dir(&staged).unwrap();
        fs::write(staged.join("new"), "new").unwrap();

        let trash = swap_in(&dest, &staged).unwrap().unwrap();

        assert_eq!(fs::read_to_string(dest.join("new")).unwrap(), "new");
        assert!(!dest.join("old").exists());
        assert_eq!(fs::read_to_string(trash.join("old")).unwrap(), "old");
        assert!(!staged.exists());
    }

    #[test]
    fn a_failed_swap_puts_the_old_bundle_back() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("g-ssh.app");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("old"), "old").unwrap();
        let staged = dir.path().join("missing.app");

        let error = swap_in(&dest, &staged).unwrap_err();

        assert!(matches!(error, UpdateError::Install(_)), "{error}");
        assert_eq!(fs::read_to_string(dest.join("old")).unwrap(), "old");
    }

    #[test]
    fn the_installer_only_replaces_this_app_with_the_staged_copy() {
        let dir = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let dest = dir.path().join("g-ssh.app");
        write_app(&dest);
        let stage = dir.path().join(".g-ssh-update-abc123");
        let staged = stage.join("g-ssh.app");
        write_app(&staged);
        let archive = cache.path().join("g-ssh-0.2.0.dmg");
        fs::write(&archive, b"dmg").unwrap();

        let request = SwapRequest {
            pid: 1,
            dest: dest.clone(),
            staged,
            stage_dir: stage,
            archive,
            token: "abc".into(),
        };
        assert!(swap_request_is_safe(&request, cache.path()).unwrap());

        let mut escaped = request;
        escaped.dest = dir.path().join("Notes.app");
        fs::create_dir(&escaped.dest).unwrap();
        assert!(!swap_request_is_safe(&escaped, cache.path()).unwrap());

        let mut outside = SwapRequest {
            pid: 1,
            dest,
            staged: dir.path().join("g-ssh.app"),
            stage_dir: dir.path().join(".g-ssh-update-abc123"),
            archive: cache.path().join("../g-ssh-0.2.0.dmg"),
            token: "abc".into(),
        };
        // The archive path is not the one just built. Rebuild a request whose
        // archive leaves the cache by a parent segment.
        outside.archive = cache.path().join("g-ssh-0.2.0.dmg");
        outside.staged = outside.stage_dir.join("g-ssh.app");
        assert!(is_absolute_normal(&outside.dest));
        let sneaky = cache.path().join("..").join("g-ssh-0.2.0.dmg");
        outside.archive = sneaky;
        assert!(
            !is_absolute_normal(&outside.archive)
                || !archive_is_safe(&outside.archive, cache.path())
        );
    }

    #[test]
    fn leftover_names_are_only_ours() {
        assert!(is_leftover_name(".g-ssh-update-abc123"));
        assert!(is_leftover_name(".g-ssh-old-abc123"));
        assert!(is_leftover_name("mount-abc123"));
        assert!(!is_leftover_name(".g-ssh-update-"));
        assert!(!is_leftover_name("g-ssh.app"));
        assert!(!is_leftover_name(".g-ssh-update-../x"));
    }
}
