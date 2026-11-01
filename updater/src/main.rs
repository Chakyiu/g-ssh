//! Replaces the installed g-ssh after that process has quit.
//!
//! The app cannot replace its own exe while Windows still has that file
//! open. This program is a different file, so it can wait for g-ssh to exit
//! and then copy the new exe into place.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

const QUIT_WAIT: Duration = Duration::from_secs(60);
const REPLACE_TRIES: u32 = 40;

fn main() {
    let mut args = std::env::args_os();
    let _argv0 = args.next();
    let code = match run(args) {
        Ok(()) => 0,
        Err(error) => {
            log_line(None, &error);
            1
        }
    };
    std::process::exit(code);
}

fn run(args: impl Iterator<Item = OsString>) -> Result<(), String> {
    let job = Job::parse(args)?;
    log_line(
        job.log.as_deref(),
        &format!("waiting for {} to quit", job.pid),
    );
    if !wait_for_exit(job.pid) {
        return Err("g-ssh did not quit, so the update was not applied".into());
    }
    // The process can be gone before Windows releases the exe.
    #[cfg(windows)]
    std::thread::sleep(Duration::from_millis(500));
    let trash = install_payload(&job.dest, &job.source)?;
    let launch_result = launch(&job.dest.join("g-ssh.exe"));
    let mut leftovers = vec![job.source];
    if let Some(archive) = &job.archive {
        leftovers.extend(clear_update_zips(archive));
    }
    leftovers.extend(trash);
    schedule_delete(&leftovers);
    launch_result
}

/// Remove `.zip` builds from the updates folder. The archive just applied is
/// one of them. A zip that is still locked is returned so the caller can
/// retry. A zip outside that folder is removed on its own.
fn clear_update_zips(archive: &Path) -> Vec<PathBuf> {
    let Some(folder) = archive.parent() else {
        return locked(archive);
    };
    if folder.file_name().and_then(|name| name.to_str()) != Some("updates") {
        return locked(archive);
    }
    let Ok(entries) = fs::read_dir(folder) else {
        return locked(archive);
    };
    let mut pending = Vec::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        if !name.to_ascii_lowercase().ends_with(".zip") {
            continue;
        }
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let path = entry.path();
        if fs::remove_file(&path).is_err() && path.exists() {
            pending.push(path);
        }
    }
    pending
}

fn locked(path: &Path) -> Vec<PathBuf> {
    if fs::remove_file(path).is_err() && path.exists() {
        vec![path.to_path_buf()]
    } else {
        Vec::new()
    }
}

struct Job {
    pid: u32,
    dest: PathBuf,
    source: PathBuf,
    archive: Option<PathBuf>,
    log: Option<PathBuf>,
}

impl Job {
    fn parse(args: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let mut pid = None;
        let mut dest = None;
        let mut source = None;
        let mut archive = None;
        let mut log = None;
        let mut args = args;
        while let Some(flag) = args.next() {
            let flag = flag
                .to_str()
                .ok_or_else(|| "unknown argument".to_string())?;
            let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag {
                "--pid" => {
                    pid = Some(
                        value
                            .to_str()
                            .and_then(|text| text.parse().ok())
                            .filter(|pid| *pid > 0)
                            .ok_or_else(|| "--pid needs a process id".to_string())?,
                    );
                }
                "--dest" => dest = Some(PathBuf::from(value)),
                "--source" => source = Some(PathBuf::from(value)),
                "--archive" => archive = Some(PathBuf::from(value)),
                "--log" => log = Some(PathBuf::from(value)),
                other => return Err(format!("unknown argument {other}")),
            }
        }
        let job = Self {
            pid: pid.ok_or_else(|| "--pid is required".to_string())?,
            dest: dest.ok_or_else(|| "--dest is required".to_string())?,
            source: source.ok_or_else(|| "--source is required".to_string())?,
            archive,
            log,
        };
        job.check()?;
        Ok(job)
    }

    fn check(&self) -> Result<(), String> {
        if !is_absolute_normal(&self.dest) || !is_absolute_normal(&self.source) {
            return Err("refused a path that is not a normal absolute path".into());
        }
        if !is_stage_dir(&self.source) {
            return Err("refused a source folder that is not an update folder".into());
        }
        if !same_parent(&self.source, &self.dest) {
            return Err("refused an update folder that is not next to g-ssh".into());
        }
        if !is_real_file(&self.source.join("g-ssh.exe")) {
            return Err("the update does not contain g-ssh.exe".into());
        }
        if !is_real_file(&self.dest.join("g-ssh.exe")) {
            return Err("g-ssh.exe is not in the install folder".into());
        }
        if let Some(archive) = &self.archive {
            if !is_absolute_normal(archive) {
                return Err("refused a path that is not a normal absolute path".into());
            }
            let name = archive
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if !name.ends_with(".zip") || !is_real_file(archive) {
                return Err("refused an archive that is not the downloaded zip".into());
            }
        }
        Ok(())
    }
}

fn is_absolute_normal(path: &Path) -> bool {
    path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir))
}

fn is_stage_dir(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(rest) = name.strip_prefix(".g-ssh-update-") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit())
}

fn same_parent(source: &Path, dest: &Path) -> bool {
    let Some(parent) = source.parent() else {
        return false;
    };
    match (parent.canonicalize(), dest.canonicalize()) {
        (Ok(parent), Ok(dest)) => parent == dest,
        _ => parent == dest,
    }
}

fn is_real_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

/// Copy `g-ssh.exe` and `update.exe` from `source` onto `dest`.
/// Old files that could not be deleted are returned so the caller can retry.
fn install_payload(dest: &Path, source: &Path) -> Result<Vec<PathBuf>, String> {
    let mut names = vec!["g-ssh.exe"];
    if is_real_file(&source.join("update.exe")) {
        names.push("update.exe");
    }
    let mut trash = Vec::new();
    for name in names {
        replace_with_retry(&source.join(name), &dest.join(name), &mut trash)?;
    }
    Ok(trash)
}

fn replace_with_retry(from: &Path, to: &Path, trash: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut last = String::from("could not copy the new file");
    for attempt in 0..REPLACE_TRIES {
        match replace_once(from, to) {
            Ok(left) => {
                if let Some(left) = left {
                    trash.push(left);
                }
                return Ok(());
            }
            Err(error) => {
                last = error;
                if attempt + 1 != REPLACE_TRIES {
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }
    Err(last)
}

/// Move `to` aside, copy `from` onto that path, and delete the old file.
/// The old path is returned when it is still there.
fn replace_once(from: &Path, to: &Path) -> Result<Option<PathBuf>, String> {
    if !is_real_file(from) {
        return Err(format!("missing {}", from.display()));
    }
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let trash = to.with_file_name(format!(".g-ssh-old-{stamp}"));
    let had_dest = to.exists();
    if had_dest {
        fs::rename(to, &trash)
            .map_err(|error| format!("could not move {} aside: {error}", to.display()))?;
    }
    if let Err(error) = fs::copy(from, to) {
        if had_dest {
            let _ = fs::rename(&trash, to);
        }
        return Err(format!("could not copy {}: {error}", to.display()));
    }
    if fs::remove_file(&trash).is_err() && trash.exists() {
        return Ok(Some(trash));
    }
    Ok(None)
}

fn launch(exe: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        let mut cmd = Command::new(exe);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(
                DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,
            );
        if cmd.spawn().is_err() {
            cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
            cmd.spawn()
                .map_err(|error| format!("could not reopen g-ssh: {error}"))?;
        }
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        let _ = exe;
        Ok(())
    }
}

fn wait_for_exit(pid: u32) -> bool {
    let started = SystemTime::now();
    while started.elapsed().unwrap_or(QUIT_WAIT) < QUIT_WAIT {
        if !process_exists(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    !process_exists(pid)
}

fn process_exists(pid: u32) -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
        }
        if pid == 0 || pid > i32::MAX as u32 {
            return false;
        }
        let rc = unsafe { kill(pid as i32, 0) };
        if rc == 0 {
            return true;
        }
        // EPERM: the process exists, and this user cannot signal it.
        return std::io::Error::last_os_error().raw_os_error() == Some(1);
    }
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
            fn CloseHandle(handle: isize) -> i32;
            fn GetExitCodeProcess(handle: isize, code: *mut u32) -> i32;
            fn GetLastError() -> u32;
        }
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
        const ERROR_ACCESS_DENIED: u32 = 5;
        const STILL_ACTIVE: u32 = 259;
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle == 0 {
                return GetLastError() == ERROR_ACCESS_DENIED;
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(handle, &mut code);
            CloseHandle(handle);
            if ok == 0 {
                return true;
            }
            code == STILL_ACTIVE
        }
    }
}

fn schedule_delete(paths: &[PathBuf]) {
    let pending: Vec<&Path> = paths
        .iter()
        .filter(|path| path.exists())
        .map(PathBuf::as_path)
        .collect();
    if pending.is_empty() {
        return;
    }
    #[cfg(windows)]
    {
        let mut cmd = Command::new("powershell.exe");
        let mut script = String::from("Start-Sleep -Seconds 1; foreach ($p in @(");
        for (ix, path) in pending.iter().enumerate() {
            if ix > 0 {
                script.push(',');
            }
            let text = path.to_string_lossy().replace('\'', "''");
            script.push('\'');
            script.push_str(&text);
            script.push('\'');
        }
        script.push_str(
            ")) { if ($p -and (Test-Path -LiteralPath $p)) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue } }",
        );
        cmd.args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        let _ = cmd.spawn();
    }
    #[cfg(not(windows))]
    {
        let _ = pending;
    }
}

fn log_line(path: Option<&Path>, text: &str) {
    let Some(path) = path else {
        return;
    };
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let _ = writeln!(file, "{stamp} {text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(dir: &Path) -> (PathBuf, PathBuf) {
        let dest = dir.join("install");
        let source = dest.join(".g-ssh-update-abc");
        fs::create_dir_all(&source).unwrap();
        fs::write(dest.join("g-ssh.exe"), b"old-app").unwrap();
        fs::write(dest.join("update.exe"), b"old-update").unwrap();
        fs::write(source.join("g-ssh.exe"), b"new-app").unwrap();
        fs::write(source.join("update.exe"), b"new-update").unwrap();
        (dest, source)
    }

    #[test]
    fn the_new_files_replace_the_installed_ones() {
        let dir = tempfile_dir();
        let (dest, source) = stage(&dir);
        let trash = install_payload(&dest, &source).unwrap();
        assert!(trash.is_empty());
        assert_eq!(fs::read(dest.join("g-ssh.exe")).unwrap(), b"new-app");
        assert_eq!(fs::read(dest.join("update.exe")).unwrap(), b"new-update");
        assert_eq!(fs::read(source.join("g-ssh.exe")).unwrap(), b"new-app");
    }

    #[test]
    fn zips_in_the_updates_folder_are_removed_after_an_update() {
        let dir = tempfile_dir();
        let updates = dir.join("g-ssh").join("updates");
        fs::create_dir_all(&updates).unwrap();
        let current = updates.join("g-ssh-0.2.6-windows-x86_64.zip");
        let old = updates.join("g-ssh-0.2.5-windows-x86_64.zip");
        let log = updates.join("swap.log");
        fs::write(&current, b"new").unwrap();
        fs::write(&old, b"old").unwrap();
        fs::write(&log, b"log").unwrap();

        let pending = clear_update_zips(&current);
        assert!(pending.is_empty());
        assert!(!current.exists());
        assert!(!old.exists());
        assert_eq!(fs::read(&log).unwrap(), b"log");

        let other = dir.join("notes.zip");
        let sibling = dir.join("taxes.zip");
        fs::write(&other, b"a").unwrap();
        fs::write(&sibling, b"b").unwrap();
        let pending = clear_update_zips(&other);
        assert!(pending.is_empty());
        assert!(!other.exists());
        assert_eq!(fs::read(&sibling).unwrap(), b"b");
    }

    #[test]
    fn a_missing_updater_leaves_the_installed_one() {
        let dir = tempfile_dir();
        let (dest, source) = stage(&dir);
        fs::remove_file(source.join("update.exe")).unwrap();
        install_payload(&dest, &source).unwrap();
        assert_eq!(fs::read(dest.join("g-ssh.exe")).unwrap(), b"new-app");
        assert_eq!(fs::read(dest.join("update.exe")).unwrap(), b"old-update");
    }

    #[test]
    fn a_job_has_to_name_the_install_folder_and_the_update_folder() {
        let dir = tempfile_dir();
        let (dest, source) = stage(&dir);
        let archive = dir.join("g-ssh.zip");
        fs::write(&archive, b"zip").unwrap();
        let args = [
            OsString::from("--pid"),
            OsString::from("12"),
            OsString::from("--dest"),
            dest.as_os_str().to_os_string(),
            OsString::from("--source"),
            source.as_os_str().to_os_string(),
            OsString::from("--archive"),
            archive.as_os_str().to_os_string(),
        ];
        let job = Job::parse(args.into_iter()).unwrap();
        assert_eq!(job.pid, 12);
        assert_eq!(job.dest, dest);

        let outside = dir.join("elsewhere");
        fs::create_dir_all(outside.join(".g-ssh-update-abc")).unwrap();
        let bad = [
            OsString::from("--pid"),
            OsString::from("12"),
            OsString::from("--dest"),
            dest.as_os_str().to_os_string(),
            OsString::from("--source"),
            outside.join(".g-ssh-update-abc").as_os_str().to_os_string(),
        ];
        assert!(Job::parse(bad.into_iter()).is_err());
    }

    fn tempfile_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "g-ssh-update-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |since| since.as_nanos())
        ));
        fs::create_dir(&path).unwrap();
        path
    }
}
