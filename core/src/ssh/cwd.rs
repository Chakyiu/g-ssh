//! The folder a shell is in.
//!
//! Shells that integrate with the terminal report it (OSC 7, iTerm's
//! `CurrentDir`, VS Code's `Cwd`, ConEmu's `9;9`). A shell on this computer
//! can also be read from the operating system, which still works when the
//! shell never reports anything. An SSH shell that has not reported a folder
//! is asked with [`super::shell::directory_probe_input`].

use std::sync::Arc;

#[cfg(unix)]
use portable_pty::MasterPty;

/// Remembers directory reports as terminal output arrives. A report can be
/// split across reads, so the bytes are scanned as a stream.
#[derive(Default)]
pub(crate) struct DirectoryReports {
    scan: Scan,
    buf: Vec<u8>,
    path: Option<String>,
    /// How many directory reports have arrived. A report from login can still
    /// name the home directory after the user has `cd`'d, so a request for the
    /// live folder ignores anything from before it started.
    generation: u64,
    watch: Option<PwdWatch>,
}

struct PwdWatch {
    started: u64,
    output: Vec<u8>,
}

#[derive(Default)]
enum Scan {
    #[default]
    Ground,
    Esc,
    Osc,
    /// Saw ESC inside an OSC, waiting to see if it is the ST terminator.
    St,
}

const MAX_OSC: usize = 4096;
const MAX_PWD_WATCH: usize = 8 * 1024;

impl DirectoryReports {
    pub(crate) fn feed(&mut self, bytes: &[u8]) {
        if let Some(watch) = &mut self.watch {
            let room = MAX_PWD_WATCH.saturating_sub(watch.output.len());
            let take = bytes.len().min(room);
            watch.output.extend_from_slice(&bytes[..take]);
        }
        for &byte in bytes {
            self.byte(byte);
        }
    }

    pub(crate) fn path(&self) -> Option<String> {
        self.path.clone()
    }

    /// Start keeping output so the next `pwd` can be read back. Output from
    /// before this call is not part of the answer.
    pub(crate) fn begin_pwd_watch(&mut self) {
        self.watch = Some(PwdWatch {
            started: self.generation,
            output: Vec::new(),
        });
    }

    /// The folder printed by `pwd`, or a directory report that arrived after
    /// [`Self::begin_pwd_watch`]. `None` until one of those shows up.
    pub(crate) fn fresh_directory(&self) -> Option<String> {
        let watch = self.watch.as_ref()?;
        if let Some(path) = path_from_pwd_output(&watch.output) {
            return Some(path);
        }
        if self.generation > watch.started {
            return self.path.clone();
        }
        None
    }

    fn byte(&mut self, byte: u8) {
        match self.scan {
            Scan::Ground => {
                if byte == 0x1b {
                    self.scan = Scan::Esc;
                }
            }
            Scan::Esc => {
                if byte == b']' {
                    self.buf.clear();
                    self.scan = Scan::Osc;
                } else if byte == 0x1b {
                    self.scan = Scan::Esc;
                } else {
                    self.scan = Scan::Ground;
                }
            }
            Scan::Osc => {
                if byte == 0x07 {
                    self.finish();
                } else if byte == 0x1b {
                    self.scan = Scan::St;
                } else if self.buf.len() >= MAX_OSC {
                    self.buf.clear();
                    self.scan = Scan::Ground;
                } else {
                    self.buf.push(byte);
                }
            }
            Scan::St => {
                if byte == b'\\' {
                    self.finish();
                } else {
                    self.buf.clear();
                    self.scan = if byte == 0x1b {
                        Scan::Esc
                    } else {
                        Scan::Ground
                    };
                }
            }
        }
    }

    fn finish(&mut self) {
        let payload = String::from_utf8_lossy(&self.buf);
        if let Some(path) = directory_from_osc(&payload) {
            self.path = Some(path);
            self.generation = self.generation.wrapping_add(1);
        }
        self.buf.clear();
        self.scan = Scan::Ground;
    }
}

/// The directory named by one OSC payload, without the terminator.
/// `None` when the sequence is some other report.
pub(crate) fn directory_from_osc(payload: &str) -> Option<String> {
    let payload = payload.trim();
    if let Some(rest) = payload.strip_prefix("1337;") {
        let rest = rest.strip_prefix("CurrentDir=")?;
        return clean_directory(rest);
    }
    if let Some(rest) = payload.strip_prefix("633;") {
        let rest = rest.strip_prefix("P;")?;
        let rest = rest.strip_prefix("Cwd=")?;
        return clean_directory(rest);
    }
    if let Some(rest) = payload.strip_prefix("9;9;") {
        let rest = rest.trim().trim_matches('"');
        return clean_directory(rest);
    }
    if let Some(rest) = payload.strip_prefix("7;") {
        return directory_from_osc7(rest);
    }
    None
}

fn directory_from_osc7(value: &str) -> Option<String> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix("file://") {
        // `file://host/path`. The path starts at the slash after the host,
        // and the host may be empty (`file:///path`).
        let slash = rest.find('/')?;
        let path = percent_decode(&rest[slash..])?;
        return clean_directory(&path);
    }
    clean_directory(value)
}

/// A folder path from a shell or the operating system, in the form SFTP and
/// the local file manager both accept. `None` when it is empty or contains a
/// control character.
pub(crate) fn clean_directory(path: &str) -> Option<String> {
    let path = path.trim().trim_matches('\0');
    if path.is_empty() || path.chars().any(char::is_control) {
        return None;
    }
    let path = path.replace('\\', "/");
    let path = strip_slash_before_drive(&path);
    let path = trim_dir_slash(&path);
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// `/C:/Users` is a file URL's path. SFTP and Windows want `C:/Users`.
fn strip_slash_before_drive(path: &str) -> String {
    let bytes = path.as_bytes();
    let is_drive =
        bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':';
    let is_folder = bytes.len() == 3 || bytes.get(3) == Some(&b'/');
    if is_drive && is_folder {
        path[1..].to_string()
    } else {
        path.to_string()
    }
}

fn trim_dir_slash(path: &str) -> String {
    if path == "/" || is_drive_root(path) {
        return path.to_string();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

fn is_drive_root(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The path `pwd` printed into `bytes`. The echoed command and the next
/// prompt are ignored. A line counts only once a newline has followed it, so
/// a path that is still arriving is not taken early.
pub(crate) fn path_from_pwd_output(bytes: &[u8]) -> Option<String> {
    let text = strip_terminal_controls(bytes);
    for line in text.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break;
        }
        if let Some(path) = pwd_line(line.trim()) {
            return Some(path);
        }
    }
    None
}

fn pwd_line(line: &str) -> Option<String> {
    if line.is_empty() || line.contains('@') || line.eq_ignore_ascii_case("pwd") {
        return None;
    }
    // The prompt and the echoed command share the line (`C:\Users\me>cd`).
    // A prompt also ends with `$`, `#` or `%`. The printed folder is neither.
    if line.contains('>') || line.ends_with(['$', '#', '%']) {
        return None;
    }
    let path = clean_directory(line)?;
    let bytes = path.as_bytes();
    let is_drive =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/';
    (path.starts_with('/') || is_drive).then_some(path)
}

/// Drop escape sequences so a prompt's title report is not read as a line.
fn strip_terminal_controls(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0x1b {
            if bytes[index] != b'\r' && bytes[index] != 0x7f {
                out.push(bytes[index]);
            }
            index += 1;
            continue;
        }
        index += 1;
        if index >= bytes.len() {
            break;
        }
        match bytes[index] {
            b']' => {
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == 0x07 {
                        index += 1;
                        break;
                    }
                    if bytes[index] == 0x1b && index + 1 < bytes.len() && bytes[index + 1] == b'\\'
                    {
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            }
            b'[' => {
                index += 1;
                while index < bytes.len() {
                    let byte = bytes[index];
                    index += 1;
                    if (b'@'..=b'~').contains(&byte) {
                        break;
                    }
                }
            }
            _ => index += 1,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_shell_name(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let base = base.trim().trim_start_matches('-');
    let base = base
        .strip_suffix(".exe")
        .or_else(|| base.strip_suffix(".EXE"))
        .unwrap_or(base);
    matches!(
        base.to_ascii_lowercase().as_str(),
        "sh" | "bash"
            | "zsh"
            | "fish"
            | "ksh"
            | "csh"
            | "tcsh"
            | "dash"
            | "ash"
            | "pwsh"
            | "powershell"
            | "cmd"
            | "nu"
            | "elvish"
            | "xonsh"
    )
}

/// The folder of the shell `shell_pid` started, or of a shell it has since
/// started in the foreground. A program the shell is running does not count:
/// `pwd` is the shell's folder, including while vim is open.
pub(crate) struct NativeDirectory {
    shell_pid: u32,
    #[cfg(unix)]
    pty: Option<std::os::fd::OwnedFd>,
}

impl NativeDirectory {
    #[cfg(unix)]
    pub(crate) fn from_pty(master: &dyn MasterPty, shell_pid: u32) -> Self {
        Self {
            shell_pid,
            pty: duplicate_pty(master),
        }
    }

    #[cfg(windows)]
    pub(crate) fn from_pid(shell_pid: u32) -> Self {
        Self { shell_pid }
    }

    pub(crate) fn query(&self) -> Option<String> {
        self.shell_directory()
            .and_then(|path| clean_directory(&path))
    }

    pub(crate) fn into_query(self) -> Arc<dyn Fn() -> Option<String> + Send + Sync> {
        Arc::new(move || self.query())
    }
}

#[cfg(unix)]
fn duplicate_pty(master: &dyn MasterPty) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let raw = master.as_raw_fd()?;
    // SAFETY: `raw` is the live PTY master. F_DUPFD_CLOEXEC returns a new fd
    // that we own, or -1.
    let duped = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
    if duped < 0 {
        return None;
    }
    // SAFETY: `duped` is a fresh fd and nothing else closes it.
    Some(unsafe { OwnedFd::from_raw_fd(duped) })
}

#[cfg(unix)]
fn foreground_pid(pty: &std::os::fd::OwnedFd) -> Option<u32> {
    use std::os::fd::AsRawFd;
    // SAFETY: the fd is a PTY master we own. tcgetpgrp only reads the
    // foreground group; -1 means the PTY has no foreground process.
    let pid = unsafe { libc::tcgetpgrp(pty.as_raw_fd()) };
    (pid > 0).then_some(pid as u32)
}

#[cfg(unix)]
impl NativeDirectory {
    fn shell_directory(&self) -> Option<String> {
        let foreground = self.pty.as_ref().and_then(foreground_pid);
        let mut pid = foreground.unwrap_or(self.shell_pid);
        for _ in 0..16 {
            if is_shell_process(pid) {
                if let Some(path) = process_cwd(pid) {
                    return Some(path);
                }
            }
            if pid == self.shell_pid {
                break;
            }
            match parent_pid(pid) {
                Some(parent) if parent > 1 && parent != pid => pid = parent,
                _ => break,
            }
        }
        process_cwd(self.shell_pid)
    }
}

#[cfg(target_os = "linux")]
fn process_cwd(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

#[cfg(target_os = "linux")]
fn parent_pid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` is in parentheses and may itself contain spaces and parentheses.
    let rest = stat.rsplit_once(')')?.1.trim_start();
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?;
    fields.next()?.parse().ok()
}

#[cfg(target_os = "linux")]
fn is_shell_process(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .is_some_and(|name| is_shell_name(name.trim()))
}

#[cfg(target_os = "macos")]
fn process_cwd(pid: u32) -> Option<String> {
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
    // SAFETY: `info` is a zeroed proc_vnodepathinfo and `size` is its size.
    // proc_pidinfo writes that many bytes, or returns 0 when the pid is gone.
    let wrote = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            &mut info as *mut libc::proc_vnodepathinfo as *mut libc::c_void,
            size,
        )
    };
    if wrote <= 0 {
        return None;
    }
    c_string_bytes(&info.pvi_cdir.vip_path)
}

#[cfg(target_os = "macos")]
fn parent_pid(pid: u32) -> Option<u32> {
    let info = bsd_info(pid)?;
    let parent = info.pbi_ppid;
    (parent > 0).then_some(parent)
}

#[cfg(target_os = "macos")]
fn is_shell_process(pid: u32) -> bool {
    let Some(info) = bsd_info(pid) else {
        return false;
    };
    let name = c_string(&info.pbi_name);
    let name = if name.is_empty() {
        c_string(&info.pbi_comm)
    } else {
        name
    };
    is_shell_name(&name)
}

#[cfg(target_os = "macos")]
fn bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `info` is a zeroed proc_bsdinfo and `size` is its size.
    let wrote = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
            size,
        )
    };
    (wrote > 0).then_some(info)
}

#[cfg(target_os = "macos")]
fn c_string(bytes: &[libc::c_char]) -> String {
    c_string_bytes(bytes).unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn c_string_bytes<T>(bytes: &[T]) -> Option<String> {
    let len = std::mem::size_of_val(bytes);
    // SAFETY: `bytes` is a contiguous C string buffer of `len` bytes. The
    // slice ends at the first NUL, or at the end when the buffer is full.
    let flat = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u8, len) };
    let end = flat
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(flat.len());
    let text = String::from_utf8_lossy(&flat[..end]).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn process_cwd(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn parent_pid(_pid: u32) -> Option<u32> {
    None
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn is_shell_process(_pid: u32) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
impl NativeDirectory {
    fn shell_directory(&self) -> Option<String> {
        None
    }
}

#[cfg(windows)]
impl NativeDirectory {
    fn shell_directory(&self) -> Option<String> {
        let pid = windows::foreground_shell(self.shell_pid);
        windows::process_cwd(pid)
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;

    pub(super) fn foreground_shell(root: u32) -> u32 {
        let entries = process_entries();
        let mut pid = root;
        for _ in 0..8 {
            let mut shells = entries.iter().filter_map(|(child, parent, name)| {
                (*parent == pid && super::is_shell_name(name)).then_some(*child)
            });
            match (shells.next(), shells.next()) {
                (Some(only), None) => pid = only,
                _ => break,
            }
        }
        pid
    }

    pub(super) fn process_cwd(pid: u32) -> Option<String> {
        // The offsets below are the 64-bit PEB. A 32-bit build falls back to
        // asking the shell.
        if cfg!(not(target_pointer_width = "64")) {
            return None;
        }
        let process = open_process(pid)?;
        let basic = process_basic_information(process.0)?;
        if basic.peb == 0 {
            return None;
        }
        // The 64-bit PEB's ProcessParameters pointer. A 32-bit shell on
        // 64-bit Windows still has this native PEB, and its parameters
        // carry the same current directory.
        let mut params = 0u64;
        if !read_memory(process.0, basic.peb + 0x20, &mut params) || params == 0 {
            return None;
        }
        let mut dir = RemoteUnicodeString::default();
        // RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath.
        if !read_memory(process.0, params + 0x38, &mut dir) || dir.length == 0 || dir.buffer == 0 {
            return None;
        }
        if dir.length > 32 * 1024 || dir.length % 2 != 0 {
            return None;
        }
        let mut bytes = vec![0u8; dir.length as usize];
        if !read_buf(process.0, dir.buffer, &mut bytes) {
            return None;
        }
        let wide: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Some(String::from_utf16_lossy(&wide))
    }

    #[repr(C)]
    struct ProcessBasicInformation {
        reserved1: usize,
        peb: u64,
        reserved2: [usize; 2],
        pid: usize,
        reserved3: usize,
    }

    #[repr(C)]
    #[derive(Default)]
    struct RemoteUnicodeString {
        length: u16,
        _max: u16,
        _pad: u32,
        buffer: u64,
    }

    struct ProcessHandle(*mut c_void);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn open_process(pid: u32) -> Option<ProcessHandle> {
        const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
        const PROCESS_VM_READ: u32 = 0x0010;
        // SAFETY: a null or invalid handle is rejected below and never closed
        // twice. The rights only let us read this process's memory.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle.is_null() || handle == (-1isize as *mut c_void) {
            None
        } else {
            Some(ProcessHandle(handle))
        }
    }

    fn process_basic_information(process: *mut c_void) -> Option<ProcessBasicInformation> {
        let mut info: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        // SAFETY: `info` is zeroed and its size is passed through. Class 0 is
        // ProcessBasicInformation. A non-zero status means the buffer is unused.
        let status = unsafe {
            NtQueryInformationProcess(
                process,
                0,
                &mut info as *mut ProcessBasicInformation as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut returned,
            )
        };
        (status == 0).then_some(info)
    }

    fn read_memory<T>(process: *mut c_void, address: u64, out: &mut T) -> bool {
        // SAFETY: `out` is a valid object. The slice covers exactly its bytes
        // and does not outlive this call.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(out as *mut T as *mut u8, std::mem::size_of::<T>())
        };
        read_buf(process, address, bytes)
    }

    fn read_buf(process: *mut c_void, address: u64, out: &mut [u8]) -> bool {
        if address == 0 || out.is_empty() {
            return false;
        }
        let mut read = 0usize;
        // SAFETY: `out` is writable for its length. `address` is a pointer in
        // `process`. A short read is treated as failure.
        let ok = unsafe {
            ReadProcessMemory(
                process,
                address as *const c_void,
                out.as_mut_ptr() as *mut c_void,
                out.len(),
                &mut read,
            )
        };
        ok != 0 && read == out.len()
    }

    fn process_entries() -> Vec<(u32, u32, String)> {
        const SNAPSHOT: u32 = 0x0000_0002;
        // SAFETY: a failed snapshot is the invalid handle, which we do not walk.
        let snap = unsafe { CreateToolhelp32Snapshot(SNAPSHOT, 0) };
        if snap.is_null() || snap == (-1isize as *mut c_void) {
            return Vec::new();
        }
        let _close = ProcessHandle(snap);
        let mut entry: ProcessEntry32W = unsafe { std::mem::zeroed() };
        entry.size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut out = Vec::new();
        // SAFETY: `entry.size` is set, which Process32FirstW requires.
        if unsafe { Process32FirstW(snap, &mut entry) } == 0 {
            return out;
        }
        loop {
            out.push((entry.pid, entry.parent_pid, exe_name(&entry.exe)));
            entry.size = std::mem::size_of::<ProcessEntry32W>() as u32;
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
        out
    }

    fn exe_name(wide: &[u16]) -> String {
        let end = wide
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(wide.len());
        String::from_utf16_lossy(&wide[..end])
    }

    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        _cnt_usage: u32,
        pid: u32,
        _heap: usize,
        _module: u32,
        _threads: u32,
        parent_pid: u32,
        _pri: i32,
        _flags: u32,
        exe: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn ReadProcessMemory(
            process: *mut c_void,
            address: *const c_void,
            buffer: *mut c_void,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
        fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process: *mut c_void,
            class: u32,
            info: *mut c_void,
            len: u32,
            returned: *mut u32,
        ) -> i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osc_reports_decode_to_a_folder() {
        assert_eq!(
            directory_from_osc("7;file://host.local/var/log"),
            Some("/var/log".to_string())
        );
        assert_eq!(
            directory_from_osc("7;file:///home/me/my%20app"),
            Some("/home/me/my app".to_string())
        );
        assert_eq!(
            directory_from_osc("7;file://host/C:/Users/me"),
            Some("C:/Users/me".to_string())
        );
        assert_eq!(
            directory_from_osc("7;file://host/C%3A/Users/me"),
            Some("C:/Users/me".to_string())
        );
        assert_eq!(
            directory_from_osc("1337;CurrentDir=/tmp/a b"),
            Some("/tmp/a b".to_string())
        );
        assert_eq!(
            directory_from_osc(r"1337;CurrentDir=C:\Users\me"),
            Some("C:/Users/me".to_string())
        );
        assert_eq!(
            directory_from_osc("633;P;Cwd=/srv/app"),
            Some("/srv/app".to_string())
        );
        assert_eq!(
            directory_from_osc(r#"9;9;"D:\work""#),
            Some("D:/work".to_string())
        );
        assert_eq!(
            directory_from_osc("7;file://host/var/log/"),
            Some("/var/log".to_string())
        );
        assert_eq!(directory_from_osc("0;title"), None);
        assert_eq!(directory_from_osc("7;file://host/var/\nbad"), None);
    }

    #[test]
    fn a_split_report_is_kept() {
        let mut reports = DirectoryReports::default();
        reports.feed(b"ready\x1b]7;file://h");
        assert_eq!(reports.path(), None);
        reports.feed(b"ost/tmp/work\x07next");
        assert_eq!(reports.path().as_deref(), Some("/tmp/work"));
        reports.feed(b"\x1b]1337;CurrentDir=/var\x1b\\");
        assert_eq!(reports.path().as_deref(), Some("/var"));
    }

    #[test]
    fn drive_roots_keep_their_slash() {
        assert_eq!(clean_directory("C:\\"), Some("C:/".to_string()));
        assert_eq!(clean_directory("/"), Some("/".to_string()));
        assert_eq!(clean_directory("/var/log/"), Some("/var/log".to_string()));
    }

    #[test]
    fn pwd_output_is_the_live_folder_not_the_old_report_or_the_prompt() {
        let mut reports = DirectoryReports::default();
        reports.feed(b"\x1b]7;file://host/root\x07");
        assert_eq!(reports.path().as_deref(), Some("/root"));
        reports.begin_pwd_watch();
        assert_eq!(reports.fresh_directory(), None);
        // The title report and the prompt both name /etc. Neither is `pwd`.
        reports.feed(b"pwd\r\n/et");
        assert_eq!(reports.fresh_directory(), None);
        reports.feed(b"c\r\n\x1b]0;root@k3s: /etc\x07root@k3s:/etc# ");
        assert_eq!(reports.fresh_directory().as_deref(), Some("/etc"));
    }

    #[test]
    fn cmd_prints_the_folder_on_its_own_line() {
        let raw = b"C:\\Users\\lcyha\\Downloads>cmd /c cd\r\nC:\\Users\\lcyha\\Downloads\r\nC:\\Users\\lcyha\\Downloads>";
        assert_eq!(
            path_from_pwd_output(raw).as_deref(),
            Some("C:/Users/lcyha/Downloads")
        );
    }

    #[test]
    fn a_directory_report_after_the_watch_starts_is_fresh() {
        let mut reports = DirectoryReports::default();
        reports.feed(b"\x1b]7;file://host/root\x07");
        reports.begin_pwd_watch();
        reports.feed(b"\x1b]7;file://host/etc\x07");
        assert_eq!(reports.fresh_directory().as_deref(), Some("/etc"));
    }

    #[test]
    fn shell_names_ignore_the_login_dash_and_exe() {
        assert!(is_shell_name("-zsh"));
        assert!(is_shell_name("powershell.exe"));
        assert!(is_shell_name("/bin/bash"));
        assert!(!is_shell_name("vim"));
        assert!(!is_shell_name("conhost.exe"));
    }
}
