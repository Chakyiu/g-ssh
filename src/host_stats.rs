//! What the server panel reads from a host: a short script run over an exec
//! channel, and the parsing of what it prints. The numbers come from `/proc`,
//! so the live part needs a Linux server.

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine as _;

/// Printed once per panel: what the machine is.
const INFO_SCRIPT: &str = r#"export LC_ALL=C
echo @host; hostname 2>/dev/null || cat /proc/sys/kernel/hostname
echo @os; (. /etc/os-release && echo "$PRETTY_NAME") 2>/dev/null
echo @kernel; uname -sr
echo @arch; uname -m
echo @cpu; grep -m 1 'model name' /proc/cpuinfo 2>/dev/null
echo @cores; getconf _NPROCESSORS_ONLN 2>/dev/null
echo @ip; hostname -I 2>/dev/null || ip -o addr show scope global 2>/dev/null
"#;

/// Printed on every tick.
const SAMPLE_SCRIPT: &str = r#"export LC_ALL=C
echo @stat; cat /proc/stat
echo @mem; cat /proc/meminfo
echo @load; cat /proc/loadavg
echo @uptime; cat /proc/uptime
echo @net; cat /proc/net/dev
echo @df; df -kP
"#;

/// The scripts go as base64, so that the login shell (fish, csh) never
/// parses them: only `sh` does.
fn command_for(script: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(script);
    format!("echo {encoded} | base64 -d | sh 2>/dev/null")
}

pub fn info_command() -> String {
    command_for(INFO_SCRIPT)
}

pub fn sample_command() -> String {
    command_for(SAMPLE_SCRIPT)
}

/// Both in one round trip. Their section names differ, so each parser finds
/// its own part of the output.
pub fn info_and_sample_command() -> String {
    command_for(&format!("{INFO_SCRIPT}{SAMPLE_SCRIPT}"))
}

/// The output split at its `@name` lines.
fn sections(output: &str) -> HashMap<&str, Vec<&str>> {
    let mut sections: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut current = "";
    for line in output.lines() {
        if let Some(name) = line.strip_prefix('@') {
            current = name.trim();
            sections.entry(current).or_default();
            continue;
        }
        if !current.is_empty() {
            sections.entry(current).or_default().push(line);
        }
    }
    sections
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_name: Option<String>,
    pub kernel: String,
    pub arch: String,
    pub cpu_model: Option<String>,
    pub cpu_count: Option<usize>,
    /// IPv4 first.
    pub addresses: Vec<String>,
}

pub fn parse_info(output: &str) -> SystemInfo {
    let sections = sections(output);
    let first = |name: &str| -> Option<String> {
        sections
            .get(name)?
            .iter()
            .map(|line| line.trim())
            .find(|line| !line.is_empty())
            .map(str::to_string)
    };
    let cpu_model = first("cpu")
        .and_then(|line| {
            line.split_once(':')
                .map(|(_, model)| model.trim().to_string())
        })
        .filter(|model| !model.is_empty());
    let addresses = sections
        .get("ip")
        .map(|lines| parse_addresses(lines))
        .unwrap_or_default();
    SystemInfo {
        hostname: first("host").unwrap_or_default(),
        os_name: first("os"),
        kernel: first("kernel").unwrap_or_default(),
        arch: first("arch").unwrap_or_default(),
        cpu_model,
        cpu_count: first("cores").and_then(|count| count.parse().ok()),
        addresses,
    }
}

/// `hostname -I` prints the addresses on one line; `ip -o addr` prints one
/// interface per line with the address after "inet" or "inet6".
fn parse_addresses(lines: &[&str]) -> Vec<String> {
    let mut addresses: Vec<String> = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        let is_ip_output = words.iter().any(|word| *word == "inet" || *word == "inet6");
        if !is_ip_output {
            addresses.extend(words.iter().map(|word| word.to_string()));
            continue;
        }
        for pair in words.windows(2) {
            if pair[0] == "inet" || pair[0] == "inet6" {
                let address = pair[1].split('/').next().unwrap_or(pair[1]);
                addresses.push(address.to_string());
            }
        }
    }
    addresses.sort_by_key(|address| address.contains(':'));
    addresses.dedup();
    addresses
}

/// Jiffies summed over every CPU since boot.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CpuTimes {
    pub total: u64,
    pub idle: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Memory {
    pub total: u64,
    pub available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

impl Memory {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }

    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Disk {
    pub mount: String,
    pub size: u64,
    pub used: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Sample {
    pub cpu: CpuTimes,
    pub cpu_count: usize,
    pub memory: Memory,
    pub load: [f32; 3],
    pub uptime: Duration,
    /// Bytes received and sent since boot, all interfaces but loopback.
    pub net_rx: u64,
    pub net_tx: u64,
    pub disks: Vec<Disk>,
}

/// `None` when the host has no `/proc/stat`: not Linux.
pub fn parse_sample(output: &str) -> Option<Sample> {
    let sections = sections(output);
    let stat = sections.get("stat")?;
    let cpu = stat.iter().find_map(|line| parse_cpu_line(line))?;
    let cpu_count = stat
        .iter()
        .filter(|line| {
            line.strip_prefix("cpu")
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        })
        .count();
    let lines = |name: &str| sections.get(name).map(Vec::as_slice).unwrap_or_default();
    let (net_rx, net_tx) = parse_net(lines("net"));
    Some(Sample {
        cpu,
        cpu_count: cpu_count.max(1),
        memory: parse_memory(lines("mem")),
        load: parse_load(lines("load")),
        uptime: parse_uptime(lines("uptime")),
        net_rx,
        net_tx,
        disks: parse_disks(lines("df")),
    })
}

/// "cpu  user nice system idle iowait irq softirq steal guest guest_nice".
/// Guest time is already counted in user, so it is left out.
fn parse_cpu_line(line: &str) -> Option<CpuTimes> {
    let rest = line.strip_prefix("cpu ")?;
    let fields: Vec<u64> = rest
        .split_whitespace()
        .take(8)
        .map(|field| field.parse().unwrap_or(0))
        .collect();
    if fields.len() < 4 {
        return None;
    }
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    Some(CpuTimes {
        total: fields.iter().sum(),
        idle,
    })
}

/// Values are in kB.
fn parse_memory(lines: &[&str]) -> Memory {
    let mut values: HashMap<&str, u64> = HashMap::new();
    for line in lines {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(kb) = rest.split_whitespace().next().and_then(|v| v.parse().ok()) else {
            continue;
        };
        values.insert(key.trim(), kb);
    }
    let kb = |key: &str| values.get(key).copied().unwrap_or(0);
    // Kernels before 3.14 have no MemAvailable.
    let available = values
        .get("MemAvailable")
        .copied()
        .unwrap_or_else(|| kb("MemFree") + kb("Buffers") + kb("Cached"));
    Memory {
        total: kb("MemTotal") * 1024,
        available: available * 1024,
        swap_total: kb("SwapTotal") * 1024,
        swap_free: kb("SwapFree") * 1024,
    }
}

fn parse_load(lines: &[&str]) -> [f32; 3] {
    let mut load = [0.0; 3];
    let Some(line) = lines.first() else {
        return load;
    };
    for (slot, value) in load.iter_mut().zip(line.split_whitespace()) {
        *slot = value.parse().unwrap_or(0.0);
    }
    load
}

fn parse_uptime(lines: &[&str]) -> Duration {
    lines
        .first()
        .and_then(|line| line.split_whitespace().next())
        .and_then(|seconds| seconds.parse::<f64>().ok())
        .map(Duration::from_secs_f64)
        .unwrap_or_default()
}

/// "  eth0: rx_bytes rx_packets ... (8 fields) tx_bytes ...". Old kernels
/// glue a large first number to the colon, so the line is cut there first.
fn parse_net(lines: &[&str]) -> (u64, u64) {
    let mut rx = 0;
    let mut tx = 0;
    for line in lines {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let fields: Vec<u64> = rest
            .split_whitespace()
            .map(|field| field.parse().unwrap_or(0))
            .collect();
        if fields.len() < 9 {
            continue;
        }
        rx += fields[0];
        tx += fields[8];
    }
    (rx, tx)
}

/// `df -kP`: "Filesystem 1024-blocks Used Available Capacity Mounted on".
/// Keeps the root and real block devices, once each: a bind mount repeats
/// its device, and loop devices are snap packages.
fn parse_disks(lines: &[&str]) -> Vec<Disk> {
    let mut disks: Vec<Disk> = Vec::new();
    let mut seen_devices: Vec<&str> = Vec::new();
    for line in lines.iter().skip(1) {
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() < 6 {
            continue;
        }
        let device = words[0];
        let mount = words[5..].join(" ");
        let is_block_device = device.starts_with("/dev/") && !device.starts_with("/dev/loop");
        if mount != "/" && !is_block_device {
            continue;
        }
        if seen_devices.contains(&device) {
            continue;
        }
        let (Ok(size), Ok(used)) = (words[1].parse::<u64>(), words[2].parse::<u64>()) else {
            continue;
        };
        seen_devices.push(device);
        disks.push(Disk {
            mount,
            size: size * 1024,
            used: used * 1024,
        });
    }
    disks
}

/// Busy share of all CPUs between two samples, 0 to 100.
pub fn cpu_percent(previous: &CpuTimes, current: &CpuTimes) -> f32 {
    let total = current.total.saturating_sub(previous.total);
    if total == 0 {
        return 0.0;
    }
    let idle = current.idle.saturating_sub(previous.idle);
    (total.saturating_sub(idle) as f32 / total as f32 * 100.0).clamp(0.0, 100.0)
}

/// What this computer is, and how busy it is, in the same text the remote
/// probe prints. The panel parses both with [`parse_info`] and [`parse_sample`].
pub fn read_local(needs_info: bool, needs_sample: bool) -> (Option<String>, Option<String>) {
    #[cfg(target_os = "linux")]
    {
        return linux_read(needs_info, needs_sample);
    }
    #[cfg(target_os = "macos")]
    {
        return macos_read(needs_info, needs_sample);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let info = needs_info.then(other_os_info);
        // One unreadable sample, so the panel stops asking.
        let sample = needs_sample.then(|| "unsupported".to_string());
        (info, sample)
    }
}

#[cfg(target_os = "linux")]
fn linux_read(needs_info: bool, needs_sample: bool) -> (Option<String>, Option<String>) {
    match (needs_info, needs_sample) {
        (true, true) => {
            let output = run_sh(info_and_sample_command());
            (output.clone(), output)
        }
        (true, false) => (run_sh(info_command()), None),
        (false, true) => (None, run_sh(sample_command())),
        (false, false) => (None, None),
    }
}

#[cfg(target_os = "linux")]
fn run_sh(command: String) -> Option<String> {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    (!text.trim().is_empty()).then_some(text)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn other_os_info() -> String {
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    format!("@host\n{host}\n@os\nWindows\n")
}

#[cfg(target_os = "macos")]
fn macos_read(needs_info: bool, needs_sample: bool) -> (Option<String>, Option<String>) {
    let info = needs_info.then(macos_info);
    let sample = needs_sample.then(macos_sample);
    (info, sample)
}

#[cfg(target_os = "macos")]
fn macos_info() -> String {
    let host = sysctl_string("kern.hostname").unwrap_or_default();
    let os = macos_product();
    let kernel = command_line("uname", &["-sr"]).unwrap_or_default();
    let arch = command_line("uname", &["-m"]).unwrap_or_default();
    let cpu = sysctl_string("machdep.cpu.brand_string")
        .filter(|model| !model.is_empty())
        .or_else(|| sysctl_string("hw.model"))
        .unwrap_or_default();
    let cores = sysctl_string("hw.ncpu").unwrap_or_default();
    let addresses = local_addresses().join(" ");
    format!(
        "@host\n{host}\n@os\n{os}\n@kernel\n{kernel}\n@arch\n{arch}\n@cpu\nmodel name: {cpu}\n@cores\n{cores}\n@ip\n{addresses}\n"
    )
}

#[cfg(target_os = "macos")]
fn macos_product() -> String {
    let name = command_line("sw_vers", &["-productName"]).unwrap_or_default();
    let version = command_line("sw_vers", &["-productVersion"]).unwrap_or_default();
    format!("{name} {version}").trim().to_string()
}

#[cfg(target_os = "macos")]
fn macos_sample() -> String {
    let ticks = cpu_ticks();
    let (user, nice, system, idle) = ticks.unwrap_or((0, 0, 0, 0));
    let cores = sysctl_u64("hw.ncpu").unwrap_or(1).max(1);
    let mut cpu_lines = String::new();
    for index in 0..cores {
        cpu_lines.push_str(&format!("cpu{index} 0 0 0 0\n"));
    }
    let (total, available, swap_total, swap_free) = memory_kb();
    let load = load_average();
    let uptime = uptime_seconds();
    let (rx, tx) = net_bytes();
    let df = command_line("df", &["-kP"]).unwrap_or_default();
    format!(
        "@stat\ncpu  {user} {nice} {system} {idle}\n{cpu_lines}@mem\nMemTotal: {total} kB\nMemAvailable: {available} kB\nSwapTotal: {swap_total} kB\nSwapFree: {swap_free} kB\n@load\n{load}\n@uptime\n{uptime:.2}\n@net\n  en0: {rx} 0 0 0 0 0 0 0 {tx}\n@df\n{df}\n"
    )
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn cpu_ticks() -> Option<(u64, u64, u64, u64)> {
    let mut info: libc::host_cpu_load_info = unsafe { std::mem::zeroed() };
    let mut count = libc::HOST_CPU_LOAD_INFO_COUNT;
    let status = unsafe {
        libc::host_statistics(
            libc::mach_host_self(),
            libc::HOST_CPU_LOAD_INFO,
            &mut info as *mut _ as libc::host_info_t,
            &mut count,
        )
    };
    if status != 0 {
        return None;
    }
    let ticks = info.cpu_ticks;
    let at = |state: libc::c_int| ticks.get(state as usize).copied().unwrap_or(0) as u64;
    Some((
        at(libc::CPU_STATE_USER),
        at(libc::CPU_STATE_NICE),
        at(libc::CPU_STATE_SYSTEM),
        at(libc::CPU_STATE_IDLE),
    ))
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn memory_kb() -> (u64, u64, u64, u64) {
    let total = sysctl_u64("hw.memsize").unwrap_or(0) / 1024;
    let page = unsafe { libc::vm_page_size }.max(4096) as u64;
    let mut stats: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
    let mut count = libc::HOST_VM_INFO64_COUNT;
    let status = unsafe {
        libc::host_statistics64(
            libc::mach_host_self(),
            libc::HOST_VM_INFO64,
            &mut stats as *mut _ as libc::host_info64_t,
            &mut count,
        )
    };
    if status != 0 {
        return (total, 0, 0, 0);
    }
    let pages = |count: libc::natural_t| count as u64 * page / 1024;
    // A packed field is read through a pointer so the compiler does not
    // assume the page counts are aligned.
    let free = unsafe { std::ptr::addr_of!(stats.free_count).read_unaligned() };
    let inactive = unsafe { std::ptr::addr_of!(stats.inactive_count).read_unaligned() };
    let speculative = unsafe { std::ptr::addr_of!(stats.speculative_count).read_unaligned() };
    let available = pages(free) + pages(inactive) + pages(speculative);
    (total, available.min(total), 0, 0)
}

#[cfg(target_os = "macos")]
fn load_average() -> String {
    // `{ 1.23 0.90 0.80 }`
    let raw = command_line("sysctl", &["-n", "vm.loadavg"]).unwrap_or_default();
    let numbers: Vec<&str> = raw
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .filter(|part| !part.is_empty())
        .take(3)
        .collect();
    if numbers.len() == 3 {
        format!("{} {} {}", numbers[0], numbers[1], numbers[2])
    } else {
        "0 0 0".to_string()
    }
}

#[cfg(target_os = "macos")]
fn uptime_seconds() -> f64 {
    let mut boot: libc::timeval = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::timeval>();
    let name = std::ffi::CString::new("kern.boottime").unwrap_or_default();
    let ok = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            &mut boot as *mut _ as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } == 0;
    if !ok || boot.tv_sec <= 0 {
        return 0.0;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    (now - boot.tv_sec as i64).max(0) as f64
}

/// Bytes in and out since boot, every interface except loopback.
#[cfg(target_os = "macos")]
fn net_bytes() -> (u64, u64) {
    let text = command_line("netstat", &["-ib"]).unwrap_or_default();
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Link rows carry the counters. A missing hardware address shifts them.
        if fields.len() < 10
            || !fields
                .get(2)
                .is_some_and(|network| network.starts_with("<Link"))
        {
            continue;
        }
        if fields[0].starts_with("lo") {
            continue;
        }
        let has_address = fields.get(3).is_some_and(|field| field.contains(':'));
        let (in_at, out_at) = if has_address { (6, 9) } else { (5, 8) };
        rx += fields.get(in_at).and_then(|v| v.parse().ok()).unwrap_or(0);
        tx += fields.get(out_at).and_then(|v| v.parse().ok()).unwrap_or(0);
    }
    (rx, tx)
}

#[cfg(target_os = "macos")]
fn local_addresses() -> Vec<String> {
    let mut addresses = Vec::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return addresses;
        }
        let mut current = head;
        while !current.is_null() {
            let iface = &*current;
            let flags = iface.ifa_flags as libc::c_int;
            let is_up = flags & libc::IFF_UP != 0;
            let is_loop = flags & libc::IFF_LOOPBACK != 0;
            if is_up && !is_loop {
                if let Some(address) = address_of(iface.ifa_addr) {
                    addresses.push(address);
                }
            }
            current = iface.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    addresses.sort_by_key(|address| address.contains(':'));
    addresses.dedup();
    addresses
}

#[cfg(target_os = "macos")]
fn address_of(addr: *const libc::sockaddr) -> Option<String> {
    if addr.is_null() {
        return None;
    }
    let family = unsafe { (*addr).sa_family as i32 };
    let text = match family {
        libc::AF_INET => {
            let ip = unsafe { (*addr.cast::<libc::sockaddr_in>()).sin_addr.s_addr };
            let octets = ip.to_ne_bytes();
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
        }
        libc::AF_INET6 => {
            let bytes = unsafe { (*addr.cast::<libc::sockaddr_in6>()).sin6_addr.s6_addr };
            format_ipv6(&bytes)
        }
        _ => return None,
    };
    // A link-local address is not how you reach this machine.
    (!text.starts_with("fe80:") && text != "127.0.0.1" && text != "::1").then_some(text)
}

#[cfg(target_os = "macos")]
fn format_ipv6(bytes: &[u8; 16]) -> String {
    let mut parts = [0u16; 8];
    for (index, part) in parts.iter_mut().enumerate() {
        *part = u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
    }
    parts.map(|part| format!("{part:x}")).join(":")
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &str) -> Option<String> {
    let key = std::ffi::CString::new(name).ok()?;
    let mut len = 0usize;
    let failed = unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0;
    if failed || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let failed = unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0;
    if failed {
        return None;
    }
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).trim().to_string())
}

#[cfg(target_os = "macos")]
fn sysctl_u64(name: &str) -> Option<u64> {
    let key = std::ffi::CString::new(name).ok()?;
    let mut value = 0u64;
    let mut len = std::mem::size_of::<u64>();
    let ok = unsafe {
        libc::sysctlbyname(
            key.as_ptr(),
            &mut value as *mut u64 as *mut _,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } == 0;
    ok.then_some(value)
}

#[cfg(target_os = "macos")]
fn command_line(program: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

pub fn bytes_per_second(previous: u64, current: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= 0.0 {
        return 0.0;
    }
    current.saturating_sub(previous) as f64 / seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "@stat
cpu  4705 356 584 3699 23 23 0 0 0 0
cpu0 1393280 32966 572056 13343292 6130 0 17875 0 23933 0
cpu1 1335532 31914 576893 13352853 5779 0 1376 0 23458 0
intr 114930548 113199788 3 0 5 263 0 4 [... lots more numbers ...]
@mem
MemTotal:        8040624 kB
MemFree:          256084 kB
MemAvailable:    5120312 kB
Buffers:          102400 kB
Cached:          4000000 kB
SwapTotal:       2097148 kB
SwapFree:        1048574 kB
@load
0.52 0.38 0.30 2/412 31337
@uptime
350735.47 234388.90
@net
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0
  eth0: 1000000    2000    0    0    0     0          0         0   500000    1500    0    0    0     0       0          0
 wlan0:2000000     10    0    0    0     0          0         0     4000      20    0    0    0     0       0          0
@df
Filesystem     1024-blocks      Used Available Capacity Mounted on
udev               4000000         0   4000000       0% /dev
tmpfs               804064      1764    802300       1% /run
/dev/sda1         98000000  41000000  52000000      45% /
/dev/loop0           65536     65536         0     100% /snap/core20/2105
/dev/sdb1        500000000 100000000 400000000      20% /mnt/data disk
/dev/sda1         98000000  41000000  52000000      45% /var/lib/docker/bind
";

    #[cfg(target_os = "macos")]
    #[test]
    fn this_mac_reports_a_name_and_a_cpu_sample() {
        let (info, sample) = read_local(true, true);
        let info = parse_info(&info.expect("info"));
        assert!(!info.hostname.is_empty(), "{info:?}");
        let sample = parse_sample(&sample.expect("sample")).expect("parse sample");
        assert!(sample.cpu.total > 0);
        assert!(sample.memory.total > 0);
    }

    #[test]
    fn a_linux_sample_is_read_whole() {
        let sample = parse_sample(SAMPLE).unwrap();
        assert_eq!(
            sample.cpu,
            CpuTimes {
                total: 9390,
                idle: 3722
            }
        );
        assert_eq!(sample.cpu_count, 2);
        assert_eq!(sample.memory.total, 8040624 * 1024);
        assert_eq!(sample.memory.used(), (8040624 - 5120312) * 1024);
        assert_eq!(sample.memory.swap_used(), (2097148 - 1048574) * 1024);
        assert_eq!(sample.load, [0.52, 0.38, 0.30]);
        assert_eq!(sample.uptime.as_secs(), 350735);
        assert_eq!((sample.net_rx, sample.net_tx), (3_000_000, 504_000));
    }

    #[test]
    fn disks_keep_the_root_and_real_devices_once() {
        let sample = parse_sample(SAMPLE).unwrap();
        let mounts: Vec<&str> = sample.disks.iter().map(|d| d.mount.as_str()).collect();
        assert_eq!(mounts, ["/", "/mnt/data disk"]);
        assert_eq!(sample.disks[0].used, 41_000_000 * 1024);
    }

    #[test]
    fn a_container_root_on_overlay_still_shows() {
        let df = [
            "Filesystem 1024-blocks Used Available Capacity Mounted on",
            "overlay 1000 500 500 50% /",
        ];
        assert_eq!(parse_disks(&df).len(), 1);
    }

    #[test]
    fn a_host_without_proc_has_no_sample() {
        assert_eq!(parse_sample("@stat\n@mem\n@load\n"), None);
    }

    #[test]
    fn old_kernels_without_mem_available_add_up_free_memory() {
        let memory = parse_memory(&[
            "MemTotal: 1000 kB",
            "MemFree: 100 kB",
            "Buffers: 50 kB",
            "Cached: 250 kB",
        ]);
        assert_eq!(memory.available, 400 * 1024);
    }

    #[test]
    fn cpu_percent_is_the_busy_share_between_samples() {
        let before = CpuTimes {
            total: 1000,
            idle: 800,
        };
        let after = CpuTimes {
            total: 1200,
            idle: 950,
        };
        assert_eq!(cpu_percent(&before, &after), 25.0);
        assert_eq!(cpu_percent(&after, &after), 0.0);
    }

    #[test]
    fn info_reads_every_field_and_puts_ipv4_first() {
        let info = parse_info(
            "@host\nweb-01\n@os\nUbuntu 24.04.1 LTS\n@kernel\nLinux 6.8.0-45-generic\n\
             @arch\nx86_64\n@cpu\nmodel name\t: AMD EPYC 7763 64-Core Processor\n\
             @cores\n4\n@ip\n2a01:4f8::1 10.0.0.5 \n",
        );
        assert_eq!(info.hostname, "web-01");
        assert_eq!(info.os_name.as_deref(), Some("Ubuntu 24.04.1 LTS"));
        assert_eq!(
            info.cpu_model.as_deref(),
            Some("AMD EPYC 7763 64-Core Processor")
        );
        assert_eq!(info.cpu_count, Some(4));
        assert_eq!(info.addresses, ["10.0.0.5", "2a01:4f8::1"]);
    }

    #[test]
    fn ip_addr_output_gives_the_addresses_without_prefix() {
        let addresses = parse_addresses(&[
            "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0",
            "2: eth0    inet6 2a01:4f8::1/64 scope global",
        ]);
        assert_eq!(addresses, ["10.0.0.5", "2a01:4f8::1"]);
    }

    #[test]
    fn one_output_gives_both_the_info_and_a_sample() {
        let output = format!("@host\nweb-01\n@kernel\nLinux 6.8.0\n{SAMPLE}");
        assert_eq!(parse_info(&output).hostname, "web-01");
        assert_eq!(
            parse_sample(&output).map(|sample| sample.cpu_count),
            Some(2)
        );
    }

    #[test]
    fn the_scripts_run_in_sh_whatever_the_login_shell() {
        let command = sample_command();
        assert!(command.starts_with("echo "));
        assert!(command.ends_with(" | base64 -d | sh 2>/dev/null"));
        assert!(!command.contains('\''));
    }
}
