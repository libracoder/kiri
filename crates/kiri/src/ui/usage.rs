//! What Kiri's window costs this computer, for the status bar beside its
//! version: memory and CPU of the window's process and the processes that
//! draw its page (WebKit's on the Mac and Linux, WebView2's on Windows), not the
//! engine's VM, which the status bar already shows. The Mac's window and
//! Windows' (crates/kiri-win, by #[path]) answer `usage` with it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use serde_json::json;

/// One process: what to call it, its memory in bytes (the footprint the
/// Activity Monitor or Task Manager shows), and its CPU time so far.
struct Proc {
    pid: u32,
    part: &'static str,
    mem: u64,
    cpu_ns: u64,
}

/// The last look: each process's CPU time, and when, for the CPU since.
static LAST: Mutex<Option<(Instant, HashMap<u32, u64>)>> = Mutex::new(None);

/// `{type: "usage", mem, cpu, cores, parts: [{name, mem, cpu, n}]}`: bytes, and
/// CPU as a percentage of one core since the last look (0 the first time).
pub fn event() -> String {
    let procs = procs();
    let now = Instant::now();
    let mut last = LAST.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let secs = last.as_ref().map(|(at, _)| now.duration_since(*at).as_secs_f64()).filter(|s| *s > 0.2);
    let pct = |p: &Proc| match (secs, last.as_ref().and_then(|(_, m)| m.get(&p.pid))) {
        (Some(s), Some(before)) => p.cpu_ns.saturating_sub(*before) as f64 / 1e9 / s * 100.0,
        _ => 0.0,
    };
    let mut parts: Vec<(&'static str, u64, f64, u32)> = Vec::new();
    for p in &procs {
        let c = pct(p);
        match parts.iter_mut().find(|x| x.0 == p.part) {
            Some(x) => {
                x.1 += p.mem;
                x.2 += c;
                x.3 += 1;
            }
            None => parts.push((p.part, p.mem, c, 1)),
        }
    }
    *last = Some((now, procs.iter().map(|p| (p.pid, p.cpu_ns)).collect()));
    let mem: u64 = parts.iter().map(|p| p.1).sum();
    let cpu: f64 = parts.iter().map(|p| p.2).sum();
    let round = |c: f64| (c * 1000.0).round() / 1000.0;
    json!({
        // CPU is a percentage of one core, as Activity Monitor and top count it;
        // the page divides by the cores to say how much of the computer it is.
        "type": "usage", "mem": mem, "cpu": round(cpu), "cores": std::thread::available_parallelism().map_or(1, |n| n.get()),
        "parts": parts.iter().map(|(name, mem, cpu, n)| json!({"name": name, "mem": mem, "cpu": round(*cpu), "n": n})).collect::<Vec<_>>(),
    })
    .to_string()
}

#[cfg(target_os = "macos")]
fn procs() -> Vec<Proc> {
    // WebKit's processes are launchd's children, not ours: macOS says which
    // app they work for through this (private, long-stable) call.
    type Responsible = unsafe extern "C" fn(libc::pid_t) -> libc::pid_t;
    // SAFETY: dlsym with a NUL-terminated name; the symbol, when there, has this signature.
    let responsible: Option<Responsible> = unsafe {
        let f = libc::dlsym(libc::RTLD_DEFAULT, c"responsibility_get_pid_responsible_for_pid".as_ptr());
        (!f.is_null()).then(|| std::mem::transmute::<*mut libc::c_void, Responsible>(f))
    };
    let me = std::process::id() as libc::pid_t;
    let mut out = Vec::new();
    if let Some(p) = sample(me, "Window") {
        out.push(p);
    }
    let Some(responsible) = responsible else { return out };
    let mut pids = vec![0 as libc::pid_t; 4096];
    // SAFETY: the buffer is pids.len() pid_t long, passed as its size in bytes.
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), (pids.len() * size_of::<libc::pid_t>()) as libc::c_int) };
    for &pid in pids.iter().take(n.max(0) as usize) {
        // SAFETY: plain query of another process by pid.
        if pid == me || pid <= 0 || unsafe { responsible(pid) } != me {
            continue;
        }
        let mut name = [0u8; 256];
        // SAFETY: the buffer is 256 bytes, passed as its size.
        let len = unsafe { libc::proc_name(pid, name.as_mut_ptr().cast(), name.len() as u32) };
        let name = String::from_utf8_lossy(&name[..len.max(0) as usize]).into_owned();
        let part = if name.contains("WebContent") {
            "Page"
        } else if name.contains("GPU") {
            "Graphics"
        } else if name.contains("Networking") {
            "Network"
        } else {
            "Helpers"
        };
        out.extend(sample(pid, part));
    }
    out
}

#[cfg(target_os = "macos")]
fn sample(pid: libc::pid_t, part: &'static str) -> Option<Proc> {
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: a rusage_info_v2 for the RUSAGE_INFO_V2 flavor.
    let r = unsafe { libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V2, (&raw mut info).cast()) };
    if r != 0 {
        return None;
    }
    // CPU times are in Mach ticks.
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut Timebase) -> libc::c_int;
    }
    let mut tb = Timebase { numer: 0, denom: 0 };
    // SAFETY: fills the struct.
    unsafe { mach_timebase_info(&raw mut tb) };
    let ticks = info.ri_user_time + info.ri_system_time;
    let ns = if tb.denom == 0 { ticks } else { ticks * u64::from(tb.numer) / u64::from(tb.denom) };
    Some(Proc { pid: pid as u32, part, mem: info.ri_phys_footprint, cpu_ns: ns })
}

/// One process entry from an OS snapshot, for filtering the descendant tree.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcRow {
    pid: u32,
    ppid: u32,
    start_time: Option<u64>,
}

/// Returns `root_pid` and its descendants from `(pid, ppid)` snapshot links,
/// querying `start_time(pid)` only for `root_pid` and candidate children.
///
/// A candidate `C` with `ppid == P` is linked under `P` only when both `P` and
/// `C` have known creation times and `C.start_time >= P.start_time`. That stops
/// PID reuse from pulling an older unrelated process (and its subtree) into
/// Kiri's usage when Windows reassigns its dead parent's PID to a Kiri child.
/// A candidate whose creation time cannot be read (`None`, such as an elevated
/// or protected process that denies `PROCESS_QUERY_LIMITED_INFORMATION`) is
/// excluded; Kiri's own children run as the same user and can always be
/// queried. `visited` guards against cycles when timestamps tie.
#[cfg(any(windows, target_os = "linux", test))]
fn descendants_with(root_pid: u32, links: &[(u32, u32)], mut start_time: impl FnMut(u32) -> Option<u64>) -> Vec<u32> {
    use std::collections::HashSet;

    let mut by_parent: HashMap<u32, Vec<u32>> = HashMap::new();
    for &(pid, ppid) in links {
        if pid != ppid {
            by_parent.entry(ppid).or_default().push(pid);
        }
    }
    let mut visited = HashSet::from([root_pid]);
    let mut tree = vec![root_pid];
    let Some(root_start) = start_time(root_pid) else {
        return tree;
    };
    let mut queue = vec![(root_pid, root_start)];
    let mut i = 0;
    while i < queue.len() {
        let (parent_pid, parent_start) = queue[i];
        i += 1;
        let Some(children) = by_parent.get(&parent_pid) else {
            continue;
        };
        for &child_pid in children {
            if visited.contains(&child_pid) {
                continue;
            }
            if let Some(child_start) = start_time(child_pid)
                && child_start >= parent_start
            {
                visited.insert(child_pid);
                tree.push(child_pid);
                queue.push((child_pid, child_start));
            }
        }
    }
    tree
}

/// Pure descendant selection over a snapshot of `(pid, ppid, start_time)` rows.
#[cfg(any(target_os = "linux", test))]
fn descendants(root_pid: u32, rows: &[ProcRow]) -> Vec<u32> {
    let links: Vec<(u32, u32)> = rows.iter().map(|r| (r.pid, r.ppid)).collect();
    let starts: HashMap<u32, Option<u64>> = rows.iter().map(|r| (r.pid, r.start_time)).collect();
    descendants_with(root_pid, &links, |pid| starts.get(&pid).copied().flatten())
}

/// This process and its children: WebKitGTK's page and network processes.
#[cfg(target_os = "linux")]
fn procs() -> Vec<Proc> {
    let me = std::process::id();
    // pid, parent, starttime, name: field 2 of /proc/<pid>/stat is the name in
    // brackets, followed by state (0), ppid (1), ..., starttime (19).
    let all: Vec<(ProcRow, String)> = std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let (name, rest) = stat.split_once(" (")?.1.rsplit_once(") ")?;
            let fields: Vec<&str> = rest.split(' ').collect();
            let ppid = fields.get(1)?.parse().ok()?;
            let start_time = fields.get(19).and_then(|s| s.parse().ok());
            Some((ProcRow { pid, ppid, start_time }, name.to_owned()))
        })
        .collect();
    let rows: Vec<ProcRow> = all.iter().map(|(r, _)| *r).collect();
    let tree = descendants(me, &rows);
    // SAFETY: sysconf has no preconditions.
    let tick_ns = 1_000_000_000 / u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }).unwrap_or(100).max(1);
    tree.into_iter()
        .filter_map(|pid| {
            let name = &all.iter().find(|(r, _)| r.pid == pid)?.1;
            let part = if pid == me {
                "Window"
            } else if name.starts_with("WebKitWebProces") {
                "Page"
            } else if name.starts_with("WebKitNetworkPr") {
                "Network"
            } else if name.starts_with("WebKitGPUProces") {
                "Graphics"
            } else {
                "Helpers"
            };
            // utime and stime: fields 14 and 15, so 11 and 12 after the name.
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let f: Vec<u64> = stat.rsplit_once(") ")?.1.split(' ').map(|x| x.parse().unwrap_or(0)).collect();
            let cpu_ns = (f.get(11)? + f.get(12)?) * tick_ns;
            // Pss: shared pages split between the processes that share them, as a footprint.
            let rollup = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).unwrap_or_default();
            let kib = rollup.lines().find_map(|l| l.strip_prefix("Pss:")).and_then(|v| v.trim().trim_end_matches(" kB").trim().parse::<u64>().ok()).unwrap_or(0);
            Some(Proc { pid, part, mem: kib << 10, cpu_ns })
        })
        .collect()
}

#[cfg(windows)]
fn procs() -> Vec<Proc> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
    use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // Every process and its parent, then the creation-time-checked tree under this one.
    let mut all: Vec<(u32, u32, String)> = Vec::new();
    // SAFETY: a snapshot handle walked with a sized PROCESSENTRY32W and closed.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e) != 0;
        while ok {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            all.push((e.th32ProcessID, e.th32ParentProcessID, String::from_utf16_lossy(&e.szExeFile[..len])));
            ok = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
    }
    let me = std::process::id();
    let links: Vec<(u32, u32)> = all.iter().map(|&(pid, ppid, _)| (pid, ppid)).collect();
    let filetime_ticks = |f: FILETIME| (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime);
    // Open each candidate process once so creation time, memory, and CPU come
    // from the same process instance (no PID-reuse window between check and sample).
    let mut samples: HashMap<u32, (u64, u64)> = HashMap::new();
    let tree = descendants_with(me, &links, |pid| {
        // SAFETY: a query-only handle, read and closed.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h == 0 {
                return None;
            }
            let (mut c, mut x, mut k, mut u) = (std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed(), std::mem::zeroed());
            let times_ok = GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u) != 0;
            let mut m: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
            m.cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            let mem = if GetProcessMemoryInfo(h, (&raw mut m).cast(), m.cb) != 0 { m.PrivateUsage as u64 } else { 0 };
            CloseHandle(h);
            if !times_ok {
                return None;
            }
            let cpu_ns = filetime_ticks(k).saturating_add(filetime_ticks(u)).saturating_mul(100);
            samples.insert(pid, (mem, cpu_ns));
            Some(filetime_ticks(c))
        }
    });
    let mut out = Vec::new();
    for pid in tree {
        let Some(&(mem, cpu_ns)) = samples.get(&pid) else {
            continue;
        };
        let name = all.iter().find(|p| p.0 == pid).map(|p| p.2.to_ascii_lowercase()).unwrap_or_default();
        let part = if pid == me {
            "Window"
        } else if name.starts_with("msedgewebview2") {
            "WebView2"
        } else {
            "Helpers"
        };
        out.push(Proc { pid, part, mem, cpu_ns });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{ProcRow, descendants, descendants_with};

    #[test]
    fn includes_genuine_children_and_grandchildren() {
        let rows = [
            ProcRow { pid: 100, ppid: 1, start_time: Some(1_000) },
            ProcRow { pid: 200, ppid: 100, start_time: Some(1_010) },
            ProcRow { pid: 201, ppid: 100, start_time: Some(1_020) },
            ProcRow { pid: 300, ppid: 200, start_time: Some(1_030) },
            ProcRow { pid: 999, ppid: 1, start_time: Some(1_050) },
        ];
        assert_eq!(descendants(100, &rows), vec![100, 200, 201, 300]);
    }

    #[test]
    fn excludes_recycled_pid_false_child_and_its_newer_grandchildren() {
        // Issue #190: kiri-win (1000) spawns conhost/wsl with recycled PID 41400
        // at t=2009. An older unrelated process (5000, started at t=1000) has
        // stale ppid=41400, and later spawned children (5001, 5002) at t=2100+.
        let rows = [
            ProcRow { pid: 1000, ppid: 500, start_time: Some(2_000) },
            ProcRow { pid: 41400, ppid: 1000, start_time: Some(2_009) },
            ProcRow { pid: 5000, ppid: 41400, start_time: Some(1_000) },
            ProcRow { pid: 5001, ppid: 5000, start_time: Some(2_100) },
            ProcRow { pid: 5002, ppid: 5001, start_time: Some(2_105) },
            // A real child of 41400 created after it is still included.
            ProcRow { pid: 41401, ppid: 41400, start_time: Some(2_010) },
        ];
        assert_eq!(descendants(1000, &rows), vec![1000, 41400, 41401]);
    }

    #[test]
    fn same_tick_creation_and_synthetic_cycles_terminate() {
        let rows = [
            ProcRow { pid: 10, ppid: 20, start_time: Some(500) },
            ProcRow { pid: 20, ppid: 10, start_time: Some(500) },
            ProcRow { pid: 30, ppid: 20, start_time: Some(500) },
            ProcRow { pid: 20, ppid: 30, start_time: Some(500) },
            ProcRow { pid: 40, ppid: 40, start_time: Some(500) },
        ];
        assert_eq!(descendants(10, &rows), vec![10, 20, 30]);
    }

    #[test]
    fn excludes_unreadable_child_start_time_and_its_subtree() {
        let rows = [
            ProcRow { pid: 100, ppid: 1, start_time: Some(1_000) },
            ProcRow { pid: 200, ppid: 100, start_time: None },
            ProcRow { pid: 201, ppid: 200, start_time: Some(1_500) },
            ProcRow { pid: 300, ppid: 100, start_time: Some(1_100) },
        ];
        assert_eq!(descendants(100, &rows), vec![100, 300]);
    }

    #[test]
    fn unreadable_root_start_time_returns_only_root() {
        let rows = [
            ProcRow { pid: 100, ppid: 1, start_time: None },
            ProcRow { pid: 200, ppid: 100, start_time: Some(1_000) },
        ];
        assert_eq!(descendants(100, &rows), vec![100]);
    }

    #[test]
    fn only_queries_candidate_processes() {
        let links = [(10, 1), (20, 10), (30, 999), (40, 20), (50, 40)];
        let mut queried = Vec::new();
        let tree = descendants_with(10, &links, |pid| {
            queried.push(pid);
            match pid {
                10 => Some(1_000),
                20 => Some(1_010),
                40 => Some(500), // older than 20 -> rejected, so 50 must not be queried
                _ => Some(2_000),
            }
        });
        assert_eq!(tree, vec![10, 20]);
        assert_eq!(queried, vec![10, 20, 40]);
    }
}
