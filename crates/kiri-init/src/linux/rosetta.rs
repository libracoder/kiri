//! What Rosetta makes inside an amd64 build step, kept out of its layer.
//!
//! Apple's Rosetta runtime makes `$HOME/.cache` and `$HOME/.cache/rosetta`
//! whenever it translates a program whose HOME exists and is writable, and
//! may leave `<name>.flu` files there; the paths are built into the runtime
//! and no setting moves or stops them. A real amd64 machine never has
//! them, so every amd64 RUN layer built on Apple silicon carried
//! `/root/.cache/rosetta` and a new mtime on /root. As the runtime's mount
//! stubs are, they are the runtime's, not the step's: in the layer of a step
//! whose program Rosetta runs, a `.cache/rosetta` folder the layers below
//! lack that holds nothing but `*.flu` files goes, with its `.cache` if
//! that is new and holds nothing else, and the time of the folder above is
//! put back; so do new `/tmp/rosetta.<pid>.<uid>` files. Anything the
//! step's own commands wrote there stays. Wherever HOME pointed (USER, an
//! ENV HOME, `HOME=` inside the step), the whole layer is looked at, so no
//! home is missed.
//!
//! Nothing runs and nothing is mounted: a step whose program is arm64
//! costs one read of its first bytes and gets nothing. While the step runs
//! its programs see Rosetta's empty folder, as they do under Docker Desktop.
//! Containers run with `docker run` are left as they are (as on Docker
//! Desktop): their diff and commit show the folder.

use std::fs;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// The first 20 bytes of an x86-64 ELF executable or shared object, and the
/// bits of them that are compared: Apple's binfmt entry for Rosetta.
pub const MAGIC: [u8; 20] = *b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00";
pub const MASK: [u8; 20] = *b"\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff";

/// Marks a step whose program runs under Rosetta, in its folder.
pub const MARK: &str = "rosetta";

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Set once this guest has Rosetta registered; never on a Linux host or an
/// x86-64 guest.
static REGISTERED: AtomicBool = AtomicBool::new(false);

#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub fn set_registered() {
    REGISTERED.store(true, Ordering::Relaxed);
}

/// The line written to `/proc/sys/fs/binfmt_misc/register`. `F` opens the
/// interpreter now, so it works inside every container's mounts.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub fn binfmt_line(interpreter: &str) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("\\x{x:02x}")).collect::<String>();
    format!(":rosetta:M::{}:{}:{interpreter}:CF", hex(&MAGIC), hex(&MASK))
}

/// Whether the kernel hands a file starting with `head` to Rosetta: as
/// binfmt_misc compares, both sides masked.
pub fn translated(head: &[u8]) -> bool {
    head.len() >= MAGIC.len() && head.iter().zip(MASK).zip(MAGIC).all(|((b, m), want)| b & m == want & m)
}

/// The interpreter of a `#!` script.
fn shebang(head: &[u8]) -> Option<&str> {
    let line = head.strip_prefix(b"#!")?;
    let line = &line[..line.iter().position(|&b| b == b'\n').unwrap_or(line.len())];
    std::str::from_utf8(line).ok()?.split_ascii_whitespace().next().filter(|p| p.starts_with('/'))
}

/// Bytes of a program looked at: an ELF header, or a `#!` line.
const HEAD: usize = 256;

/// The first bytes of `path` inside the root, every link resolved inside it.
/// Only a regular file is opened for reading, and never in a way that can
/// wait: this runs on the agent's own thread, and the step's tree is the
/// step's to shape (a FIFO there would hold the agent for good, a device
/// node's open can do anything). So the file is found with an `O_PATH`
/// lookup, which opens nothing, checked with `fstat`, and only then opened
/// through that very descriptor, `O_NONBLOCK`.
fn head_of(root: &fs::File, path: &str) -> Option<Vec<u8>> {
    use std::os::fd::AsFd;
    let at = super::inroot::lookup(root.as_fd(), Path::new(path)).ok()?;
    // SAFETY: fstat into a zeroed stat on a descriptor we own.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(at.as_raw_fd(), &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let mut f = fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY).open(format!("/proc/self/fd/{}", at.as_raw_fd())).ok()?;
    let mut head = vec![0u8; HEAD];
    let n = f.read(&mut head).ok()?;
    head.truncate(n);
    Some(head)
}

/// Whether the step's program (`argv0`, looked up on its PATH as the start
/// does) runs under Rosetta, a script's interpreter included.
fn starts_translated(rootfs: &Path, argv0: &str, env: &[&str], cwd: &str) -> bool {
    let Ok(root) = fs::File::open(rootfs) else { return false };
    let candidates: Vec<String> = if argv0.contains('/') {
        vec![if argv0.starts_with('/') { argv0.to_owned() } else { format!("{}/{argv0}", cwd.trim_end_matches('/')) }]
    } else {
        let path = env.iter().find_map(|e| e.strip_prefix("PATH=")).unwrap_or(DEFAULT_PATH);
        path.split(':').filter(|d| !d.is_empty()).map(|d| format!("{}/{argv0}", d.trim_end_matches('/'))).collect()
    };
    let Some(head) = candidates.iter().find_map(|c| head_of(&root, c)) else { return false };
    if translated(&head) {
        return true;
    }
    shebang(&head).and_then(|i| head_of(&root, i)).is_some_and(|h| translated(&h))
}

/// Marks the step in `base` about to start on `rootfs` when Rosetta will
/// run its program (and drops an old mark otherwise). Nothing at all where
/// Rosetta is not registered.
pub fn mark_step(base: &Path, rootfs: &Path, argv: &[&str], env: &[&str], cwd: &str) -> io::Result<()> {
    if !REGISTERED.load(Ordering::Relaxed) {
        return Ok(());
    }
    let file = base.join(MARK);
    if argv.first().is_some_and(|a| starts_translated(rootfs, a, env, cwd)) {
        return fs::write(file, "");
    }
    match fs::remove_file(&file) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Whether the step in `base` ran under Rosetta.
pub fn marked(base: &Path) -> bool {
    base.join(MARK).exists()
}

/// A path (relative, no leading `/`) Rosetta names `<home>/.cache/rosetta`.
pub fn is_cache_folder(rel: &[u8]) -> bool {
    rel == b".cache/rosetta" || rel.ends_with(b"/.cache/rosetta")
}

/// `<home>/.cache`, the folder above one.
pub fn is_cache_parent(rel: &[u8]) -> bool {
    rel == b".cache" || rel.ends_with(b"/.cache")
}

/// A file Rosetta leaves in its folder: `<name>.flu`.
pub fn is_flu(name: &[u8]) -> bool {
    name.len() > 4 && name.ends_with(b".flu") && !name.contains(&b'/')
}

/// `tmp/rosetta.<pid>.<uid>`, the runtime's file in /tmp.
pub fn is_tmp_file(rel: &[u8]) -> bool {
    let Some(rest) = rel.strip_prefix(b"tmp/rosetta.") else { return false };
    let mut parts = rest.split(|&b| b == b'.');
    let num = |p: Option<&[u8]>| p.is_some_and(|p| !p.is_empty() && p.iter().all(u8::is_ascii_digit));
    num(parts.next()) && num(parts.next()) && parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes binfmt_misc reads from a magic or mask field: `\xHH`
    /// escapes and plain characters.
    fn unescape(field: &str) -> Vec<u8> {
        let b = field.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i..].starts_with(b"\\x") {
                out.push(u8::from_str_radix(&field[i + 2..i + 4], 16).unwrap());
                i += 4;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    /// The entry registered before this module, read as the kernel reads it.
    #[test]
    fn the_binfmt_line_is_apples_entry() {
        let old = concat!(
            ":rosetta:M::",
            r"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00",
            ":",
            r"\xff\xff\xff\xff\xff\xfe\xfe\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff",
            ":/run/rosetta/rosetta:CF",
        );
        let fields = |l: &str| -> Vec<Vec<u8>> { l.split(':').map(unescape).collect() };
        let line = binfmt_line("/run/rosetta/rosetta");
        assert_eq!(fields(&line), fields(old));
        assert_eq!(fields(&line)[4], MAGIC);
        assert_eq!(fields(&line)[5], MASK);
    }

    fn elf(class: u8, kind: u8, machine: u16) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        (h[4], h[5], h[6]) = (class, 1, 1);
        h[16] = kind;
        h[18..20].copy_from_slice(&machine.to_le_bytes());
        h
    }

    #[test]
    fn only_x86_64_programs_go_to_rosetta() {
        assert!(translated(&elf(2, 2, 0x3e)), "x86-64 executable");
        assert!(translated(&elf(2, 3, 0x3e)), "x86-64 PIE (ET_DYN)");
        assert!(!translated(&elf(2, 2, 0xb7)), "arm64");
        assert!(!translated(&elf(1, 2, 0x03)), "i386");
        assert!(!translated(b"#!/bin/sh\n"));
        assert!(!translated(&elf(2, 2, 0x3e)[..19]), "too short");
    }

    #[test]
    fn a_scripts_interpreter_is_read_from_its_first_line() {
        assert_eq!(shebang(b"#!/bin/sh -e\necho"), Some("/bin/sh"));
        assert_eq!(shebang(b"#! /usr/bin/env python3\n"), Some("/usr/bin/env"));
        assert_eq!(shebang(b"#!sh\n"), None);
        assert_eq!(shebang(b"echo\n"), None);
    }

    #[test]
    fn rosettas_names() {
        assert!(is_cache_folder(b"root/.cache/rosetta") && is_cache_folder(b".cache/rosetta") && is_cache_folder(b"home/app/.cache/rosetta"));
        assert!(!is_cache_folder(b"root/x.cache/rosetta") && !is_cache_folder(b"root/.cache/rosetta2"));
        assert!(is_cache_parent(b"root/.cache") && is_cache_parent(b".cache") && !is_cache_parent(b"root/my.cache"));
        assert!(is_flu(b"0ced6549d448d1bd719c6202a33ca024.flu") && !is_flu(b".flu") && !is_flu(b"notes.txt"));
        assert!(is_tmp_file(b"tmp/rosetta.12.0") && is_tmp_file(b"tmp/rosetta.4021.1000"));
        assert!(!is_tmp_file(b"tmp/rosetta.12") && !is_tmp_file(b"tmp/rosetta.a.0") && !is_tmp_file(b"tmp/rosetta.1.2.3") && !is_tmp_file(b"var/tmp/rosetta.1.2"));
    }

    #[test]
    fn steps_are_marked_only_for_an_amd64_program_on_a_rosetta_guest() {
        let d = std::env::temp_dir().join(format!("kiri-rosetta-mark-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for p in ["bin", "usr/bin", "app", "base"] {
            fs::create_dir_all(d.join(p)).unwrap();
        }
        fs::write(d.join("bin/sh"), elf(2, 3, 0x3e)).unwrap();
        fs::write(d.join("usr/bin/native"), elf(2, 3, 0xb7)).unwrap();
        fs::write(d.join("app/run"), b"#!/bin/sh\necho\n").unwrap();
        // An absolute link resolves inside the root, not on this machine.
        std::os::unix::fs::symlink("/bin/sh", d.join("usr/bin/linked")).unwrap();
        let base = d.join("base");
        // Not registered (a Linux host, an Intel Mac): nothing is read or written.
        mark_step(&base, &d, &["/bin/sh"], &[], "/").unwrap();
        assert!(!marked(&base));
        set_registered();
        let mark = |argv0: &str, env: &[&str]| {
            mark_step(&base, &d, &[argv0], env, "/app").unwrap();
            marked(&base)
        };
        assert!(mark("/bin/sh", &[]));
        assert!(!mark("native", &[]), "an arm64 program: no mark, the old one gone");
        assert!(mark("sh", &["PATH=/usr/bin:/bin"]));
        assert!(mark("linked", &[]));
        assert!(mark("./run", &[]), "a script run by an amd64 shell");
        assert!(!mark("missing", &[]));
        let _ = fs::remove_dir_all(&d);
    }

    fn mkfifo(p: &Path) {
        let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }

    /// Runs `f` on a thread of its own and says whether it finished within
    /// two seconds; a hung one is left behind (the test fails).
    fn finishes<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(2)).ok()
    }

    /// `RUN mkfifo /f` then `RUN ["/f"]`, or a script whose `#!`
    /// interpreter is a FIFO: the look at the program's first bytes never
    /// opens it for reading (nobody writes to it: the agent would wait for
    /// good), and a device node is not opened either.
    #[test]
    fn a_fifo_or_a_device_as_the_program_never_blocks_the_look() {
        let d = std::env::temp_dir().join(format!("kiri-rosetta-fifo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("bin")).unwrap();
        mkfifo(&d.join("f"));
        mkfifo(&d.join("bin/interp"));
        fs::write(d.join("script"), b"#!/bin/interp\n").unwrap();
        std::os::unix::fs::symlink("/f", d.join("linked")).unwrap();
        let root = d.clone();
        let got = finishes(move || {
            ["/f", "/script", "/linked"].iter().map(|p| starts_translated(&root, p, &[], "/")).collect::<Vec<_>>()
        });
        assert_eq!(got, Some(vec![false, false, false]), "the look at a FIFO hung");
        let _ = fs::remove_dir_all(&d);
    }

    /// The bytes looked at are bounded, whatever the file's size.
    #[test]
    fn only_the_first_bytes_are_read() {
        let d = std::env::temp_dir().join(format!("kiri-rosetta-head-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let mut big = elf(2, 3, 0x3e);
        big.resize(1 << 20, b'x');
        fs::write(d.join("p"), &big).unwrap();
        let root = fs::File::open(&d).unwrap();
        let head = head_of(&root, "/p").unwrap();
        assert!(head.len() <= 256 && translated(&head));
        let _ = fs::remove_dir_all(&d);
    }
}
