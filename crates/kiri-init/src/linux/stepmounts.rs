//! A build step's `RUN --mount`s that are more than a bind of a guest
//! path, made ready by the agent before the step's child starts and turned
//! into plain mount lines. Only for `run_flags::STEP`. Each one lives in
//! `<containers>/<id>/mnt/<n>/` and is unmounted when the step is removed
//! (see `unmount_all`).
//!
//! Extra flags on a step's mount line (`source\ttarget\tflags`):
//! - `layers=<hex>:<hex>…` (top first): `source` is a path inside the
//!   merged tree of those unpacked layers, mounted as a read-only overlay;
//!   with `rw` the overlay gets a throw-away upper, so the step can write
//!   there and the writes go with the step (BuildKit's `rw` bind). The path
//!   is resolved inside that tree, as BuildKit resolves it: a link in it,
//!   absolute or with `..`, never leads out of the stage. The line becomes
//!   a bind of the tree with `within=<path, hex>`, which the step's child
//!   resolves again inside the tree and binds through the descriptor it
//!   gets (`resolve_within`): nothing is followed from the agent's root,
//!   and nothing swapped in between a check and the mount is mounted.
//! - `lower` with `rw`: `source` is a guest folder (a host folder on a
//!   Linux host) that the step may write to, its writes kept in a throw-away
//!   upper and never reaching the folder.
//! - `mkdir=<uid>:<gid>:<mode octal>`: `source` is a cache folder made with
//!   that owner and mode when it is not there yet; with `seed=<hex>:<hex>…`
//!   and `seedpath=<path, hex>` a new one starts as a copy of that path in
//!   those layers (`from=`, resolved inside them as a bind's path is), its
//!   owner and mode then set as asked (`seedmax=<bytes>`: refused when it
//!   holds more file data than that, the cache's budget). With
//!   `prune` an existing folder is emptied first (`--no-cache`) and made
//!   again as a new one.
//! - `secret=<hex>,uid=,gid=,mode=`: the file's bytes; `source` is ignored.
//!   It is written to a tmpfs of its own, never to a disk, and bound
//!   read-only at the target.
//! - `ssh=<token>,uid=,gid=,mode=`: an ssh agent socket with that owner and
//!   mode, on a tmpfs of its own, bound at the target; each connection to
//!   it is relayed to the host with the step's token (`stepssh`).

use std::fs;
use std::io::{self, Write};
use std::ffi::OsString;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use super::{inroot, layers, sys};

/// `source=` as BuildKit takes it: cleaned as a path from the stage's root
/// (`a/../b` is `b`, `..` at the root stays there) before any link is
/// followed.
fn clean_in_stage(src: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in src.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

/// What `inner` names in the tree at `tree`, every link in it resolved
/// inside that tree, as an `O_PATH` descriptor of the object itself.
/// Missing is NotFound, named as BuildKit names it.
pub fn resolve_within(tree: &Path, inner: &Path) -> io::Result<OwnedFd> {
    let root = inroot::open_root(tree)?;
    let inner = clean_in_stage(inner);
    inroot::lookup(root.as_fd(), &inner).map_err(|e| {
        let gone = e.raw_os_error() == Some(libc::ENOENT) || e.kind() == io::ErrorKind::NotFound;
        if gone { io::Error::new(io::ErrorKind::NotFound, format!("\"/{}\": not found", inner.display())) } else { e }
    })
}

fn in_stage(view: &Path, src: &str) -> io::Result<OwnedFd> {
    resolve_within(view, Path::new(src))
}

/// A `within=` word's path (hex, as a mount line can hold any name).
pub fn within_path(hex: &str) -> io::Result<PathBuf> {
    Ok(PathBuf::from(OsString::from_vec(unhex(hex).map_err(|_| bad("bad stage path"))?)))
}

fn proc_path(fd: &OwnedFd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

pub fn is_dir(fd: &OwnedFd) -> io::Result<bool> {
    // SAFETY: fstat into a zeroed stat on a descriptor we own.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    sys::check(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } as _, "stat")?;
    Ok(st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

fn bad(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.to_owned())
}

/// From the first step with a secret or an ssh agent on, this agent never
/// writes a core: a secret's bytes (and the hex of them in the step's mount
/// lines, and the frame they came in) are in its memory, and with no
/// limit on core size a crash would write them to disk. Children it forks
/// (the ssh relay) keep this; containers get it back at their exec, as
/// every exec does. Earlier crashes still leave a core for debugging.
fn hold_secrets() {
    // SAFETY: a plain prctl on this process.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
}

/// Overwrites a secret's bytes once they are written where they go.
fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: a valid, aligned byte of a buffer we own; volatile so the
        // write is not left out as dead.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
}

/// Hex digits to bytes, on the bytes of the text: any other character, a
/// multi-byte one included, is an error, never a slice inside a character.
fn unhex(s: &str) -> io::Result<Vec<u8>> {
    let digit = |b: u8| (b as char).to_digit(16).filter(|_| b.is_ascii()).map(|d| d as u8);
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(bad("bad secret"));
    }
    b.chunks_exact(2).map(|p| digit(p[0]).zip(digit(p[1])).map(|(h, l)| h << 4 | l).ok_or_else(|| bad("bad secret"))).collect()
}

/// The lock of the cache folder `dir`: `<dir>.lock` beside it, held (flock,
/// exclusive) until the returned file is dropped.
fn cache_lock(dir: &Path) -> io::Result<fs::File> {
    fs::create_dir_all(dir.parent().ok_or_else(|| bad("bad cache folder"))?)?;
    let f = fs::OpenOptions::new().create(true).truncate(false).write(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(format!("{}.lock", dir.display()))?;
    loop {
        // SAFETY: flock on a descriptor we own.
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX) } == 0 {
            return Ok(f);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// A path as an overlay option takes it: `:` and `,` would split it.
fn lowerdir_part(p: &Path) -> io::Result<String> {
    let s = p.to_str().ok_or_else(|| bad("mount source is not UTF-8"))?;
    if s.contains([':', ',', '\\']) {
        return Err(bad("a mount source with ':' or ',' cannot be a step's overlay"));
    }
    Ok(s.to_owned())
}

/// The unpacked layers `hex:hex…` (top first) as overlay lower folders.
fn overlay_lowers(list: &str, layer_root: &Path) -> io::Result<Vec<String>> {
    let mut v = Vec::new();
    for h in list.split(':') {
        if !layers::present(layer_root, h) {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("layer {h} is not unpacked")));
        }
        let part = lowerdir_part(&layers::dir(layer_root, h)?)?;
        // overlayfs refuses a folder listed twice.
        if !v.contains(&part) {
            v.push(part);
        }
    }
    Ok(v)
}

/// The step's mount lines, with every special one made ready and rewritten
/// as a bind of what was made.
pub fn prepare(lines: impl Iterator<Item = String>, base: &Path, layer_root: &Path) -> io::Result<Vec<String>> {
    let r = prepare_lines(lines, base, layer_root);
    // An ssh relay made for a step that will not start ends now.
    if r.is_err()
        && let Some(id) = base.file_name().and_then(|n| n.to_str())
    {
        super::stepssh::forget(id);
    }
    r
}

fn prepare_lines(lines: impl Iterator<Item = String>, base: &Path, layer_root: &Path) -> io::Result<Vec<String>> {
    let mnt = base.join("mnt");
    let mut out = Vec::new();
    for (n, line) in lines.enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 3 {
            out.push(line);
            continue;
        }
        let (src, target, words) = (f[0], f[1], f[2]);
        let flags: Vec<&str> = words.split(',').filter(|w| !w.is_empty()).collect();
        let value = |k: &str| flags.iter().find_map(|w| w.strip_prefix(k));
        let rw = flags.contains(&"rw");
        let plain: Vec<&str> = flags.iter().copied().filter(|w| !w.contains('=') && !matches!(*w, "lower" | "rw" | "prune")).collect();
        let here = mnt.join(n.to_string());
        if let Some(hex) = value("secret=") {
            hold_secrets();
            let num = |k: &str, d: u32| value(k).map_or(Ok(d), |v| u32::from_str_radix(v, if k == "mode=" { 8 } else { 10 }).map_err(|_| bad("bad secret owner")));
            let (uid, gid, mode) = (num("uid=", 0)?, num("gid=", 0)?, num("mode=", 0o400)?);
            let mut data = unhex(hex)?;
            fs::create_dir_all(&here)?;
            sys::mount(c"tmpfs", &sys::cstr(&here)?, c"tmpfs", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, Some(c"mode=0700,size=1m"))?;
            let file = here.join("secret");
            let mut w = fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&file)?;
            let written = w.write_all(&data);
            wipe(&mut data);
            written?;
            drop(w);
            let c = sys::cstr(&file)?;
            // SAFETY: valid NUL-terminated path; plain ownership and mode calls.
            unsafe {
                sys::check(libc::chown(c.as_ptr(), uid, gid) as _, "secret owner")?;
            }
            fs::set_permissions(&file, fs::Permissions::from_mode(mode))?;
            out.push(format!("{}\t{target}\tro", file.display()));
            continue;
        }
        if let Some(token) = value("ssh=") {
            hold_secrets();
            let num = |k: &str, d: u32| value(k).map_or(Ok(d), |v| u32::from_str_radix(v, if k == "mode=" { 8 } else { 10 }).map_err(|_| bad("bad ssh socket owner")));
            let (uid, gid, mode) = (num("uid=", 0)?, num("gid=", 0)?, num("mode=", 0o600)?);
            let id = base.file_name().and_then(|n| n.to_str()).ok_or_else(|| bad("bad step folder"))?;
            let socket = super::stepssh::start(id, &here, token, uid, gid, mode)?;
            out.push(format!("{}\t{target}\t", socket.display()));
            continue;
        }
        if let Some(own) = value("mkdir=") {
            let p: Vec<&str> = own.split(':').collect();
            let [uid, gid, mode] = p[..] else { return Err(bad("bad cache owner")) };
            let (uid, gid) = (uid.parse::<u32>().map_err(|_| bad("bad cache owner"))?, gid.parse::<u32>().map_err(|_| bad("bad cache owner"))?);
            let mode = u32::from_str_radix(mode, 8).map_err(|_| bad("bad cache mode"))?;
            let dir = Path::new(src);
            // The cache's lock, held while it is pruned or made: two steps
            // that name the same cache at once (two builds) take turns, so
            // neither removes the other's `.new` or `.pruned` half way.
            let _lock = cache_lock(dir)?;
            if flags.contains(&"prune") && fs::symlink_metadata(dir).is_ok() {
                // Moved aside first: the step never sees it half deleted.
                let gone = PathBuf::from(format!("{src}.pruned"));
                fs::rename(dir, &gone)?;
                super::rmtree::remove_all(&gone)?;
            }
            if fs::symlink_metadata(dir).is_err() {
                fs::create_dir_all(dir.parent().ok_or_else(|| bad("bad cache folder"))?)?;
                // Filled beside it and renamed in, so a fill cut short is never the cache.
                let fresh = PathBuf::from(format!("{src}.new"));
                let _ = super::rmtree::remove_all(&fresh);
                fs::create_dir(&fresh)?;
                if let Some(list) = value("seed=") {
                    let view = here.join("seed");
                    fs::create_dir_all(&view)?;
                    let mut lowers = overlay_lowers(list, layer_root)?;
                    if lowers.len() == 1 {
                        let empty = here.join("empty");
                        fs::create_dir_all(&empty)?;
                        lowers.push(lowerdir_part(&empty)?);
                    }
                    sys::mount_overlay(&view, &lowers, ",index=off,redirect_dir=nofollow,metacopy=off", libc::MS_RDONLY)?;
                    let inner = String::from_utf8(unhex(value("seedpath=").unwrap_or_default())?).map_err(|_| bad("bad cache seed path"))?;
                    // The cache's budget, when the engine gives one: a seed
                    // with more file data than that is refused, not copied.
                    let seed_max = value("seedmax=").map_or(Ok(u64::MAX), |v| v.parse::<u64>().map_err(|_| bad("bad cache seed budget")))?;
                    // Resolved inside the layers and copied from that very
                    // folder; a path that is missing or not a folder seeds
                    // nothing, as before.
                    let copied = match in_stage(&view, &inner) {
                        Ok(from) if is_dir(&from).unwrap_or(false) => super::container::copy_tree_within(Path::new(&proc_path(&from)), &fresh, seed_max),
                        Ok(_) => Ok(()),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                        Err(e) => Err(e),
                    };
                    let _ = sys::umount_lazy(&view);
                    copied?;
                }
                fs::rename(&fresh, dir)?;
                let c = sys::cstr(dir)?;
                // SAFETY: valid NUL-terminated path.
                unsafe {
                    sys::check(libc::chown(c.as_ptr(), uid, gid) as _, "cache owner")?;
                }
                fs::set_permissions(dir, fs::Permissions::from_mode(mode))?;
            }
            out.push(format!("{src}\t{target}\t{}", plain.join(",")));
            continue;
        }
        let lowers: Option<Vec<String>> = if let Some(list) = value("layers=") {
            Some(overlay_lowers(list, layer_root)?)
        } else if flags.contains(&"lower") {
            Some(vec![lowerdir_part(Path::new(src))?])
        } else {
            None
        };
        let Some(lowers) = lowers else {
            out.push(line);
            continue;
        };
        let view = here.join("view");
        fs::create_dir_all(&view)?;
        // One folder alone is a lower an overlay with no upper refuses; an
        // empty folder below it is harmless and makes two.
        let mut lowers = lowers;
        if lowers.len() == 1 && !rw {
            let empty = here.join("empty");
            fs::create_dir_all(&empty)?;
            lowers.push(lowerdir_part(&empty)?);
        }
        let mut opts = String::from(",index=off,redirect_dir=nofollow,metacopy=off");
        let mut mflags = libc::MS_RDONLY;
        if rw {
            let (upper, work) = (here.join("upper"), here.join("work"));
            fs::create_dir_all(&upper)?;
            fs::create_dir_all(&work)?;
            opts.push_str(&format!(",upperdir={},workdir={}", lowerdir_part(&upper)?, lowerdir_part(&work)?));
            mflags = 0;
        }
        sys::mount_overlay(&view, &lowers, &opts, mflags)?;
        if flags.contains(&"lower") {
            out.push(format!("{}\t{target}\t{}", view.display(), plain.join(",")));
        } else {
            // Never by path: a link in the stage would be followed from the
            // agent's root, before the step's own root is in place. Looked
            // up here too, so a missing path fails the step with its name.
            let inner = clean_in_stage(Path::new(src));
            drop(in_stage(&view, src)?);
            let mut words = plain.clone();
            let within = format!("within={}", hexs(inner.as_os_str().as_encoded_bytes()));
            words.push(&within);
            out.push(format!("{}\t{target}\t{}", view.display(), words.join(",")));
        }
    }
    Ok(out)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Unmounts whatever `prepare` mounted for the step at `base`.
pub fn unmount_all(base: &Path) {
    if let Some(id) = base.file_name().and_then(|n| n.to_str()) {
        super::stepssh::forget(id);
    }
    let Ok(list) = fs::read_dir(base.join("mnt")) else { return };
    for e in list.flatten() {
        let p = e.path();
        let _ = sys::umount_lazy(&p.join("view"));
        let _ = sys::umount_lazy(&p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn root() -> bool {
        // SAFETY: no arguments, no side effects.
        unsafe { libc::geteuid() == 0 }
    }

    /// A step folder, a layer store with one unpacked layer holding links
    /// that point out of it, and an "outside" folder standing in for the
    /// agent's root. Removed (and unmounted) when dropped.
    struct Stage {
        dir: PathBuf,
        base: PathBuf,
        layers: PathBuf,
        outside: PathBuf,
        hex: String,
    }

    impl Drop for Stage {
        fn drop(&mut self) {
            unmount_all(&self.base);
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn stage(tag: &str) -> Stage {
        let dir = std::env::temp_dir().join(format!("kiri-stepmounts-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (base, layers, outside) = (dir.join("containers/step-1"), dir.join("layers"), dir.join("outside"));
        let hex = "ab".repeat(32);
        let l = layers.join(&hex);
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(outside.join("secret")).unwrap();
        fs::write(outside.join("secret/key"), "outside").unwrap();
        fs::create_dir_all(l.join("data/x")).unwrap();
        fs::write(l.join("data/x/f"), "inside").unwrap();
        fs::create_dir_all(l.join("a/b")).unwrap();
        // Out of the stage, every way: to /, to the outside folder by an
        // absolute path, by `..`, through a chain, through a parent.
        symlink("/", l.join("esc")).unwrap();
        symlink(&outside, l.join("abs_out")).unwrap();
        symlink("../".repeat(40) + outside.strip_prefix("/").unwrap().to_str().unwrap(), l.join("up")).unwrap();
        symlink(&outside, l.join("a/b/c")).unwrap();
        symlink("/a/b", l.join("chain1")).unwrap();
        symlink("chain1/c", l.join("chain2")).unwrap();
        // And inside it, as BuildKit follows them.
        symlink("/data", l.join("abs")).unwrap();
        symlink("data/x", l.join("rel")).unwrap();
        symlink("/data/x/f", l.join("file")).unwrap();
        fs::write(layers.join(format!("{hex}.done")), "").unwrap();
        Stage { dir, base, layers, outside, hex }
    }

    /// Where a prepared line's source really is: what the step's child
    /// binds (a stage path resolved inside the stage, or the path itself).
    fn source_of(line: &str) -> PathBuf {
        let f: Vec<&str> = line.split('\t').collect();
        match f[2].split(',').find_map(|w| w.strip_prefix("within=")) {
            Some(w) => fs::canonicalize(proc_path(&resolve_within(Path::new(f[0]), &within_path(w).unwrap()).unwrap())).unwrap(),
            None => fs::canonicalize(f[0]).unwrap(),
        }
    }

    fn bind(s: &Stage, src: &str, rw: bool) -> io::Result<(PathBuf, Vec<String>)> {
        let line = format!("{src}\t/m\tlayers={},{}", s.hex, if rw { "rw" } else { "ro" });
        let p = prepare(std::iter::once(line), &s.base, &s.layers)?;
        let at = source_of(&p[0]);
        Ok((at, p))
    }

    /// `RUN --mount=type=bind,from=<stage>,source=<link out>`: the source
    /// is resolved inside the stage. A link to / is the stage's root, a
    /// link to anything outside names nothing there; never the agent's
    /// root or the outside folder.
    #[test]
    fn a_stage_bind_never_follows_a_link_out_of_the_stage() {
        if !root() {
            eprintln!("skipped: needs root (overlay mounts)");
            return;
        }
        for rw in [false, true] {
            let s = stage(if rw { "bind-rw" } else { "bind-ro" });
            let view = s.base.join("mnt/0/view");
            let (at, _p) = bind(&s, "/esc", rw).unwrap();
            assert_eq!(at, fs::canonicalize(&view).unwrap(), "rw={rw}: a link to / is the stage's root");
            unmount_all(&s.base);
            for src in ["/abs_out", "/up", "/chain2", "/a/b/c/secret", "/chain2/key"] {
                let got = bind(&s, src, rw);
                let outside = fs::canonicalize(&s.outside).unwrap();
                match &got {
                    Ok((at, _)) => assert!(!at.starts_with(&outside) && at.starts_with(fs::canonicalize(&view).unwrap()), "rw={rw}: {src} reached {}", at.display()),
                    Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound, "rw={rw}: {src}: {e}"),
                }
                drop(got);
                unmount_all(&s.base);
            }
            assert_eq!(fs::read_dir(s.outside.join("secret")).unwrap().count(), 1);
        }
    }

    /// Links that stay inside the stage are followed, as BuildKit follows
    /// them: to a folder by an absolute or a relative path, and to a file.
    #[test]
    fn a_stage_bind_follows_a_link_inside_the_stage() {
        if !root() {
            eprintln!("skipped: needs root (overlay mounts)");
            return;
        }
        let s = stage("inside");
        let view = fs::canonicalize(&s.base).unwrap().join("mnt/0/view");
        for (src, want) in [("/abs", "data"), ("rel", "data/x"), ("/file", "data/x/f"), ("/data/../abs/x", "data/x"), ("/", "")] {
            let (at, _p) = bind(&s, src, false).unwrap();
            assert_eq!(at, if want.is_empty() { view.clone() } else { view.join(want) }, "{src}");
            unmount_all(&s.base);
        }
        assert_eq!(bind(&s, "/missing", false).err().map(|e| e.kind()), Some(io::ErrorKind::NotFound));
    }

    /// A step with a secret makes the agent one that writes no core from
    /// then on (the secret's bytes are in its memory); the secret itself is
    /// written where the step reads it.
    #[test]
    fn a_secret_makes_the_agent_write_no_core() {
        if !root() {
            eprintln!("skipped: needs root (a tmpfs mount)");
            return;
        }
        let s = stage("secret");
        let line = format!("\t/run/secrets/s\tsecret={},uid=0,gid=0,mode=400", "736563726574");
        let out = prepare(std::iter::once(line), &s.base, &s.layers).unwrap();
        let file = out[0].split('\t').next().unwrap().to_owned();
        assert_eq!(fs::read(&file).unwrap(), b"secret");
        // SAFETY: a plain prctl query.
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0, "no core from here on");
    }

    /// The bind goes through the descriptor the lookup gave: a link swapped
    /// in at that path afterwards (before the step's child mounts it)
    /// changes nothing.
    #[test]
    fn a_link_swapped_in_after_the_lookup_is_not_what_gets_mounted() {
        if !root() {
            eprintln!("skipped: needs root (bind mounts)");
            return;
        }
        let s = stage("swap");
        let tree = s.dir.join("tree");
        fs::create_dir_all(tree.join("a/x")).unwrap();
        fs::write(tree.join("a/x/f"), "inside").unwrap();
        let at = in_stage(&tree, "/a/x").unwrap();
        fs::rename(tree.join("a"), tree.join("gone")).unwrap();
        symlink(&s.outside, tree.join("a")).unwrap();
        let target = s.dir.join("target");
        fs::create_dir_all(&target).unwrap();
        sys::mount(&sys::cstr(Path::new(&proc_path(&at))).unwrap(), &sys::cstr(&target).unwrap(), c"none", libc::MS_BIND, None).unwrap();
        let got = fs::read_dir(&target).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
        let _ = sys::umount_lazy(&target);
        assert_eq!(got, ["f"], "the folder looked up, not the outside one");
    }

    fn seed(s: &Stage, path: &str, id: &str) -> io::Result<PathBuf> {
        let cache = s.dir.join("cache").join(id);
        let line = format!("{}\t/c\tmkdir=0:0:755,seed={},seedpath={}", cache.display(), s.hex, hexs(path.as_bytes()));
        prepare(std::iter::once(line), &s.base, &s.layers)?;
        unmount_all(&s.base);
        Ok(cache)
    }

    fn names(p: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(p).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    /// `--mount=type=cache,from=<stage>,source=<link>`: a new cache folder
    /// starts as a copy of what the link names inside the stage; a link out
    /// of it copies nothing of the agent's root or the outside folder.
    #[test]
    fn a_cache_seed_never_follows_a_link_out_of_the_stage() {
        if !root() {
            eprintln!("skipped: needs root (overlay mounts)");
            return;
        }
        let s = stage("seed");
        // Inside: copied.
        assert_eq!(names(&seed(&s, "/abs", "in").unwrap()), ["x"]);
        assert_eq!(fs::read_to_string(s.dir.join("cache/in/x/f")).unwrap(), "inside");
        // A link to /: the stage's own root, never the agent's.
        let all = seed(&s, "/esc", "esc").unwrap();
        assert!(names(&all).contains(&"data".to_owned()) && !all.join("proc/self").exists(), "{:?}", names(&all));
        // Out of it: nothing of the outside folder.
        for (i, p) in ["/abs_out", "/up", "/chain2"].iter().enumerate() {
            let c = seed(&s, p, &format!("out{i}")).unwrap();
            assert!(!c.join("secret").exists() && !c.join("key").exists(), "{p}: {:?}", names(&c));
        }
    }

    /// Hex from a request that is not hex (a multi-byte character where a
    /// digit pair would be, an odd length) is an error, never a panic.
    #[test]
    fn unhex_takes_any_text() {
        assert_eq!(unhex("00ff7A").unwrap(), [0, 255, 0x7a]);
        assert_eq!(unhex("").unwrap(), b"");
        for bad in ["€0", "0€", "a", "zz", "0x", "+1", "é"] {
            assert!(unhex(bad).is_err(), "{bad}");
        }
    }

    /// A cache another step is preparing (its lock held) is not pruned
    /// under it: the prune waits its turn.
    #[test]
    fn a_cache_prune_waits_for_the_cache_lock() {
        let d = std::env::temp_dir().join(format!("kiri-cache-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let cache = d.join("caches/c");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("old"), "x").unwrap();
        let held = cache_lock(&cache).unwrap();
        let line = format!("{}\t/c\tmkdir=0:0:755,prune", cache.display());
        let base = d.join("step");
        fs::create_dir_all(&base).unwrap();
        let (b, l) = (base.clone(), d.join("layers"));
        let t = std::thread::spawn(move || prepare(std::iter::once(line), &b, &l).map(|_| ()).map_err(|e| e.to_string()));
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(cache.join("old").exists(), "pruned while the lock was held");
        drop(held);
        let r = t.join().unwrap();
        if r.is_ok() {
            assert!(!cache.join("old").exists(), "pruned once the lock was free");
        }
        let _ = fs::remove_dir_all(&d);
    }
}
