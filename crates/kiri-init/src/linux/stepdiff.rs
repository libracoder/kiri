//! A build step's layer: the step's overlay upper folder written as the tar
//! BuildKit's overlay differ writes for the same change (BuildKit
//! `util/overlay/overlay_linux.go` `Changes`, containerd
//! `pkg/archive/tar.go` `ChangeWriter`).
//!
//! - The upper is walked depth first, each folder's names sorted bytewise.
//! - A whiteout (0/0 character device) becomes `.wh.<name>` (mode, owner
//!   and time 0) where the name is in the layers below, and is dropped
//!   where it is not. The opaque marker is never written: an opaque folder
//!   is compared with the layers below and each name that is gone becomes
//!   its own `.wh.`.
//! - A path also in the layers below is written only if it differs (mode,
//!   owner, device, capability; for non-folders size and mtime, and the
//!   bytes when both mtimes are whole seconds). A folder that is written
//!   because something under it is gets its upper stat, once. A folder
//!   whose mtime alone changed is not written, as BuildKit's `sameDirent`
//!   leaves it out: parity with Docker's builds, layers no bigger than
//!   BuildKit's.
//! - A name starting `.wh.` that the step wrote itself is refused, as are
//!   overlay redirects and metacopy files.
//! - The /etc files the runtime mounts over a step (`hosts`,
//!   `resolv.conf`; `hostname` is not mounted for a step) are left out, and an /etc that held nothing else, as
//!   BuildKit's mount stub cleaner leaves them out. The
//!   `/proc`, `/sys` and `/dev` folders made on a root without them stay,
//!   as runc's do in BuildKit.
//!
//! The layers below are read through one folder (`base`): the layer itself
//! for one layer, a read-only overlay of them for several. Every lookup in
//! it resolves links inside it, so an image's symlinks cannot point the
//! comparison outside. The upper is read by path: the step is gone and
//! only folders seen as folders are entered.

use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use kiri_proto::layertar::{self, Entry, Kind};

use super::{fsview, sys};

/// Prefix of the error text the daemon reads as a refusal, not a failure.
pub const REFUSED: &str = "refused: ";

fn refused(what: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{REFUSED}{what}"))
}

/// The files the runtime mounts over in /etc for every step.
fn etc_mount(name: &[u8]) -> bool {
    matches!(name, b"hosts" | b"resolv.conf")
}

/// What is compared of a file in the upper and below it.
struct Stat {
    mode: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    dev: u64,
    ino: u64,
    nlink: u64,
}

impl From<&fs::Metadata> for Stat {
    fn from(m: &fs::Metadata) -> Stat {
        Stat {
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            rdev: m.rdev(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            dev: m.dev(),
            ino: m.ino(),
            nlink: m.nlink(),
        }
    }
}

/// A stat field as u64, whatever its width on this target (`st_nlink`
/// is u32 on aarch64 Linux and u64 on x86_64).
fn wide<T: Into<u64>>(x: T) -> u64 {
    x.into()
}

impl From<&libc::stat> for Stat {
    fn from(s: &libc::stat) -> Stat {
        Stat {
            mode: s.st_mode,
            uid: s.st_uid,
            gid: s.st_gid,
            rdev: wide(s.st_rdev),
            size: u64::try_from(s.st_size).unwrap_or(0),
            mtime: s.st_mtime,
            mtime_ns: s.st_mtime_nsec,
            dev: wide(s.st_dev),
            ino: wide(s.st_ino),
            nlink: wide(s.st_nlink),
        }
    }
}

impl Stat {
    fn kind(&self) -> u32 {
        self.mode & libc::S_IFMT
    }
    fn is_dir(&self) -> bool {
        self.kind() == libc::S_IFDIR
    }
    fn is_whiteout(&self) -> bool {
        self.kind() == libc::S_IFCHR && self.rdev == 0
    }
}

/// The layers under the step, as one read-only tree.
pub struct Base {
    root: OwnedFd,
}

impl Base {
    pub fn open(dir: &Path) -> io::Result<Base> {
        let c = sys::cstr(dir)?;
        // SAFETY: plain open of a directory; owned right away.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        sys::check(fd as _, "open the layers below")?;
        // SAFETY: a fresh descriptor.
        Ok(Base { root: unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) } })
    }

    fn lstat(&self, rel: &[u8]) -> io::Result<Option<(Stat, OwnedFd)>> {
        match self.open_bytes(rel, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(fd) => {
                // SAFETY: fstat into a zeroed stat on a descriptor we own.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                sys::check(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } as _, "stat below")?;
                Ok(Some(((&st).into(), fd)))
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn open_bytes(&self, rel: &[u8], flags: i32) -> io::Result<OwnedFd> {
        open_in_bytes(self.root.as_raw_fd(), rel, flags)
    }

    /// The names in folder `rel` below, empty when it is not a folder there.
    fn names(&self, rel: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let fd = match self.open_bytes(rel, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(fd) => fd,
            Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        sorted_names(&PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())))
    }
}

/// openat2(RESOLVE_IN_ROOT) of a path given as bytes, names not UTF-8 too.
fn open_in_bytes(root: RawFd, rel: &[u8], flags: i32) -> io::Result<OwnedFd> {
    let rel = if rel.is_empty() { &b"."[..] } else { rel };
    let p = Path::new(OsStr::from_bytes(rel));
    match p.to_str() {
        Some(s) => fsview::open_in(root, s, flags),
        None => {
            // fsview takes a str; a name that is not UTF-8 goes through
            // a descriptor of its parent instead.
            let parent = p.parent().map(|q| q.as_os_str().as_bytes()).unwrap_or_default();
            let name = p.file_name().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            let dir = open_in_bytes(root, parent, libc::O_PATH | libc::O_DIRECTORY)?;
            let c = CString::new(name.as_bytes())?;
            // SAFETY: openat of a single name (no `/`) under a confined descriptor.
            let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
            sys::check(fd as _, "open below")?;
            // SAFETY: a fresh descriptor.
            Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) })
        }
    }
}

fn sorted_names(dir: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut names: Vec<Vec<u8>> = fs::read_dir(dir)?.map(|e| e.map(|e| e.file_name().as_bytes().to_vec())).collect::<io::Result<_>>()?;
    names.sort();
    Ok(names)
}

fn xattr(path: &CString, name: &std::ffi::CStr, follow: bool) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 256];
    loop {
        // SAFETY: valid NUL-terminated path and name; at most buf.len() bytes written.
        let n = unsafe {
            if follow {
                libc::getxattr(path.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
            } else {
                libc::lgetxattr(path.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
            }
        };
        if n >= 0 {
            buf.truncate(n as usize);
            return Ok(buf);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::ENODATA | libc::ENOTSUP) => return Ok(Vec::new()),
            Some(libc::ERANGE) if buf.len() < 65536 => buf.resize(buf.len() * 4, 0),
            _ => return Err(e),
        }
    }
}

fn join(rel: &[u8], name: &[u8]) -> Vec<u8> {
    if rel.is_empty() {
        name.to_vec()
    } else {
        [rel, b"/", name].concat()
    }
}

fn parent(rel: &[u8]) -> &[u8] {
    rel.iter().rposition(|b| *b == b'/').map_or(&b""[..], |i| &rel[..i])
}

/// A folder being walked: its names in the upper and (opaque) below, and
/// how far the merge of the two has gone.
struct OpenDir {
    rel: Vec<u8>,
    opaque: bool,
    upper: Vec<Vec<u8>>,
    below: Vec<Vec<u8>>,
    i: usize,
    j: usize,
}

/// What [`Writer::stub_one`] found.
enum Stub {
    Is(bool),
    IfAll(Vec<Vec<u8>>),
}

struct Writer<'a, W: Write> {
    upper: &'a Path,
    base: Option<&'a Base>,
    out: W,
    head: Vec<u8>,
    /// Folders written so far: a folder is written once, before the first
    /// thing under it.
    dirs: HashSet<Vec<u8>>,
    /// The first name of each hard-linked inode, which carries the body.
    links: HashMap<(u64, u64), Vec<u8>>,
    /// Where the step had mounts (relative, no leading `/`): what the
    /// runtime made there for them is not the step's.
    targets: HashSet<Vec<u8>>,
    /// The step's program ran under Rosetta: what Rosetta made is left out
    /// as a stub is (see `rosetta`).
    rosetta: bool,
    stubs: Stubs,
}

/// What the runtime left in the upper for the step's mounts, which the
/// layer leaves out: to delete from the upper before it is kept as the
/// layer itself, so the folder and the tar hold the same tree.
#[derive(Debug, Default, PartialEq)]
pub struct Stubs {
    /// Stub paths, outermost only.
    pub remove: Vec<Vec<u8>>,
    /// Folders of the layers below that the layer leaves out although
    /// their mtime changed (`sameDirent`). BuildKit's snapshot of the step
    /// keeps that time, and a `COPY --from` of the stage reads the
    /// snapshot, so the time is sent beside the tar.
    pub touched: Vec<Vec<u8>>,
    /// Folders of the layers below that held what Rosetta made and nothing
    /// else of the step's, with the mtime they had below: on an amd64
    /// machine nothing was made there, so their time is the image's.
    pub rosetta_times: Vec<(Vec<u8>, i64, i64)>,
}

impl Stubs {
    /// Deletes the stubs from `upper`. Each parent keeps the mtime it had
    /// just before the removal, as BuildKit's stub cleaner restores it
    /// (executor/stubs.go, buildkit#3148): the time the step left, stub
    /// creation included, never the time the layers below had. A COPY
    /// --from of the stage then sees what BuildKit's snapshot shows,
    /// and a folder the step wrote in keeps the step's time.
    pub fn clean(&self, upper: &Path) -> io::Result<()> {
        let root = super::inroot::open_root(upper)?;
        for rel in &self.remove {
            // Found inside `upper` with no symlink on the way: a stub whose
            // folder is no longer a folder is no stub to remove.
            let Some((dir, name)) = in_upper(&root, rel)? else { continue };
            let before = fstat(dir.as_raw_fd())?;
            let at = super::inroot::at_path(std::os::fd::AsFd::as_fd(&dir), &name);
            match lstat_at(dir.as_raw_fd(), &name) {
                Ok(m) if m.st_mode & libc::S_IFMT == libc::S_IFDIR => super::rmtree::remove_all(Path::new(OsStr::from_bytes(at.to_bytes())))?,
                // SAFETY: a valid directory descriptor and a single NUL-terminated name.
                Ok(_) => drop(sys::check(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } as _, "remove stub")?),
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            }
            let t = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }, libc::timespec { tv_sec: before.st_mtime, tv_nsec: before.st_mtime_nsec }];
            set_times(&dir, None, &t)?;
        }
        for (rel, sec, nsec) in &self.rosetta_times {
            let t = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }, libc::timespec { tv_sec: *sec, tv_nsec: *nsec }];
            if rel.is_empty() {
                set_times(&root, None, &t)?;
            } else if let Some((dir, name)) = in_upper(&root, rel)? {
                set_times(&dir, Some(&name), &t)?;
            }
        }
        Ok(())
    }

    /// The touched folders' times in `upper` once it is cleaned, as
    /// records of `len: u32 LE | path | sec: i64 LE | nsec: u32 LE`
    /// (`copy_op::STEP_LAYER`).
    pub fn folder_times(&self, upper: &Path) -> io::Result<Vec<u8>> {
        let root = super::inroot::open_root(upper)?;
        let mut out = Vec::new();
        for rel in &self.touched {
            let Some((dir, name)) = in_upper(&root, rel)? else {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("/{} is no longer a folder", String::from_utf8_lossy(rel))));
            };
            let m = lstat_at(dir.as_raw_fd(), &name)?;
            out.extend_from_slice(&(rel.len() as u32).to_le_bytes());
            out.extend_from_slice(rel);
            out.extend_from_slice(&m.st_mtime.to_le_bytes());
            out.extend_from_slice(&(m.st_mtime_nsec as u32).to_le_bytes());
        }
        Ok(out)
    }
}

/// `rel`'s folder and name inside the upper folder opened as `root`, with
/// no symlink on the way (see `inroot::parent_strict`); None when a folder
/// on the way is no longer one (the step left a link there).
fn in_upper(root: &OwnedFd, rel: &[u8]) -> io::Result<Option<(OwnedFd, CString)>> {
    match super::inroot::parent_strict(std::os::fd::AsFd::as_fd(root), Path::new(OsStr::from_bytes(rel))) {
        Ok(found) => Ok(Some(found)),
        // parent_strict names the path in its error, so the kind is what is
        // left of the errno: ENOTDIR, ENOENT, or ELOOP (a link on the way).
        Err(e) if matches!(e.kind(), io::ErrorKind::NotADirectory | io::ErrorKind::NotFound) || e.to_string().ends_with("(os error 40)") => Ok(None),
        Err(e) => Err(e),
    }
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: fstat of a valid descriptor (O_PATH ones too) into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    sys::check(unsafe { libc::fstat(fd, &mut st) } as _, "stat")?;
    Ok(st)
}

fn lstat_at(dir: RawFd, name: &std::ffi::CStr) -> io::Result<libc::stat> {
    // SAFETY: fstatat of one name under a valid descriptor, not following it, into a zeroed stat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// Sets times on `name` in `dir` (not followed), or on `dir` itself.
fn set_times(dir: &OwnedFd, name: Option<&std::ffi::CStr>, t: &[libc::timespec; 2]) -> io::Result<()> {
    let ret = match name {
        // SAFETY: a valid directory descriptor, a NUL-terminated name and two timespecs.
        Some(n) => unsafe { libc::utimensat(dir.as_raw_fd(), n.as_ptr(), t.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) },
        None => {
            let p = CString::new(format!("/proc/self/fd/{}", dir.as_raw_fd())).expect("no NUL");
            // SAFETY: the descriptor's magic link, resolved to the folder itself, and two timespecs.
            unsafe { libc::utimensat(libc::AT_FDCWD, p.as_ptr(), t.as_ptr(), 0) }
        }
    };
    sys::check(ret as _, "restore mtime")?;
    Ok(())
}

/// Writes the layer tar for the step whose upper folder is `upper`, the
/// layers below it seen through `base` (none for a step on scratch).
/// `mounts` are the step's mount targets.
/// `rosetta`: the step's program ran under Rosetta (see `rosetta`).
/// Returns the stubs it left out.
pub fn write_step(upper: &Path, base: Option<&Base>, mounts: &[&[u8]], rosetta: bool, out: impl Write) -> io::Result<Stubs> {
    let mut targets: HashSet<Vec<u8>> = mounts.iter().map(|m| m.strip_prefix(b"/").unwrap_or(m).to_vec()).filter(|m| !m.is_empty()).collect();
    targets.extend([b"etc/hosts".to_vec(), b"etc/resolv.conf".to_vec()]);
    let mut w = Writer { upper, base, out, head: Vec::with_capacity(3 * layertar::BLOCK), dirs: HashSet::new(), links: HashMap::new(), targets, rosetta, stubs: Stubs::default() };
    w.walk(b"", false)?;
    w.out.write_all(&layertar::END)?;
    w.out.flush()?;
    Ok(w.stubs)
}

impl<W: Write> Writer<'_, W> {
    fn upath(&self, rel: &[u8]) -> PathBuf {
        if rel.is_empty() { self.upper.to_path_buf() } else { self.upper.join(OsStr::from_bytes(rel)) }
    }

    fn below(&self, rel: &[u8]) -> io::Result<Option<(Stat, OwnedFd)>> {
        match self.base {
            Some(b) => b.lstat(rel),
            None => Ok(None),
        }
    }

    /// The tree under `rel`, depth first in name order. In an opaque folder
    /// (`opaque`), the names of the layers below are merged in: those not
    /// in the upper are gone. The step may leave a tree of any depth, so
    /// the folders being walked are a stack, not a recursion.
    fn walk(&mut self, rel: &[u8], opaque: bool) -> io::Result<()> {
        let mut stack = vec![self.open_dir(rel, opaque)?];
        while let Some(top) = stack.last_mut() {
            let (upper, below) = (&top.upper, &top.below);
            if top.i >= upper.len() && top.j >= below.len() {
                stack.pop();
                continue;
            }
            let take_upper = top.j >= below.len() || (top.i < upper.len() && upper[top.i] <= below[top.j]);
            if !take_upper {
                let gone = join(&top.rel, &below[top.j]);
                top.j += 1;
                self.delete(&gone)?;
                continue;
            }
            if top.j < below.len() && below[top.j] == upper[top.i] {
                top.j += 1;
            }
            // each name is looked at once: taken, not copied
            let name = std::mem::take(&mut top.upper[top.i]);
            top.i += 1;
            if let Some((child, opaque)) = self.entry(&top.rel, &name, top.opaque)? {
                stack.push(self.open_dir(&child, opaque)?);
            }
        }
        Ok(())
    }

    /// A folder [`Writer::walk`] goes into: its names in the upper, and
    /// below when it is opaque.
    fn open_dir(&self, rel: &[u8], opaque: bool) -> io::Result<OpenDir> {
        let upper = sorted_names(&self.upath(rel))?;
        let below = match (opaque, self.base) {
            (true, Some(b)) => b.names(rel)?,
            _ => Vec::new(),
        };
        Ok(OpenDir { rel: rel.to_vec(), opaque, upper, below, i: 0, j: 0 })
    }

    /// One name of a folder; for a folder, it and whether it is opaque,
    /// to walk next.
    fn entry(&mut self, rel: &[u8], name: &[u8], opaque: bool) -> io::Result<Option<(Vec<u8>, bool)>> {
        let child = join(rel, name);
        let path = self.upath(&child);
        let meta = fs::symlink_metadata(&path)?;
        let st = Stat::from(&meta);
        if st.is_whiteout() {
            if self.below(&child)?.is_some() {
                self.delete(&child)?;
            }
            return Ok(None);
        }
        if name.starts_with(b".wh.") {
            return Err(refused(format!("the step wrote /{}: names starting .wh. cannot be kept in a layer", String::from_utf8_lossy(&child))));
        }
        let cpath = sys::cstr(&path)?;
        for (attr, what) in [(c"trusted.overlay.redirect", "a renamed folder (overlay redirect)"), (c"trusted.overlay.metacopy", "a metadata-only copy")] {
            if !xattr(&cpath, attr, false)?.is_empty() {
                return Err(refused(format!("/{} is {what}", String::from_utf8_lossy(&child))));
            }
        }
        if self.stub(&child, &st)? {
            self.stubs.remove.push(child);
            return Ok(None);
        }
        if self.rosetta && self.rosetta_made(&child, &st)? {
            self.rosetta_parent(rel)?;
            self.stubs.remove.push(child);
            return Ok(None);
        }
        let below = self.below(&child)?;
        let same = match &below {
            Some((b, fd)) => self.same(b, fd, &st, &path, &cpath)?,
            None => false,
        };
        if !same {
            self.emit(&child, &st, &cpath)?;
        } else if st.is_dir() && below.as_ref().is_some_and(|(b, _)| (b.mtime, b.mtime_ns) != (st.mtime, st.mtime_ns)) {
            self.stubs.touched.push(child.clone());
        }
        if st.is_dir() {
            // Opaque only over something below, as BuildKit's checkOpaque.
            let opaque_here = below.is_some() && is_opaque(&cpath)?;
            return Ok(Some((child, opaque || opaque_here)));
        }
        Ok(None)
    }

    /// A mount point the runtime made for the step, which BuildKit's stub
    /// cleaner removes: a mount target the layers
    /// below did not have, still an empty folder or file, and the folders
    /// made above it that hold nothing else. The /etc files are covered by
    /// their mount for the whole step, so whatever the upper holds there is
    /// the runtime's.
    ///
    /// The folders under a mount target are a stack here, not a recursion.
    fn stub(&self, child: &[u8], st: &Stat) -> io::Result<bool> {
        let mut stack = match self.stub_one(child, st)? {
            Stub::Is(v) => return Ok(v),
            Stub::IfAll(names) => vec![(child.to_vec(), names.into_iter())],
        };
        while let Some((dir, names)) = stack.last_mut() {
            let Some(n) = names.next() else {
                stack.pop();
                continue;
            };
            let c = join(dir, &n);
            let m = Stat::from(&fs::symlink_metadata(self.upath(&c))?);
            match self.stub_one(&c, &m)? {
                Stub::Is(false) => return Ok(false),
                Stub::Is(true) => {}
                Stub::IfAll(names) => stack.push((c, names.into_iter())),
            }
        }
        Ok(true)
    }

    /// [`Writer::stub`] for one path: a stub or not, or a folder above a
    /// mount target, a stub if everything in it is.
    fn stub_one(&self, child: &[u8], st: &Stat) -> io::Result<Stub> {
        if child.strip_prefix(b"etc/").is_some_and(etc_mount) {
            return Ok(Stub::Is(true));
        }
        if self.below(child)?.is_some() {
            return Ok(Stub::Is(false));
        }
        if self.targets.contains(child) {
            return Ok(Stub::Is(if st.is_dir() { sorted_names(&self.upath(child))?.is_empty() } else { st.kind() == libc::S_IFREG && st.size == 0 }));
        }
        let prefix = [child, b"/"].concat();
        if !st.is_dir() || !self.targets.iter().any(|t| t.starts_with(&prefix)) {
            return Ok(Stub::Is(false));
        }
        Ok(Stub::IfAll(sorted_names(&self.upath(child))?))
    }

    /// What Rosetta's runtime made in the step (see `rosetta`), none of it
    /// in the layers below: a `<home>/.cache/rosetta` folder with nothing
    /// but its `*.flu` files, a `<home>/.cache` that holds only that, and a
    /// `/tmp/rosetta.<pid>.<uid>` file.
    fn rosetta_made(&self, child: &[u8], st: &Stat) -> io::Result<bool> {
        if self.below(child)?.is_some() {
            return Ok(false);
        }
        if super::rosetta::is_tmp_file(child) {
            return Ok(!st.is_dir());
        }
        if !st.is_dir() {
            return Ok(false);
        }
        if super::rosetta::is_cache_folder(child) {
            for n in sorted_names(&self.upath(child))? {
                let m = Stat::from(&fs::symlink_metadata(self.upath(&join(child, &n)))?);
                if !super::rosetta::is_flu(&n) || m.kind() != libc::S_IFREG {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        if super::rosetta::is_cache_parent(child) && sorted_names(&self.upath(child))? == [b"rosetta".to_vec()] {
            let c = join(child, b"rosetta");
            let m = Stat::from(&fs::symlink_metadata(self.upath(&c))?);
            return self.rosetta_made(&c, &m);
        }
        Ok(false)
    }

    /// The folder `dir` that held something Rosetta made: when the layers
    /// below have it and the step changed nothing else in it (every other
    /// name in the upper is a copy of one below, none new or deleted), its
    /// time goes back to the one below once cleaned. Otherwise the step's
    /// own change set it, and it keeps the time the step left.
    fn rosetta_parent(&mut self, dir: &[u8]) -> io::Result<()> {
        let Some((b, _)) = self.below(dir)? else { return Ok(()) };
        if self.stubs.rosetta_times.iter().any(|(r, ..)| r == dir) {
            return Ok(());
        }
        for n in sorted_names(&self.upath(dir))? {
            let c = join(dir, &n);
            let m = Stat::from(&fs::symlink_metadata(self.upath(&c))?);
            if self.rosetta_made(&c, &m)? {
                continue;
            }
            if m.is_whiteout() || self.below(&c)?.is_none() {
                return Ok(());
            }
        }
        self.stubs.rosetta_times.push((dir.to_vec(), b.mtime, b.mtime_ns));
        Ok(())
    }

    /// BuildKit's `sameDirent`.
    ///
    /// Notice: this function follows the order of decisions of `sameDirent`
    /// in BuildKit `util/overlay/overlay_linux.go` (stat, capabilities,
    /// folder, size and mtime seconds, nanoseconds, symlink target, empty
    /// file, content), so it is a changed version of that code and not the
    /// original. BuildKit is Copyright The BuildKit Authors, licensed under
    /// the Apache License 2.0. Licence texts and upstream notices are in
    /// NOTICE, section "Code ported into Kiri".
    fn same(&self, b: &Stat, bfd: &OwnedFd, u: &Stat, upath: &Path, ucpath: &CString) -> io::Result<bool> {
        if b.mode != u.mode || b.uid != u.uid || b.gid != u.gid || b.rdev != u.rdev {
            return Ok(false);
        }
        let below = CString::new(format!("/proc/self/fd/{}", bfd.as_raw_fd()))?;
        if xattr(&below, c"security.capability", true)? != xattr(ucpath, c"security.capability", false)? {
            return Ok(false);
        }
        if u.is_dir() {
            return Ok(true);
        }
        if b.size != u.size || b.mtime != u.mtime {
            return Ok(false);
        }
        if b.mtime_ns != 0 || u.mtime_ns != 0 {
            return Ok(b.mtime_ns == u.mtime_ns);
        }
        if u.kind() == libc::S_IFLNK {
            let mut buf = vec![0u8; 4096];
            // SAFETY: readlinkat of the descriptor itself ("" with an O_PATH fd), into buf.
            let n = unsafe { libc::readlinkat(bfd.as_raw_fd(), c"".as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
            sys::check(n as _, "readlink below")?;
            buf.truncate(n as usize);
            return Ok(fs::read_link(upath)?.as_os_str().as_bytes() == buf);
        }
        if u.size == 0 || u.kind() != libc::S_IFREG {
            return Ok(true);
        }
        let mut theirs = fs::File::open(format!("/proc/self/fd/{}", bfd.as_raw_fd()))?;
        let mut ours = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY).open(upath)?;
        let (mut a, mut c) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
        loop {
            let n = read_full(&mut ours, &mut a)?;
            let m = read_full(&mut theirs, &mut c)?;
            if n != m || a[..n] != c[..m] {
                return Ok(false);
            }
            if n == 0 {
                return Ok(true);
            }
        }
    }

    /// A path of the layers below that the step removed.
    fn delete(&mut self, child: &[u8]) -> io::Result<()> {
        let name = join(parent(child), &[b".wh.", child.rsplit(|b| *b == b'/').next().unwrap_or_default()].concat());
        self.parents(&name)?;
        self.head.clear();
        layertar::header(&mut self.head, &Entry::whiteout(&name));
        self.out.write_all(&self.head)
    }

    /// containerd's `includeParents`: the folders above `name` not written
    /// yet, outermost first, each with its upper stat. Gathered from the
    /// nearest up, then written from the top: no recursion per level.
    fn parents(&mut self, name: &[u8]) -> io::Result<()> {
        let mut missing: Vec<Vec<u8>> = Vec::new();
        let mut p = parent(name);
        while !p.is_empty() && !self.dirs.contains(p) {
            missing.push(p.to_vec());
            p = parent(p);
        }
        for p in missing.into_iter().rev() {
            let path = self.upath(&p);
            let st = Stat::from(&fs::metadata(&path)?);
            self.emit(&p, &st, &sys::cstr(&path)?)?;
        }
        Ok(())
    }

    fn emit(&mut self, rel: &[u8], st: &Stat, cpath: &CString) -> io::Result<()> {
        let (kind, mut link) = match st.kind() {
            libc::S_IFSOCK => return Ok(()),
            libc::S_IFDIR => (Kind::Dir, Vec::new()),
            libc::S_IFLNK => (Kind::Symlink, fs::read_link(self.upath(rel))?.into_os_string().into_vec()),
            libc::S_IFCHR => (Kind::Char, Vec::new()),
            libc::S_IFBLK => (Kind::Block, Vec::new()),
            libc::S_IFIFO => (Kind::Fifo, Vec::new()),
            _ => (Kind::File, Vec::new()),
        };
        self.parents(rel)?;
        let name = if kind == Kind::Dir { [rel, b"/"].concat() } else { rel.to_vec() };
        let mut kind = kind;
        let mut size = if kind == Kind::File { st.size } else { 0 };
        if kind != Kind::Dir && st.nlink > 1 {
            match self.links.get(&(st.dev, st.ino)) {
                Some(first) => {
                    (kind, link, size) = (Kind::HardLink, first.clone(), 0);
                }
                None => {
                    self.links.insert((st.dev, st.ino), name.clone());
                }
            }
        }
        let cap = xattr(cpath, c"security.capability", false)?;
        let records: Vec<(&str, &[u8])> = if cap.is_empty() { Vec::new() } else { vec![("SCHILY.xattr.security.capability", &cap[..])] };
        let e = Entry {
            name: &name,
            kind,
            link: &link,
            mode: st.mode & 0o7777,
            uid: u64::from(st.uid),
            gid: u64::from(st.gid),
            size,
            mtime: st.mtime,
            devmajor: libc::major(st.rdev),
            devminor: libc::minor(st.rdev),
            records: &records,
        };
        self.head.clear();
        layertar::header(&mut self.head, &e);
        self.out.write_all(&self.head)?;
        if kind == Kind::Dir {
            self.dirs.insert(rel.to_vec());
        }
        if size > 0 {
            let mut f = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY).open(self.upath(rel))?;
            let n = io::copy(&mut (&mut f).take(size), &mut self.out)?;
            if n != size {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("/{} got shorter while it was read", String::from_utf8_lossy(rel))));
            }
            self.out.write_all(&[0u8; layertar::BLOCK][..layertar::padding(size)])?;
        }
        Ok(())
    }
}

fn read_full(f: &mut fs::File, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn is_opaque(path: &CString) -> io::Result<bool> {
    for attr in [c"trusted.overlay.opaque", c"user.overlay.opaque"] {
        if xattr(path, attr, false)? == b"y" {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// A step whose program did not run under Rosetta.
    fn write(upper: &Path, base: Option<&Base>, mounts: &[&[u8]], out: impl Write) -> io::Result<Stubs> {
        write_step(upper, base, mounts, false, out)
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kiri-stepdiff-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("upper")).unwrap();
        fs::create_dir_all(d.join("below")).unwrap();
        d
    }

    fn root() -> bool {
        // SAFETY: a plain getter.
        unsafe { libc::geteuid() == 0 }
    }

    /// The stubs' clean-up works inside the upper folder only: a stub
    /// whose folder the step (or something it left running) turned into a
    /// symlink to elsewhere is left alone, and nothing outside is removed,
    /// re-timed or read. It went by path before, through the link.
    #[test]
    fn stub_clean_up_never_leaves_the_upper_folder() {
        let d = scratch("stub-confined");
        let (u, out) = (d.join("upper"), d.join("outside"));
        fs::create_dir_all(out.join("dir")).unwrap();
        fs::write(out.join("x"), "keep").unwrap();
        set_mtime(&out, 1_000_000_000, 0);
        set_mtime(&out.join("dir"), 1_000_000_000, 0);
        symlink(&out, u.join("a")).unwrap();
        fs::create_dir_all(u.join("b")).unwrap();
        fs::write(u.join("b/stub"), "").unwrap();
        let stubs = Stubs {
            remove: vec![b"a/x".to_vec(), b"a/dir".to_vec(), b"b/stub".to_vec()],
            touched: vec![b"a/dir".to_vec()],
            rosetta_times: vec![(b"a/dir".to_vec(), 5, 0)],
        };
        stubs.clean(&u).unwrap();
        assert_eq!(fs::read_to_string(out.join("x")).unwrap(), "keep", "removed through the link");
        assert!(out.join("dir").is_dir(), "removed through the link");
        assert!(!u.join("b/stub").exists(), "a real stub goes");
        assert_eq!(fs::metadata(out.join("dir")).unwrap().mtime(), 1_000_000_000, "re-timed through the link");
        assert_eq!(fs::metadata(&out).unwrap().mtime(), 1_000_000_000);
        assert!(stubs.folder_times(&u).is_err(), "a time read through the link");
        fs::remove_dir_all(&d).unwrap();
    }

    fn set_mtime(p: &Path, secs: i64, nsec: i64) {
        let c = sys::cstr(p).unwrap();
        let t = [libc::timespec { tv_sec: secs, tv_nsec: nsec }, libc::timespec { tv_sec: secs, tv_nsec: nsec }];
        // SAFETY: valid path and two timespecs.
        assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), t.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }, 0);
    }

    fn set_xattr(p: &Path, name: &std::ffi::CStr, v: &[u8]) -> bool {
        let c = sys::cstr(p).unwrap();
        // SAFETY: valid path, name and value.
        unsafe { libc::lsetxattr(c.as_ptr(), name.as_ptr(), v.as_ptr().cast(), v.len(), 0) == 0 }
    }

    /// (name, typeflag, mode, size, link, body) of each entry.
    fn entries(tar_bytes: &[u8]) -> Vec<(String, u8, u32, u64, String, Vec<u8>)> {
        assert_eq!(tar_bytes.len() % 512, 0);
        assert_eq!(&tar_bytes[tar_bytes.len() - 1024..], &[0u8; 1024][..], "ends with two zero blocks");
        let mut a = tar::Archive::new(tar_bytes);
        a.entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let name = String::from_utf8_lossy(&e.path_bytes()).into_owned();
                let h = e.header().clone();
                let link = e.link_name_bytes().map(|l| String::from_utf8_lossy(&l).into_owned()).unwrap_or_default();
                let mut body = Vec::new();
                e.read_to_end(&mut body).unwrap();
                (name, h.entry_type().as_byte(), h.mode().unwrap(), h.size().unwrap(), link, body)
            })
            .collect()
    }

    fn diff(d: &Path, with_below: bool) -> io::Result<Vec<u8>> {
        let base = with_below.then(|| Base::open(&d.join("below")).unwrap());
        let mut out = Vec::new();
        write(&d.join("upper"), base.as_ref(), &[], &mut out).map(drop)?;
        Ok(out)
    }

    #[test]
    fn a_new_tree_is_written_depth_first_in_byte_order_with_folders_slashed() {
        let d = scratch("new");
        let u = d.join("upper");
        fs::create_dir_all(u.join("a/b")).unwrap();
        fs::write(u.join("a/b/f"), b"hello").unwrap();
        fs::write(u.join("a-z"), b"x").unwrap();
        fs::write(u.join("B"), b"").unwrap();
        symlink("/etc/passwd", u.join("a/link")).unwrap();
        fs::set_permissions(u.join("a/b/f"), fs::Permissions::from_mode(0o4755)).unwrap();
        let got = entries(&diff(&d, false).unwrap());
        let names: Vec<&str> = got.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names, ["B", "a/", "a/b/", "a/b/f", "a/link", "a-z"]);
        let f = &got[3];
        assert_eq!((f.1, f.2, f.3, &f.5[..]), (b'0', 0o4755, 5, &b"hello"[..]));
        assert_eq!((got[4].1, got[4].4.as_str()), (b'2', "/etc/passwd"));
        assert_eq!(got[1].1, b'5');
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn what_is_the_same_below_is_left_out_but_its_folder_comes_with_a_change() {
        let d = scratch("same");
        for side in ["upper", "below"] {
            let s = d.join(side);
            fs::create_dir_all(s.join("usr/lib")).unwrap();
            fs::write(s.join("usr/lib/same"), b"abc").unwrap();
            set_mtime(&s.join("usr/lib/same"), 1_600_000_000, 5);
            // Whole-second times on both: the bytes decide.
            fs::write(s.join("usr/lib/bytes"), if side == "upper" { b"new" } else { b"old" }).unwrap();
            set_mtime(&s.join("usr/lib/bytes"), 1_600_000_000, 0);
            fs::write(s.join("usr/lib/samebytes"), b"keep").unwrap();
            set_mtime(&s.join("usr/lib/samebytes"), 1_600_000_000, 0);
        }
        let got = entries(&diff(&d, true).unwrap());
        let names: Vec<&str> = got.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names, ["usr/", "usr/lib/", "usr/lib/bytes"]);
        let _ = fs::remove_dir_all(&d);

        // Nothing changed: an empty layer, the two end blocks alone.
        let d = scratch("same-all");
        for side in ["upper", "below"] {
            fs::create_dir_all(d.join(side).join("usr")).unwrap();
            set_mtime(&d.join(side).join("usr"), 1_600_000_000, 0);
        }
        assert_eq!(diff(&d, true).unwrap(), vec![0u8; 1024]);
        // Nor is a folder whose mtime alone changed, as in BuildKit.
        set_mtime(&d.join("upper/usr"), 1_700_000_000, 0);
        assert_eq!(diff(&d, true).unwrap(), vec![0u8; 1024]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_hard_link_carries_the_body_once() {
        let d = scratch("links");
        let u = d.join("upper");
        fs::write(u.join("a"), b"body").unwrap();
        fs::hard_link(u.join("a"), u.join("b")).unwrap();
        let got = entries(&diff(&d, false).unwrap());
        assert_eq!((got[0].0.as_str(), got[0].1, got[0].3), ("a", b'0', 4));
        assert_eq!((got[1].0.as_str(), got[1].1, got[1].3, got[1].4.as_str()), ("b", b'1', 0, "a"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_name_starting_wh_from_the_step_is_refused() {
        let d = scratch("wh");
        fs::create_dir_all(d.join("upper/x")).unwrap();
        fs::write(d.join("upper/x/.wh.y"), b"").unwrap();
        let err = diff(&d, false).unwrap_err();
        assert!(err.to_string().starts_with(REFUSED), "{err}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn the_runtimes_mount_points_are_left_out() {
        let d = scratch("stubs");
        let u = d.join("upper");
        fs::create_dir_all(u.join("etc")).unwrap();
        fs::create_dir_all(u.join("proc")).unwrap();
        fs::write(u.join("etc/hosts"), b"").unwrap();
        fs::write(u.join("etc/resolv.conf"), b"").unwrap();
        fs::write(u.join("app"), b"x").unwrap();
        let got = entries(&diff(&d, false).unwrap());
        // /proc stays, as runc's mount point does in BuildKit.
        assert_eq!(got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["app", "proc/"]);
        // An /etc with something of the step's own stays, without the stubs.
        fs::write(u.join("etc/motd"), b"hi").unwrap();
        let got = entries(&diff(&d, false).unwrap());
        assert_eq!(got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["app", "etc/", "etc/motd", "proc/"]);
        let _ = fs::remove_dir_all(&d);
    }

    /// An image's /etc that only the runtime's stubs touched: the layer
    /// leaves it out (only its time changed), and once the stubs are gone
    /// the kept folder has the time the step left, not the image's, as
    /// BuildKit's stub cleaner and snapshot have it (a COPY
    /// --from=0 / / sees the step's time on /etc).
    #[test]
    fn a_folder_only_the_stubs_touched_keeps_the_steps_time() {
        let d = scratch("stubtime");
        let u = d.join("upper");
        fs::create_dir_all(d.join("below/etc")).unwrap();
        fs::write(d.join("below/etc/hosts"), b"127.0.0.1 localhost\n").unwrap();
        set_mtime(&d.join("below/etc"), 1_500_000_000, 0);
        fs::create_dir_all(u.join("etc")).unwrap();
        fs::write(u.join("etc/resolv.conf"), b"").unwrap();
        fs::write(u.join("my-urandom"), b"").unwrap();
        set_mtime(&u.join("etc"), 1_700_000_000, 5);
        let base = Base::open(&d.join("below")).unwrap();
        let mut out = Vec::new();
        let stubs = write(&u, Some(&base), &[], &mut out).unwrap();
        assert_eq!(entries(&out).iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["my-urandom"]);
        assert_eq!(stubs.remove, [b"etc/resolv.conf".to_vec()]);
        stubs.clean(&u).unwrap();
        assert!(!u.join("etc/resolv.conf").exists());
        let m = fs::metadata(u.join("etc")).unwrap();
        assert_eq!((m.mtime(), m.mtime_nsec()), (1_700_000_000, 5));
        // The time the tar leaves out is sent beside it.
        assert_eq!(stubs.touched, [b"etc".to_vec()]);
        let rec = stubs.folder_times(&u).unwrap();
        assert_eq!(rec, [&3u32.to_le_bytes()[..], b"etc", &1_700_000_000i64.to_le_bytes(), &5u32.to_le_bytes()].concat());
        let _ = fs::remove_dir_all(&d);
    }

    /// The step wrote in the image's /etc beside the stubs (adduser): the
    /// layer has /etc with the step's time, and the kept folder keeps that
    /// time after the stubs go, so the next layers agree with BuildKit's.
    #[test]
    fn a_folder_the_step_wrote_in_keeps_the_steps_time() {
        let d = scratch("wrotetime");
        let u = d.join("upper");
        fs::create_dir_all(d.join("below/etc")).unwrap();
        fs::write(d.join("below/etc/passwd"), b"root:x:0:0::/root:/bin/sh\n").unwrap();
        set_mtime(&d.join("below/etc"), 1_500_000_000, 0);
        fs::create_dir_all(u.join("etc")).unwrap();
        fs::write(u.join("etc/resolv.conf"), b"").unwrap();
        fs::write(u.join("etc/hosts"), b"").unwrap();
        fs::write(u.join("etc/passwd"), b"root:x:0:0::/root:/bin/sh\napp:x:1234:1234::/home/app:/bin/sh\n").unwrap();
        set_mtime(&u.join("etc"), 1_700_000_000, 0);
        let base = Base::open(&d.join("below")).unwrap();
        let mut out = Vec::new();
        let stubs = write(&u, Some(&base), &[], &mut out).unwrap();
        assert_eq!(entries(&out).iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["etc/", "etc/passwd"]);
        let mut a = tar::Archive::new(&out[..]);
        let first = a.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(first.header().mtime().unwrap(), 1_700_000_000);
        stubs.clean(&u).unwrap();
        let m = fs::metadata(u.join("etc")).unwrap();
        assert_eq!((m.mtime(), m.mtime_nsec()), (1_700_000_000, 0));
        assert!(u.join("etc/passwd").exists() && !u.join("etc/hosts").exists());
        let _ = fs::remove_dir_all(&d);
    }

    /// A mount target the runtime made, and the folders it made above it,
    /// stay out; a target with the step's own files, or one the image
    /// had, is the step's.
    #[test]
    fn mount_targets_made_for_the_step_are_left_out() {
        use std::os::unix::fs::MetadataExt;
        let d = scratch("targets");
        let u = d.join("upper");
        fs::create_dir_all(d.join("below/t")).unwrap();
        fs::create_dir_all(u.join("t/tmpfs")).unwrap();
        fs::create_dir_all(u.join("t/sub/cache")).unwrap();
        fs::create_dir_all(u.join("run/secrets")).unwrap();
        fs::write(u.join("run/secrets/s"), b"").unwrap();
        let mounts: [&[u8]; 3] = [b"/t/tmpfs", b"/t/sub/cache", b"/run/secrets/s"];
        let base = Base::open(&d.join("below")).unwrap();
        let mut out = Vec::new();
        write(&u, Some(&base), &mounts, &mut out).unwrap();
        // /t is the image's and only its mtime changed: nothing at all.
        assert_eq!(out, vec![0u8; 1024]);
        // Cleaned, the upper holds what the tar holds; /t keeps the time the
        // step's stubs gave it, not the image's, as BuildKit's snapshot does.
        set_mtime(&d.join("below/t"), 1_500_000_000, 7);
        set_mtime(&u.join("t"), 1_700_000_000, 3);
        let stubs = write(&u, Some(&base), &mounts, &mut Vec::new()).unwrap();
        assert_eq!(stubs.remove, [b"run".to_vec(), b"t/sub".to_vec(), b"t/tmpfs".to_vec()]);
        stubs.clean(&u).unwrap();
        assert!(!u.join("run").exists() && !u.join("t/sub").exists() && !u.join("t/tmpfs").exists());
        let m = fs::metadata(u.join("t")).unwrap();
        assert_eq!((m.mtime(), m.mtime_nsec()), (1_700_000_000, 3));
        fs::create_dir_all(u.join("t/sub/cache")).unwrap();
        fs::write(u.join("t/sub/mine"), b"x").unwrap();
        let mut out = Vec::new();
        write(&u, Some(&base), &mounts, &mut out).unwrap();
        assert_eq!(entries(&out).iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["t/", "t/sub/", "t/sub/mine"]);
        let _ = fs::remove_dir_all(&d);
    }

    fn rosetta_layer(u: &Path, base: &Base) -> (Vec<String>, Stubs) {
        let mut out = Vec::new();
        let stubs = write_step(u, Some(base), &[], true, &mut out).unwrap();
        (entries(&out).into_iter().map(|e| e.0).collect(), stubs)
    }

    /// What Rosetta made in an amd64 step (see `rosetta`) is not in its
    /// layer, wherever HOME was, and the homes keep the image's mtime.
    #[test]
    fn what_rosetta_made_in_an_amd64_step_is_left_out() {
        use std::os::unix::fs::MetadataExt;
        let d = scratch("rosetta");
        let u = d.join("upper");
        for p in ["root", "home/app", "tmp"] {
            fs::create_dir_all(d.join("below").join(p)).unwrap();
            set_mtime(&d.join("below").join(p), 1_793_870_342, 5);
        }
        fs::create_dir_all(u.join("root/.cache/rosetta")).unwrap();
        fs::create_dir_all(u.join("home/app/.cache/rosetta")).unwrap();
        fs::write(u.join("home/app/.cache/rosetta/0ced6549d448d1bd719c6202a33ca024.flu"), b"t").unwrap();
        // A HOME the step set itself, under a folder the step made.
        fs::create_dir_all(u.join("work/.cache/rosetta")).unwrap();
        fs::create_dir_all(u.join("tmp")).unwrap();
        fs::write(u.join("tmp/rosetta.42.0"), b"").unwrap();
        fs::write(u.join("out"), b"x").unwrap();
        let base = Base::open(&d.join("below")).unwrap();
        let (got, stubs) = rosetta_layer(&u, &base);
        assert_eq!(got, ["out", "work/"]);
        stubs.clean(&u).unwrap();
        for p in ["root/.cache", "home/app/.cache", "work/.cache", "tmp/rosetta.42.0"] {
            assert!(!u.join(p).exists(), "{p}");
        }
        for p in ["root", "home/app", "tmp"] {
            let m = fs::metadata(u.join(p)).unwrap();
            assert_eq!((m.mtime(), m.mtime_nsec()), (1_793_870_342, 5), "{p}");
        }
        // Without the mark the same tree is the step's.
        let mut out = Vec::new();
        fs::create_dir_all(u.join("root/.cache/rosetta")).unwrap();
        write(&u, Some(&base), &[], &mut out).unwrap();
        assert!(entries(&out).iter().any(|e| e.0 == "root/.cache/rosetta/"));
        let _ = fs::remove_dir_all(&d);
    }

    /// A home the step also wrote in keeps the time the step left, as any
    /// folder with the step's own change does.
    #[test]
    fn a_home_the_step_wrote_in_keeps_the_steps_time() {
        use std::os::unix::fs::MetadataExt;
        let d = scratch("rosetta-time");
        let u = d.join("upper");
        fs::create_dir_all(d.join("below/root")).unwrap();
        set_mtime(&d.join("below/root"), 1_793_870_342, 0);
        fs::create_dir_all(u.join("root/.cache/rosetta")).unwrap();
        fs::write(u.join("root/notes"), b"n").unwrap();
        set_mtime(&u.join("root"), 1_800_000_000, 0);
        let base = Base::open(&d.join("below")).unwrap();
        let (got, stubs) = rosetta_layer(&u, &base);
        assert_eq!(got, ["root/", "root/notes"]);
        stubs.clean(&u).unwrap();
        assert!(!u.join("root/.cache").exists());
        assert_eq!(fs::metadata(u.join("root")).unwrap().mtime(), 1_800_000_000);
        let _ = fs::remove_dir_all(&d);
    }

    /// What the step's own commands wrote in its .cache stays (pip's cache
    /// beside Rosetta's folder, a file of its own in that folder), and a
    /// folder the image had is the image's, `.flu` files and all.
    #[test]
    fn what_the_step_wrote_beside_rosettas_folder_stays() {
        let d = scratch("rosetta-own");
        let u = d.join("upper");
        fs::create_dir_all(d.join("below/root")).unwrap();
        fs::create_dir_all(d.join("below/srv/.cache/rosetta")).unwrap();
        fs::create_dir_all(u.join("root/.cache/rosetta")).unwrap();
        fs::create_dir_all(u.join("root/.cache/pip")).unwrap();
        fs::write(u.join("root/.cache/pip/wheel"), b"w").unwrap();
        fs::create_dir_all(u.join("home/app/.cache/rosetta")).unwrap();
        fs::write(u.join("home/app/.cache/rosetta/keep"), b"mine").unwrap();
        fs::create_dir_all(u.join("srv/.cache/rosetta")).unwrap();
        fs::write(u.join("srv/.cache/rosetta/a.flu"), b"t").unwrap();
        fs::write(u.join("tmp-not"), b"").unwrap();
        let base = Base::open(&d.join("below")).unwrap();
        let (got, _) = rosetta_layer(&u, &base);
        assert_eq!(
            got,
            [
                "home/",
                "home/app/",
                "home/app/.cache/",
                "home/app/.cache/rosetta/",
                "home/app/.cache/rosetta/keep",
                "root/",
                "root/.cache/",
                "root/.cache/pip/",
                "root/.cache/pip/wheel",
                "srv/",
                "srv/.cache/",
                "srv/.cache/rosetta/",
                "srv/.cache/rosetta/a.flu",
                "tmp-not",
            ]
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// `user.overlay.opaque` (an unprivileged overlay's marker) works for
    /// anyone; the kernel's own `trusted.` one needs root.
    #[test]
    fn an_opaque_folder_becomes_one_whiteout_per_name_gone() {
        let d = scratch("opaque");
        fs::create_dir_all(d.join("below/data/old")).unwrap();
        fs::write(d.join("below/data/a"), b"1").unwrap();
        fs::write(d.join("below/data/old/deep"), b"1").unwrap();
        fs::write(d.join("below/data/z"), b"1").unwrap();
        fs::create_dir_all(d.join("upper/data")).unwrap();
        fs::write(d.join("upper/data/b"), b"2").unwrap();
        if !set_xattr(&d.join("upper/data"), c"user.overlay.opaque", b"y") {
            eprintln!("skipped: no user xattrs here");
            return;
        }
        let got = entries(&diff(&d, true).unwrap());
        let names: Vec<&str> = got.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names, ["data/", "data/.wh.a", "data/b", "data/.wh.old", "data/.wh.z"]);
        let wh = &got[1];
        assert_eq!((wh.1, wh.2, wh.3), (b'0', 0, 0));
        assert!(!names.iter().any(|n| n.contains(".wh..wh..opq")));
        let _ = fs::remove_dir_all(&d);
    }

    /// A removed path is a 0/0 character device in the upper: `.wh.` where
    /// the layers below have it, nothing where they do not.
    #[test]
    fn whiteouts_name_only_what_was_below() {
        if !root() {
            eprintln!("skipped: needs root for mknod");
            return;
        }
        let d = scratch("whiteout");
        fs::create_dir_all(d.join("below/etc")).unwrap();
        fs::write(d.join("below/etc/gone"), b"x").unwrap();
        fs::create_dir_all(d.join("upper/etc")).unwrap();
        for n in ["gone", "never"] {
            sys::mknod(&sys::cstr(d.join("upper/etc").join(n)).unwrap(), libc::S_IFCHR, 0, 0).unwrap();
        }
        let got = entries(&diff(&d, true).unwrap());
        assert_eq!(got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(), ["etc/", "etc/.wh.gone"]);
        let _ = fs::remove_dir_all(&d);
    }

    /// The layers below are looked into with their links kept inside them.
    #[test]
    fn links_below_do_not_lead_the_comparison_outside() {
        let d = scratch("escape");
        let outside = d.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("f"), b"same").unwrap();
        set_mtime(&outside.join("f"), 1_600_000_000, 7);
        symlink(&outside, d.join("below/lib")).unwrap();
        fs::create_dir_all(d.join("upper/lib")).unwrap();
        fs::write(d.join("upper/lib/f"), b"same").unwrap();
        set_mtime(&d.join("upper/lib/f"), 1_600_000_000, 7);
        let got = entries(&diff(&d, true).unwrap());
        // Through the link's absolute target `lib/f` would look unchanged.
        assert!(got.iter().any(|e| e.0 == "lib/f"), "{got:?}");
        let _ = fs::remove_dir_all(&d);
    }

    /// `root/d/.../d/f` with `depth` folders, made and removed by path a
    /// level at a time (no recursion in the test either).
    fn deep(root: &Path, depth: usize, body: &[u8]) {
        let mut p = root.to_path_buf();
        for _ in 0..depth {
            p.push("d");
            fs::create_dir(&p).unwrap();
        }
        fs::write(p.join("f"), body).unwrap();
    }

    fn remove_deep(root: &Path, depth: usize) {
        let mut p = root.join("d/".repeat(depth));
        let _ = fs::remove_file(p.join("f"));
        for _ in 0..depth {
            let _ = fs::remove_dir(&p);
            p.pop();
        }
    }

    /// The step left a tree 1000 folders deep: the layer is written on a
    /// thread with an ordinary stack (2 MiB), every folder in it. Below,
    /// the same tree with another body: only the file and its folders.
    #[test]
    fn a_tree_1000_folders_deep_is_written_on_an_ordinary_stack() {
        let d = scratch("deep");
        deep(&d.join("upper"), 1000, b"new");
        deep(&d.join("below"), 1000, b"old");
        let dd = d.clone();
        let (alone, over) = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || (entries(&diff(&dd, false).unwrap()), entries(&diff(&dd, true).unwrap())))
            .unwrap()
            .join()
            .unwrap();
        for got in [&alone, &over] {
            assert_eq!(got.len(), 1001);
            let last = got.last().unwrap();
            assert_eq!(last.0, format!("{}f", "d/".repeat(1000)));
            assert_eq!(last.5, b"new");
        }
        for side in ["upper", "below"] {
            remove_deep(&d.join(side), 1000);
        }
        let _ = fs::remove_dir_all(&d);
    }
}
