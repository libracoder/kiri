//! Kiri's own builder's caches in `docker builder prune`, `docker system
//! prune` and `docker system df`, beside BuildKit's (builder.rs): the step
//! cache's entries and their layers in the image store, the layers the step
//! cache named once and names no more, and the folders of `RUN
//! --mount=type=cache`, where this machine can reach them (a Linux host,
//! whose guest is a process of it).
//!
//! They are shown and pruned as BuildKit's records are: type `regular` for
//! a step and its layer, `exec.cachemount` for a cache folder; `all`,
//! `until`/`unused-for`, `keep-storage`, `type`, `id`, `description` and
//! `inuse`/`shared`/`private` apply as they do to BuildKit's. A layer an
//! image names is `Shared` and stays: pruning such a step (with `all`)
//! removes only its entry. A layer is removed through the store, which
//! keeps any blob an image names or a running build holds; a cache folder
//! a running step uses is never removed.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use kiri_forge::cache::{CacheKey, StepCache};
use kiri_forge::ports::Digest;

use super::engine::Error;
use super::filters::Filters;
use super::http::Request;

/// Given a test of whether a step uses the cache folder of a name now.
pub type Visitor<'v> = dyn FnMut(&dyn Fn(&str) -> bool) + 'v;
/// Calls a [`Visitor`]; no step starts using a folder meanwhile.
pub type Gate = dyn Fn(&mut Visitor<'_>);

/// The cache folders of `RUN --mount=type=cache`, on this machine's disk.
pub struct Mounts<'a> {
    pub root: PathBuf,
    pub gate: &'a Gate,
}

/// What prune and df look at.
pub struct Caches<'a> {
    pub steps: &'a StepCache,
    pub store: &'a kiri_image::Store,
    pub mounts: Option<Mounts<'a>>,
}

/// Which records a prune takes, from its query and filters.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Selection {
    pub all: bool,
    /// Kept: what was used after this (Unix seconds).
    pub cut: Option<f64>,
    /// Removes the least recently used until the rest takes no more.
    pub keep: Option<u64>,
    pub kind: Option<String>,
    pub id: Option<String>,
    pub description: Option<String>,
    /// A `parent` filter: none of these records has one.
    pub parent: bool,
    pub inuse: bool,
    pub shared: bool,
    pub private: bool,
}

impl Selection {
    /// Read from a `/build/prune` whose filters builder.rs has checked.
    pub fn of(req: &Request, f: &Filters) -> Result<Selection, Error> {
        let one = |k: &str| f.values(k).and_then(|v| v.first()).cloned();
        let flag = |k: &str| f.bool(k) == Some(true) || f.values(k).is_some_and(|v| v.iter().any(String::is_empty));
        let mut cut = None;
        for key in ["until", "unused-for"] {
            if let Some(c) = super::ops::prune_until(f, key)? {
                cut = Some(c);
            }
        }
        let bytes = |k: &str| req.query(k).and_then(|v| v.parse::<u64>().ok()).filter(|v| *v > 0);
        Ok(Selection {
            all: req.flag("all"),
            cut,
            keep: bytes("keep-storage").or_else(|| bytes("max-used-space")),
            kind: one("type"),
            id: one("id"),
            description: one("description"),
            parent: f.values("parent").is_some(),
            inuse: flag("inuse"),
            shared: flag("shared"),
            private: flag("private"),
        })
    }
}

#[derive(Debug, Clone)]
enum What {
    Step(CacheKey, Option<Digest>),
    Retired(Digest),
    Mount(String),
}

#[derive(Debug, Clone)]
struct Item {
    id: String,
    kind: &'static str,
    description: String,
    size: u64,
    shared: bool,
    in_use: bool,
    created: Option<i64>,
    last_used: Option<i64>,
    what: What,
}

impl Item {
    /// When it was last used, as prune's `until` and `keep-storage` order
    /// it: one with no time counts as oldest.
    fn age_key(&self) -> i64 {
        self.last_used.or(self.created).unwrap_or(0)
    }

    fn selected(&self, s: &Selection) -> bool {
        if self.in_use || s.inuse || s.parent || (!s.all && self.shared) {
            return false;
        }
        (!s.shared || self.shared)
            && (!s.private || !self.shared)
            && s.kind.as_deref().is_none_or(|k| k == self.kind)
            && s.id.as_deref().is_none_or(|i| self.id.contains(i))
            && s.description.as_deref().is_none_or(|d| d == self.description)
            && s.cut.is_none_or(|c| (self.age_key() as f64) <= c)
    }
}

fn secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn hex_of(d: &Digest) -> &str {
    d.as_str().strip_prefix("sha256:").unwrap_or(d.as_str())
}

/// The blob of a layer made here (its digest is its diff_id), if the store
/// has one: its size.
fn blob_size(store: &kiri_image::Store, layer: &Digest) -> Option<u64> {
    std::fs::metadata(store.blob_path(layer.as_str()).ok()?).ok().filter(std::fs::Metadata::is_file).map(|m| m.len())
}

fn items(c: &Caches) -> Vec<Item> {
    let named: std::collections::HashSet<String> = c.store.images().unwrap_or_default().into_iter().flat_map(|i| i.layers.into_iter().map(|l| l.digest)).collect();
    let mut out = Vec::new();
    for r in c.steps.records() {
        let created = r.entry.config_change.lines().next().and_then(|l| l.strip_prefix("created=")).map(super::time::parse_unix).filter(|t| *t > 0);
        let (size, shared) = match &r.entry.layer {
            Some(l) => (blob_size(c.store, l).unwrap_or(0), named.contains(l.as_str())),
            None => (0, false),
        };
        let description = match &r.entry.layer {
            Some(l) => format!("kiri build step, layer {}", &hex_of(l)[..12]),
            None => "kiri build step, no layer".to_owned(),
        };
        out.push(Item {
            id: r.key.to_string(),
            kind: "regular",
            description,
            size,
            shared,
            in_use: false,
            created,
            last_used: r.last_used.map(|t| t as i64),
            what: What::Step(r.key, r.entry.layer),
        });
    }
    for l in c.steps.retired() {
        // One an image names is the image's now; one already gone is nothing.
        if named.contains(l.as_str()) {
            continue;
        }
        let Some(size) = blob_size(c.store, &l) else { continue };
        out.push(Item {
            id: hex_of(&l).to_owned(),
            kind: "regular",
            description: "kiri build layer no step names".to_owned(),
            size,
            shared: false,
            in_use: false,
            created: None,
            last_used: None,
            what: What::Retired(l),
        });
    }
    if let Some(m) = &c.mounts {
        let Ok(rd) = std::fs::read_dir(&m.root) else { return out };
        let mut folders: Vec<(String, std::fs::Metadata)> = rd
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                // Names the builder gives (`<hex>` or `<hex>.<n>`); never a prune's own trash.
                let ok = name.split('.').next().is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
                ok.then_some((name, e.metadata().ok().filter(std::fs::Metadata::is_dir)?))
            })
            .collect();
        folders.sort_by(|a, b| a.0.cmp(&b.0));
        let mut busy = Vec::new();
        (m.gate)(&mut |used| busy = folders.iter().map(|(n, _)| used(n)).collect());
        for ((name, meta), in_use) in folders.into_iter().zip(busy.into_iter().chain(std::iter::repeat(false))) {
            let used = meta.modified().ok().map(secs);
            out.push(Item {
                id: name.clone(),
                kind: "exec.cachemount",
                description: "kiri cache mount".to_owned(),
                size: tree_size(&m.root.join(&name)),
                shared: false,
                in_use,
                created: meta.created().ok().map(secs).or(used),
                last_used: used,
                what: What::Mount(name),
            });
        }
    }
    out
}

/// `system df`'s BuildCache rows for these caches.
pub fn rows(c: &Caches) -> Vec<Value> {
    let time = |t: Option<i64>| t.map(|s| super::time::rfc3339(UNIX_EPOCH + std::time::Duration::from_secs(s.max(0) as u64)));
    items(c)
        .into_iter()
        .map(|i| {
            json!({
                "ID": i.id, "Parent": null, "Parents": [], "Type": i.kind, "Description": i.description,
                "InUse": i.in_use, "Shared": i.shared, "Size": i.size,
                "CreatedAt": time(i.created.or(i.last_used)), "LastUsedAt": time(i.last_used), "UsageCount": u8::from(i.last_used.is_some()),
            })
        })
        .collect()
}

/// Removes what `s` selects: (ids removed, bytes freed).
pub fn prune(c: &Caches, s: &Selection) -> (Vec<String>, u64) {
    let all = items(c);
    let mut chosen: Vec<Item> = all.iter().filter(|i| i.selected(s)).cloned().collect();
    if let Some(keep) = s.keep {
        // The least recently used go first, until what stays fits.
        chosen.sort_by_key(Item::age_key);
        let mut total: u64 = all.iter().filter(|i| !i.shared).map(|i| i.size).sum();
        chosen.retain(|i| {
            if total <= keep {
                return false;
            }
            total = total.saturating_sub(i.size);
            true
        });
    }
    let (mut ids, mut freed) = (Vec::new(), 0u64);
    for i in chosen {
        let gone = match &i.what {
            What::Step(key, layer) => match c.steps.remove(&[*key]) {
                Ok(k) if !k.is_empty() => {
                    freed += layer.as_ref().filter(|_| !i.shared).map_or(0, |l| remove_layer(c, l));
                    true
                }
                _ => false,
            },
            What::Retired(l) => {
                let f = remove_layer(c, l);
                freed += f;
                f > 0
            }
            What::Mount(name) => c.mounts.as_ref().is_some_and(|m| remove_mount(m, name)).then(|| freed += i.size).is_some(),
        };
        if gone {
            ids.push(i.id);
        }
    }
    (ids, freed)
}

/// Removes a layer made here if no image names it and no build holds it:
/// the bytes freed. Once its blob is gone it is no longer listed.
fn remove_layer(c: &Caches, l: &Digest) -> u64 {
    let Some(size) = blob_size(c.store, l) else {
        let _ = c.steps.forget_retired(std::slice::from_ref(l));
        return 0;
    };
    if c.store.remove_if_unused(l.as_str()).is_err() || blob_size(c.store, l).is_some() {
        return 0;
    }
    let _ = c.steps.forget_retired(std::slice::from_ref(l));
    size
}

/// Moves a cache folder no step uses out of the builder's way (a step
/// starting after makes a new one), then deletes it.
fn remove_mount(m: &Mounts, name: &str) -> bool {
    let from = m.root.join(name);
    let to = m.root.join(format!(".pruned-{name}-{}", std::process::id()));
    let mut moved = false;
    (m.gate)(&mut |used| moved = !used(name) && std::fs::rename(&from, &to).is_ok());
    if moved {
        remove_tree(&to);
    }
    moved
}

/// Bytes of the files under `root`, walked without recursion or open
/// folders held, so a tree of any depth costs no stack.
fn tree_size(root: &Path) -> u64 {
    let mut total = 0;
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => todo.push(e.path()),
                Ok(_) => total += e.metadata().map_or(0, |m| m.len()),
                Err(_) => {}
            }
        }
    }
    total
}

/// Deletes a tree without recursion: files as found, folders once empty.
/// A folder that cannot be emptied (a path too long to name) is left.
fn remove_tree(root: &Path) {
    let mut todo = vec![(root.to_path_buf(), false)];
    while let Some((dir, listed)) = todo.pop() {
        if listed {
            let _ = std::fs::remove_dir(&dir);
            continue;
        }
        todo.push((dir.clone(), true));
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            match e.file_type() {
                Ok(t) if t.is_dir() => todo.push((e.path(), false)),
                _ => {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
}

/// Marks a cache folder used now, for prune's `until` (on a Linux host,
/// where it is on this machine's disk; elsewhere nothing).
pub fn mount_used(guest_folder: &str) {
    #[cfg(target_os = "linux")]
    if let Ok(f) = std::fs::File::open(guest_folder) {
        let _ = f.set_modified(SystemTime::now());
    }
    #[cfg(not(target_os = "linux"))]
    let _ = guest_folder;
}

#[cfg(test)]
mod tests {
    use super::*;
    use kiri_forge::cache::CacheEntry;
    use std::io::Write as _;

    struct Fixture {
        root: PathBuf,
        store: kiri_image::Store,
        steps: StepCache,
    }

    impl Fixture {
        fn new(tag: &str) -> Fixture {
            let root = std::env::temp_dir().join(format!("kiri-buildcache-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let store = kiri_image::Store::open(root.join("store")).unwrap();
            let steps = StepCache::open(&root.join("build/steps")).unwrap();
            std::fs::create_dir_all(root.join("mounts")).unwrap();
            Fixture { root, store, steps }
        }

        /// A layer made here: a plain-tar blob, its digest its diff_id.
        fn layer(&self, bytes: &[u8]) -> Digest {
            let mut w = self.store.ingest().unwrap();
            w.write_all(bytes).unwrap();
            let (d, _) = w.finish().unwrap();
            Digest::parse(&d).unwrap()
        }

        fn image_naming(&self, name: &str, layer: &Digest) {
            let cfg = self.layer(format!("{{\"rootfs\":{{\"diff_ids\":[\"{}\"]}}}}", layer.as_str()).as_bytes());
            self.store
                .put_image(kiri_image::Image {
                    name: name.into(),
                    digest: format!("sha256:{}", "1".repeat(64)),
                    index_digest: None,
                    config_digest: cfg.as_str().to_owned(),
                    layers: vec![kiri_image::Layer { digest: layer.as_str().to_owned(), size: 1, media_type: "application/vnd.oci.image.layer.v1.tar".into() }],
                    size: 0,
                    platform: "linux/amd64".into(),
                    created: String::new(),
                    pulled_at: 0,
                    config: kiri_image::RunConfig::default(),
                })
                .unwrap();
        }

        fn step(&self, n: u8, layer: Option<&Digest>, created: &str) -> CacheKey {
            let key = CacheKey([n; 32]);
            self.steps.record(key, CacheEntry { layer: layer.cloned(), config_change: format!("created={created}") }).unwrap();
            key
        }

        fn has(&self, l: &Digest) -> bool {
            self.store.blob_path(l.as_str()).unwrap().exists()
        }

        fn caches<'a>(&'a self, gate: &'a Gate) -> Caches<'a> {
            Caches { steps: &self.steps, store: &self.store, mounts: Some(Mounts { root: self.root.join("mounts"), gate }) }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn nothing_in_use(f: &mut Visitor<'_>) {
        f(&|_| false)
    }

    fn ids(v: &[Value]) -> Vec<String> {
        v.iter().map(|r| r["ID"].as_str().unwrap().to_owned()).collect()
    }

    /// df lists every step, retired layer and cache folder, with BuildKit's
    /// fields; a layer an image names is Shared.
    #[test]
    fn df_lists_steps_retired_layers_and_cache_folders() {
        let fx = Fixture::new("df");
        let mine = fx.layer(b"a step's tar");
        let theirs = fx.layer(b"a tar an image names");
        fx.image_naming("app:1", &theirs);
        let k1 = fx.step(1, Some(&mine), "2026-11-01T10:00:00Z");
        let k2 = fx.step(2, Some(&theirs), "2026-11-02T10:00:00Z");
        let k3 = fx.step(3, None, "2026-11-03T10:00:00Z");
        let old = fx.layer(b"replaced");
        let k4 = fx.step(4, Some(&old), "2026-11-04T10:00:00Z");
        fx.step(4, None, "2026-11-05T10:00:00Z");
        let folder = fx.root.join("mounts").join("a".repeat(64));
        std::fs::create_dir_all(folder.join("deep/er")).unwrap();
        std::fs::write(folder.join("deep/er/f"), vec![0u8; 3000]).unwrap();
        std::fs::create_dir_all(fx.root.join("mounts/.pruned-x")).unwrap();
        let rows = rows(&fx.caches(&nothing_in_use));
        let by = |id: &str| rows.iter().find(|r| r["ID"] == id).unwrap_or_else(|| panic!("{id} in {rows:?}")).clone();
        assert_eq!(rows.len(), 6, "{rows:?}");
        let r1 = by(&k1.to_string());
        assert_eq!((r1["Type"].as_str(), r1["Size"].as_u64(), r1["Shared"].as_bool(), r1["InUse"].as_bool()), (Some("regular"), Some(12), Some(false), Some(false)));
        assert_eq!(r1["CreatedAt"], "2026-11-01T10:00:00.000000000Z");
        assert!(r1["LastUsedAt"].is_string());
        assert_eq!(by(&k2.to_string())["Shared"], true);
        assert_eq!(by(&k3.to_string())["Size"], 0);
        assert_eq!(by(&k4.to_string())["Size"], 0, "replaced by a step with no layer");
        assert_eq!(by(hex_of(&old))["Description"], "kiri build layer no step names");
        let m = by(&"a".repeat(64));
        assert_eq!((m["Type"].as_str(), m["Size"].as_u64()), (Some("exec.cachemount"), Some(3000)));
    }

    /// A prune with no filter takes every step, layer and folder no image
    /// names and nothing uses; an image's layer and a folder in use stay.
    #[test]
    fn prune_removes_what_nothing_uses_and_keeps_the_rest() {
        let fx = Fixture::new("prune");
        let mine = fx.layer(b"a step's tar");
        let theirs = fx.layer(b"a tar an image names");
        let shared_by_two = fx.layer(b"one tar, two steps");
        fx.image_naming("app:1", &theirs);
        let k1 = fx.step(1, Some(&mine), "2026-11-01T10:00:00Z");
        let k2 = fx.step(2, Some(&theirs), "2026-11-01T10:00:00Z");
        fx.step(3, Some(&shared_by_two), "2026-11-01T10:00:00Z");
        fx.step(4, Some(&shared_by_two), "2026-11-01T10:00:00Z");
        let free = "b".repeat(64);
        let busy = "c".repeat(64);
        for f in [&free, &busy] {
            std::fs::create_dir_all(fx.root.join("mounts").join(f).join("x")).unwrap();
            std::fs::write(fx.root.join("mounts").join(f).join("x/y"), b"12345").unwrap();
        }
        let gate = |f: &mut Visitor<'_>| f(&|n: &str| n == "c".repeat(64));
        let c = fx.caches(&gate);
        let (gone, freed) = prune(&c, &Selection::default());
        assert!(gone.contains(&k1.to_string()) && gone.contains(&free), "{gone:?}");
        assert!(!gone.contains(&k2.to_string()) && !gone.contains(&busy), "shared and in use stay: {gone:?}");
        assert_eq!(freed, 12 + 18 + 5);
        assert!(!fx.has(&mine) && !fx.has(&shared_by_two));
        assert!(fx.has(&theirs), "an image's layer is never removed");
        assert!(!fx.root.join("mounts").join(&free).exists());
        assert!(fx.root.join("mounts").join(&busy).join("x/y").exists());
        assert_eq!(ids(&rows(&c)), [k2.to_string(), busy.clone()]);
        assert!(std::fs::read_dir(fx.root.join("mounts")).unwrap().count() == 1, "no trash left");
        // With `all`, the image's step goes too, its layer stays the image's.
        let (gone, freed) = prune(&c, &Selection { all: true, ..Selection::default() });
        assert_eq!((gone, freed), (vec![k2.to_string()], 0));
        assert!(fx.has(&theirs));
        assert!(fx.store.find("app:1").unwrap().is_some());
    }

    /// A layer a running build holds stays, and is offered again later.
    #[test]
    fn a_layer_a_build_holds_is_kept_for_a_later_prune() {
        let fx = Fixture::new("pinned");
        let l = fx.layer(b"held");
        let k = fx.step(1, Some(&l), "2026-11-01T10:00:00Z");
        let pin = fx.store.pin(l.as_str());
        let c = fx.caches(&nothing_in_use);
        let (gone, freed) = prune(&c, &Selection::default());
        assert_eq!((gone, freed), (vec![k.to_string()], 0), "the entry goes, the held layer stays");
        assert!(fx.has(&l));
        assert_eq!(ids(&rows(&c)), [hex_of(&l)]);
        drop(pin);
        let (gone, freed) = prune(&c, &Selection::default());
        assert_eq!((gone, freed), (vec![hex_of(&l).to_owned()], 4));
        assert!(!fx.has(&l) && rows(&c).is_empty());
    }

    /// A step cache file with these entries: (key byte, layer, last use).
    fn steps_file(path: &Path, entries: &[(u8, &Digest, u64)]) -> StepCache {
        use sha2::Digest as _;
        let mut body = String::from("kiri-build step cache 3\n");
        for (k, l, used) in entries {
            let change: String = b"created=2020-01-01T00:00:00Z".iter().map(|b| format!("{b:02x}")).collect();
            body.push_str(&format!("{} {} {change} {used}\n", CacheKey([*k; 32]), l.as_str()));
        }
        let sum: String = sha2::Sha256::digest(body.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("{body}sum {sum}\n")).unwrap();
        StepCache::open(path).unwrap()
    }

    #[test]
    fn prune_filters_choose_as_buildkits_do() {
        let fx = Fixture::new("filters");
        let (a, b) = (fx.layer(b"used later"), fx.layer(b"used earlier, longer"));
        // Key 1 was used after key 2.
        let steps = steps_file(&fx.root.join("other/steps"), &[(1, &a, 2000), (2, &b, 1000)]);
        std::fs::create_dir_all(fx.root.join("mounts").join("d".repeat(64))).unwrap();
        let c = Caches { steps: &steps, ..fx.caches(&nothing_in_use) };
        let (k1, k2) = (CacheKey([1; 32]).to_string(), CacheKey([2; 32]).to_string());
        let none = |s: Selection| assert_eq!(prune(&c, &s), (vec![], 0), "{s:?}");
        none(Selection { cut: Some(500.0), kind: Some("regular".into()), ..Selection::default() });
        none(Selection { kind: Some("source.local".into()), ..Selection::default() });
        none(Selection { inuse: true, ..Selection::default() });
        none(Selection { shared: true, ..Selection::default() });
        none(Selection { parent: true, ..Selection::default() });
        none(Selection { description: Some("x".into()), ..Selection::default() });
        none(Selection { keep: Some(1 << 30), ..Selection::default() });
        // until: what was used before the cut.
        let one = prune(&c, &Selection { cut: Some(1500.0), kind: Some("regular".into()), keep: None, ..Selection::default() });
        assert_eq!(one, (vec![k2.clone()], 20));
        let steps = steps_file(&fx.root.join("other2/steps"), &[(1, &a, 2000), (2, &fx.layer(b"used earlier, longer"), 1000)]);
        let c = Caches { steps: &steps, ..fx.caches(&nothing_in_use) };
        // keep-storage: the least recently used go first, until the rest fits.
        assert_eq!(prune(&c, &Selection { keep: Some(15), kind: Some("regular".into()), ..Selection::default() }), (vec![k2.clone()], 20));
        assert_eq!(prune(&c, &Selection { id: Some(k1[..10].to_owned()), ..Selection::default() }), (vec![k1.clone()], 10));
        let (gone, _) = prune(&c, &Selection { kind: Some("exec.cachemount".into()), private: true, ..Selection::default() });
        assert_eq!(gone, ["d".repeat(64)]);
    }

    #[test]
    fn the_prune_request_reads_as_a_selection() {
        let req = Request::internal("POST", "/build/prune", &[("all", "1"), ("keep-storage", "5000"), ("filters", r#"{"until":["1h"],"type":["exec.cachemount"],"id":["ab"],"private":[""]}"#)], Vec::new());
        let f = super::super::api::filters(&req, &["until", "type", "id", "private"]).unwrap();
        let s = Selection::of(&req, &f).unwrap();
        assert!(s.all && s.private && !s.shared && !s.inuse && !s.parent);
        assert_eq!((s.keep, s.kind.as_deref(), s.id.as_deref()), (Some(5000), Some("exec.cachemount"), Some("ab")));
        let now = secs(SystemTime::now()) as f64;
        assert!(s.cut.is_some_and(|c| (c - (now - 3600.0)).abs() < 5.0), "{s:?}");
        let plain = Request::internal("POST", "/build/prune", &[], Vec::new());
        let s = Selection::of(&plain, &super::super::api::filters(&plain, &["until"]).unwrap()).unwrap();
        assert_eq!(s, Selection::default());
    }

    #[test]
    fn a_deep_cache_folder_is_measured_and_removed_without_recursion() {
        let fx = Fixture::new("deep");
        let name = "e".repeat(64);
        let mut p = fx.root.join("mounts").join(&name);
        for _ in 0..300 {
            p.push("d");
        }
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("f"), b"xyz").unwrap();
        let c = fx.caches(&nothing_in_use);
        assert_eq!(rows(&c)[0]["Size"], 3);
        assert_eq!(prune(&c, &Selection::default()), (vec![name.clone()], 3));
        assert!(!fx.root.join("mounts").join(&name).exists());
    }
}
