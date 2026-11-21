//! Named kill points on the store's commit path, for the tests that show a
//! kill or a power cut at any of them leaves the store whole. They exist only with the `fault-inject` feature; a
//! release build has none, and `point` is an empty inline function there.
//!
//! `KIRI_TEST_FAULT=<point>[@n][:kill|stall]`, several separated by `,`:
//! at the n-th time (default the first) the process reaches `<point>`, it
//! either dies at once with no clean-up (`kill`, the default: abort, as a
//! SIGKILL would leave it) or writes the point's name to the file named by
//! `KIRI_TEST_FAULT_HIT` and stops there for good (`stall`), so a test can
//! cut the power at exactly that moment.

#[cfg(feature = "fault-inject")]
pub fn point(name: &str) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static PLAN: OnceLock<Vec<(String, u64, bool)>> = OnceLock::new();
    static HITS: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    let plan = PLAN.get_or_init(|| {
        std::env::var("KIRI_TEST_FAULT")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                let (rest, stall) = match s.rsplit_once(':') {
                    Some((r, m)) => (r, m == "stall"),
                    None => (s, false),
                };
                let (p, n) = rest.split_once('@').map_or((rest, 1), |(p, n)| (p, n.parse().unwrap_or(1)));
                (p.to_owned(), n, stall)
            })
            .collect()
    });
    let Some((_, n, stall)) = plan.iter().find(|(p, _, _)| p == name) else { return };
    let hit = {
        let mut hits = HITS.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
        let c = hits.entry(name.to_owned()).or_insert(0);
        *c += 1;
        *c
    };
    if hit != *n {
        return;
    }
    eprintln!("KIRI_TEST_FAULT: {name} reached ({hit})");
    if *stall {
        if let Some(f) = std::env::var_os("KIRI_TEST_FAULT_HIT") {
            let _ = std::fs::write(f, name);
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
    std::process::abort();
}

#[cfg(not(feature = "fault-inject"))]
#[inline(always)]
pub fn point(_name: &str) {}
