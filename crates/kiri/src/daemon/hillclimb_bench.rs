//! Frozen Rust benchmark suite for the Kiri Hillclimb (daemon, HTTP/API,
//! seccomp, logfile, kiri-proto, kiri-share-proto, kiri-image).
//!
//! Excluded from production binaries (`#[cfg(test)]`) and skipped by normal
//! `cargo test` (`#[ignore]`). Run via the frozen harness script in scratch:
//!   cargo test --profile fast --bin kiri daemon::hillclimb_bench::run_daemon_bench -- --ignored --exact --nocapture

use std::hint::black_box;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use kiri_image::{Image, Layer, RunConfig, Store};
use kiri_proto::{FsEntry, Limits, Msg, Net, Stats, Stream, run_flags};
use kiri_share_proto::Msg as ShareMsg;

use super::api;
use super::caller::Caller;
use super::engine::{Engine, Spec, boot_without_vm};
use super::logfile::{self, Log, LogConfig};
use super::network::Settings as NetSettings;
use super::seccomp;

static SEQ: AtomicU64 = AtomicU64::new(1);

fn temp_dir(tag: &str) -> PathBuf {
    let id = SEQ.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("kiri-hc-{tag}-{}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).expect("create bench tempdir");
    p
}

struct MetricSummary {
    median: f64,
    p95: f64,
    p99: f64,
    iqr: f64,
    cv_pct: f64,
    n: usize,
}

fn summarize(samples: &[f64]) -> MetricSummary {
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let n = s.len();
    let median = if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 };
    let p95 = s[((n * 95) / 100).min(n - 1)];
    let p99 = s[((n * 99) / 100).min(n - 1)];
    let q1 = s[(n / 4).min(n - 1)];
    let q3 = s[((n * 3) / 4).min(n - 1)];
    let mean = s.iter().sum::<f64>() / n as f64;
    let var = s.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    let cv_pct = if mean > 0.0 { var.sqrt() / mean * 100.0 } else { 0.0 };
    MetricSummary { median, p95, p99, iqr: q3 - q1, cv_pct, n }
}

fn emit_metric(name: &str, pillar: &str, workload: &str, unit: &str, samples: &[f64], bytes: u64, work_ops: u64, errors: u64) {
    let st = summarize(samples);
    let row = json!({
        "name": name,
        "pillar": pillar,
        "workload": workload,
        "unit": unit,
        "median": st.median,
        "p95": st.p95,
        "p99": st.p99,
        "iqr": st.iqr,
        "cv_pct": st.cv_pct,
        "n": st.n,
        "bytes": bytes,
        "work_ops": work_ops,
        "errors": errors,
    });
    println!("HILLCLIMB_JSON:{row}");
}

struct BenchServer {
    root: PathBuf,
    sock: PathBuf,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    container_ids: Vec<String>,
    log_container_id: String,
}

impl Drop for BenchServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.sock);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn populate_fixture(root: &Path, n_containers: usize, n_images: usize, n_volumes: usize, n_networks: usize, log_lines: usize) -> (Arc<Engine>, Vec<String>, String) {
    let engine = boot_without_vm(root);
    let repos = ["postgres", "redis", "nginx", "node", "python", "alpine"];

    // 1. Populate realistic image store (config blobs + images.json)
    let mut dummy_img_for_create = None;
    for i in 0..n_images {
        let repo = repos[i % repos.len()];
        let cfg = json!({
            "architecture": "arm64",
            "os": "linux",
            "created": format!("2026-11-{:02}T10:{:02}:00Z", (i % 27) + 1, i % 60),
            "config": {
                "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", format!("APP_VERSION=v{i}")],
                "Cmd": ["/bin/sh"],
                "Labels": {
                    "org.opencontainers.image.source": format!("https://github.com/example/{repo}"),
                    "org.opencontainers.image.version": format!("1.{i}.0"),
                    "com.kiri.bench": "1"
                }
            }
        });
        let cfg_bytes = serde_json::to_vec(&cfg).unwrap();
        let mut w = engine.store.ingest().unwrap();
        w.write_all(&cfg_bytes).unwrap();
        let (cfg_digest, _sz, _pin) = w.finish_pinned().unwrap();
        let img = Image {
            name: format!("{repo}:v{i}"),
            digest: cfg_digest.clone(),
            index_digest: None,
            config_digest: cfg_digest,
            layers: Vec::new(),
            size: 16_000_000 + (i as u64) * 512_000,
            platform: "linux/arm64".into(),
            created: format!("2026-11-{:02}T10:{:02}:00Z", (i % 27) + 1, i % 60),
            pulled_at: 1_764_000_000 + i as u64,
            config: RunConfig {
                env: vec!["PATH=/usr/bin:/bin".into()],
                entrypoint: Vec::new(),
                cmd: vec!["/bin/sh".into()],
                working_dir: "/app".into(),
                user: String::new(),
            },
            mirror: None,
        };
        if dummy_img_for_create.is_none() {
            dummy_img_for_create = Some(img.clone());
        }
        engine.store.put_image(img).unwrap();
    }
    let base_img = dummy_img_for_create.expect("at least 1 image");

    // 2. Populate volumes
    for i in 0..n_volumes {
        engine
            .volume_ensure_with(&format!("vol-data-{i}"), json!({"env": "bench", "idx": i.to_string()}), Default::default())
            .unwrap();
    }

    // 3. Populate networks
    for i in 0..n_networks {
        let _ = engine.lock_net().create(
            &format!("net-bench-{i}"),
            NetSettings { labels: json!({"tier": "app"}), ..Default::default() },
        );
    }

    // 4. Populate containers (mix of running and exited, Compose labels, ports, mounts)
    let mut ids = Vec::with_capacity(n_containers);
    for i in 0..n_containers {
        let repo = repos[i % repos.len()];
        let labels = if i % 4 == 0 {
            json!({
                "com.docker.compose.project": format!("proj-{}", i % 3),
                "com.docker.compose.service": format!("svc-{i}"),
                "tier": "backend",
                "env": "bench"
            })
        } else {
            json!({
                "app": format!("svc-{i}"),
                "tier": if i % 2 == 0 { "web" } else { "worker" },
                "env": "bench"
            })
        };
        let spec: Spec = serde_json::from_value(json!({
            "image": format!("{repo}:v{}", i % n_images),
            "image_id": base_img.config_digest,
            "entrypoint": ["/usr/local/bin/entrypoint.sh"],
            "cmd": ["--port", format!("{}", 8000 + i), "--workers", "4"],
            "env": ["PATH=/usr/bin:/bin", format!("SERVICE_ID={i}"), "RUST_LOG=info"],
            "cwd": "/app",
            "user": "",
            "auto_remove": true,
            "network_mode": "bridge",
            "labels": labels,
            "restart": {"name": "no", "max_retries": 0}
        }))
        .unwrap();
        let id = engine.create(Some(format!("svc-app-{i}")), spec, &base_img).unwrap();
        if i % 5 != 0 {
            engine.mark_running_for_test(&id, [172, 17, 0, ((i % 240) + 2) as u8]);
        }
        ids.push(id);
    }

    // 5. Populate a realistic container log file on disk for the first container
    let log_cid = ids[0].clone();
    {
        let mut lg = Log::new(logfile::dir(engine.store.root(), &log_cid), &LogConfig::default());
        let base_ns: u64 = 1_764_260_000_000_000_000;
        for i in 0..log_lines {
            let stream = if i % 10 == 0 { Stream::Stderr } else { Stream::Stdout };
            let line = format!(
                "level={} req_id={:06} method=GET path=/v1/orders/{} status=200 latency_ms={} bytes=4096\n",
                if i % 10 == 0 { "ERROR" } else { "INFO" },
                i,
                i % 1000,
                (i % 45) + 1
            );
            lg.append(stream, base_ns + (i as u64) * 1_000_000, line.as_bytes());
        }
        lg.flush();
    }

    (engine, ids, log_cid)
}

fn start_server(tag: &str, n_containers: usize, n_images: usize, n_volumes: usize, n_networks: usize, log_lines: usize) -> BenchServer {
    let root = temp_dir(tag);
    let sock = root.join("docker.sock");
    let (engine, container_ids, log_container_id) = populate_fixture(&root, n_containers, n_images, n_volumes, n_networks, log_lines);
    let listener = UnixListener::bind(&sock).expect("bind bench unix socket");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = stop.clone();
    let handle = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if stop_bg.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = conn else { break };
            let eng = engine.clone();
            std::thread::spawn(move || {
                let _ = api::serve(stream, eng, Caller::Host);
            });
        }
    });
    BenchServer { root, sock, stop, handle: Some(handle), container_ids, log_container_id }
}

/// Reads one HTTP/1.1 response from `r`, returning `(status, body_bytes, total_wire_bytes)`.
fn read_http_response(r: &mut BufReader<UnixStream>) -> io::Result<(u16, Vec<u8>, u64)> {
    let mut line = String::new();
    let mut wire = 0u64;
    let n = r.read_line(&mut line)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof reading status"));
    }
    wire += n as u64;
    let status: u16 = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut content_len: Option<usize> = None;
    let mut chunked = false;
    loop {
        line.clear();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        wire += n as u64;
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().ok();
            } else if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            line.clear();
            let n = r.read_line(&mut line)?;
            wire += n as u64;
            let sz = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if sz == 0 {
                line.clear();
                let n = r.read_line(&mut line)?;
                wire += n as u64;
                break;
            }
            let prev = body.len();
            body.resize(prev + sz, 0);
            r.read_exact(&mut body[prev..])?;
            let mut crlf = [0u8; 2];
            r.read_exact(&mut crlf)?;
            wire += (sz + 2) as u64;
        }
    } else if let Some(len) = content_len {
        body.resize(len, 0);
        r.read_exact(&mut body)?;
        wire += len as u64;
    }
    Ok((status, body, wire))
}

fn http_keepalive_get(w: &mut UnixStream, r: &mut BufReader<UnixStream>, path: &str) -> io::Result<(u16, Vec<u8>, u64)> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: kiri\r\nX-Kiri-Background: 1\r\n\r\n");
    w.write_all(req.as_bytes())?;
    read_http_response(r)
}

fn http_close_get(sock: &Path, path: &str) -> io::Result<(u16, Vec<u8>, u64)> {
    let mut s = UnixStream::connect(sock)?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: kiri\r\nConnection: close\r\nX-Kiri-Background: 1\r\n\r\n");
    s.write_all(req.as_bytes())?;
    let mut r = BufReader::new(s);
    read_http_response(&mut r)
}

fn bench_http_endpoint(
    sock: &Path,
    name: &str,
    pillar: &str,
    workload: &str,
    path: &str,
    reqs_per_sample: usize,
    samples_n: usize,
    verify: impl Fn(&[u8]) -> bool,
) {
    let stream = UnixStream::connect(sock).expect("connect keepalive");
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut w = stream.try_clone().unwrap();
    let mut r = BufReader::new(stream);

    // Warmup
    for _ in 0..3 {
        let (st, body, _) = http_keepalive_get(&mut w, &mut r, path).unwrap();
        assert_eq!(st, 200);
        assert!(verify(&body));
    }

    let mut samples = Vec::with_capacity(samples_n);
    let mut last_wire = 0u64;
    let mut work_ops = 0u64;
    let mut errors = 0u64;
    for _ in 0..samples_n {
        let mut last_body = Vec::new();
        let t0 = Instant::now();
        for _ in 0..reqs_per_sample {
            match http_keepalive_get(&mut w, &mut r, path) {
                Ok((200, body, wire)) if !body.is_empty() => {
                    black_box(&body);
                    last_wire = wire;
                    last_body = body;
                    work_ops += 1;
                }
                _ => errors += 1,
            }
        }
        let per_req_us = t0.elapsed().as_secs_f64() * 1e6 / reqs_per_sample as f64;
        if !last_body.is_empty() && !verify(&last_body) {
            errors += 1;
        }
        samples.push(per_req_us);
    }
    emit_metric(name, pillar, workload, "us", &samples, last_wire, work_ops, errors);
}

fn bench_ui_refresh_cycle(sock: &Path, name: &str, workload: &str, samples_n: usize) {
    let paths = ["/containers/json?all=1", "/images/json", "/volumes", "/networks"];
    // Warmup
    for _ in 0..2 {
        for p in paths {
            let (st, _, _) = http_close_get(sock, p).unwrap();
            assert_eq!(st, 200);
        }
    }
    let mut samples = Vec::with_capacity(samples_n);
    let mut cycle_bytes = 0u64;
    let mut work_ops = 0u64;
    let mut errors = 0u64;
    for _ in 0..samples_n {
        let t0 = Instant::now();
        let mut total_wire = 0u64;
        for p in paths {
            match http_close_get(sock, p) {
                Ok((200, body, wire)) if !body.is_empty() => {
                    black_box(&body);
                    total_wire += wire;
                    work_ops += 1;
                }
                _ => errors += 1,
            }
        }
        cycle_bytes = total_wire;
        samples.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    emit_metric(name, "latency", workload, "us", &samples, cycle_bytes, work_ops, errors);
}

fn bench_concurrent_contention(sock: &Path, cid: &str) {
    let threads = 4usize;
    let iters_per_thread = 25usize;
    let paths = [
        "/containers/json?all=1".to_owned(),
        "/info".to_owned(),
        "/images/json".to_owned(),
        format!("/containers/{cid}/json"),
    ];
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let mut handles = Vec::with_capacity(threads);
    for t in 0..threads {
        let s = sock.to_path_buf();
        let p = paths[t % paths.len()].clone();
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let stream = UnixStream::connect(&s).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            // Warmup before synchronized contention burst
            for _ in 0..2 {
                let (st, _, _) = http_keepalive_get(&mut w, &mut r, &p).unwrap();
                assert_eq!(st, 200);
            }
            b.wait();
            let mut times = Vec::with_capacity(iters_per_thread);
            let mut wire_sum = 0u64;
            let mut ok = 0u64;
            let mut err = 0u64;
            for _ in 0..iters_per_thread {
                let t0 = Instant::now();
                match http_keepalive_get(&mut w, &mut r, &p) {
                    Ok((200, body, wire)) if !body.is_empty() => {
                        black_box(&body);
                        wire_sum += wire;
                        ok += 1;
                    }
                    _ => err += 1,
                }
                times.push(t0.elapsed().as_secs_f64() * 1e6);
            }
            (times, wire_sum, ok, err)
        }));
    }
    let mut all_times = Vec::new();
    let mut total_bytes = 0u64;
    let mut total_ops = 0u64;
    let mut total_err = 0u64;
    for h in handles {
        let (times, b, ok, err) = h.join().unwrap();
        all_times.extend(times);
        total_bytes += b;
        total_ops += ok;
        total_err += err;
    }
    emit_metric(
        "api_concurrent_contention_heavy",
        "lag",
        "heavy",
        "us",
        &all_times,
        total_bytes / total_ops.max(1),
        total_ops,
        total_err,
    );
}

fn bench_seccomp() {
    let small_json = r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","write","close","exit_group","brk"],"action":"SCMP_ACT_ALLOW"}]}"#;
    let default_json = include_str!("seccomp_docker_default.json");
    let default_caps: u64 = 0x0000_0000_a804_25fb;

    for (name, workload, json, reps, samples_n) in [
        ("seccomp_compile_small", "small", small_json, 20usize, 15usize),
        ("seccomp_compile_heavy", "heavy", default_json, 5usize, 21usize),
    ] {
        // Warmup
        let first = seccomp::compile(json, default_caps).expect("seccomp compile");
        assert!(!first.is_empty());

        let mut samples = Vec::with_capacity(samples_n);
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        let mut bytes = 0u64;
        for _ in 0..samples_n {
            let t0 = Instant::now();
            for _ in 0..reps {
                match seccomp::compile(black_box(json), default_caps) {
                    Ok(prog) if prog.len() == first.len() => {
                        bytes = prog.len() as u64;
                        black_box(&prog);
                        work_ops += 1;
                    }
                    _ => errors += 1,
                }
            }
            samples.push(t0.elapsed().as_secs_f64() * 1e6 / reps as f64);
        }
        emit_metric(name, "latency", workload, "us", &samples, bytes, work_ops, errors);
    }
}

fn bench_kiri_proto() {
    let mut buf = Vec::with_capacity(128 * 1024);

    // Small: Ping + Stats + Started roundtrip
    {
        let stats = Stats {
            uptime_ns: 12_345_678_900,
            mem_total_kib: 8 * 1024 * 1024,
            mem_available_kib: 6 * 1024 * 1024,
            agent_rss_kib: 4096,
            mem_used_kib: 512 * 1024,
            mem_stall: 0,
            oom_kills: 0,
            mem_balloon_kib: Some(2 * 1024 * 1024),
            mem_committed_kib: Some(700 * 1024),
        };
        let mut samples = Vec::with_capacity(15);
        let mut bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        // Warmup
        for i in 0..200u64 {
            buf.clear();
            Msg::Ping(i).encode(&mut buf);
            let _ = black_box(kiri_proto::decode(&buf));
            buf.clear();
            Msg::Stats(stats).encode(&mut buf);
            let _ = black_box(kiri_proto::decode(&buf));
        }
        for _ in 0..15 {
            let t0 = Instant::now();
            for i in 0..500u64 {
                buf.clear();
                Msg::Ping(i).encode(&mut buf);
                if kiri_proto::decode(&buf).is_err() { errors += 1; }
                bytes = buf.len() as u64;
                buf.clear();
                Msg::Stats(stats).encode(&mut buf);
                if kiri_proto::decode(&buf).is_err() { errors += 1; }
                bytes += buf.len() as u64;
                buf.clear();
                Msg::Started { id: "abcdef0123456789abcdef0123456789", pid: 42, starting: false }.encode(&mut buf);
                if kiri_proto::decode(&buf).is_err() { errors += 1; }
                bytes += buf.len() as u64;
                black_box(&buf);
                work_ops += 3;
            }
            samples.push(t0.elapsed().as_secs_f64() * 1e6 / 500.0);
        }
        emit_metric("kiri_proto_roundtrip_small", "latency", "small", "us", &samples, bytes, work_ops, errors);
    }

    // Heavy: encode_run (10 layers, 24 env vars, 6 mounts, 2 KB seccomp) + 64 KiB Output + 200-entry FsList
    {
        let layers: Vec<String> = (0..10).map(|i| format!("sha256:{i:064x}")).collect();
        let argv = vec!["/usr/local/bin/server".to_owned(), "--bind".to_owned(), "0.0.0.0:8080".to_owned()];
        let env: Vec<String> = (0..24).map(|i| format!("ENV_VAR_{i}=value_number_{i}_with_payload")).collect();
        let mounts: Vec<String> = (0..6).map(|i| format!("/mnt/mac/src-{i}\t/app/dir-{i}\trw")).collect();
        let extra_hosts = vec!["host.docker.internal:172.17.0.1".to_owned()];
        let dns_names = vec!["web".to_owned(), "web.app".to_owned()];
        let net_opts = vec!["mtu=1500".to_owned()];
        let host_opts = vec!["rlimit=nofile:65536:65536".to_owned()];
        let seccomp_bytes = vec![0x06u8; 2048];
        let out_chunk = vec![b'A'; 64 * 1024];
        let fs_names: Vec<String> = (0..200).map(|i| format!("module_file_{i:04}.rs")).collect();
        let fs_entries: Vec<FsEntry<'_>> = fs_names
            .iter()
            .enumerate()
            .map(|(i, n)| FsEntry { name: n.as_str(), mode: 0o100644, size: (i as u64 + 1) * 4096, mtime: 1_764_000_000, mtime_nsec: 123, ino: i as u64 + 1 })
            .collect();
        let limits = Limits::default();

        let mut samples = Vec::with_capacity(15);
        let mut bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        // Warmup
        for _ in 0..20 {
            buf.clear();
            kiri_proto::encode_fs_list(&mut buf, &fs_entries);
            let _ = black_box(kiri_proto::decode(&buf));
        }
        for _ in 0..15 {
            let t0 = Instant::now();
            for _ in 0..200 {
                let mut total_b = 0u64;
                buf.clear();
                kiri_proto::encode_run(
                    &mut buf,
                    "c0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
                    &layers,
                    &argv,
                    &env,
                    "/app",
                    "1000:1000",
                    "web-01",
                    run_flags::STDIN,
                    Net {
                        bridge: "kiri0",
                        ip: [172, 17, 0, 12],
                        prefix: 16,
                        gateway: [172, 17, 0, 1],
                        extra_hosts: &extra_hosts,
                        dns_names: &dns_names,
                        opts: &net_opts,
                    },
                    &mounts,
                    &limits,
                    0,
                    &host_opts,
                    &seccomp_bytes,
                );
                total_b += buf.len() as u64;
                match kiri_proto::decode(&buf) {
                    Ok(Msg::Run(r)) if r.layers.iter().count() == 10 && r.env.iter().count() == 24 => {}
                    _ => errors += 1,
                }
                buf.clear();
                Msg::Output { id: "c0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", stream: Stream::Stdout, data: &out_chunk }.encode(&mut buf);
                total_b += buf.len() as u64;
                match kiri_proto::decode(&buf) {
                    Ok(Msg::Output { data, .. }) if data.len() == out_chunk.len() => {}
                    _ => errors += 1,
                }
                buf.clear();
                kiri_proto::encode_fs_list(&mut buf, &fs_entries);
                total_b += buf.len() as u64;
                match kiri_proto::decode(&buf) {
                    Ok(Msg::FsList { count, raw }) if count == 200 => {
                        let iterated = kiri_proto::fs_entries(count, raw).count();
                        if iterated != 200 { errors += 1; }
                    }
                    _ => errors += 1,
                }
                bytes = total_b;
                black_box(&buf);
                work_ops += 3;
            }
            samples.push(t0.elapsed().as_secs_f64() * 1e6 / 200.0);
        }
        emit_metric("kiri_proto_roundtrip_heavy", "latency", "heavy", "us", &samples, bytes, work_ops, errors);
    }
}

fn bench_kiri_share_proto() {
    let mut buf = Vec::with_capacity(64 * 1024);
    // Small: Window + Ping
    {
        let mut samples = Vec::with_capacity(15);
        let mut bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        // Warmup
        for i in 0..200u32 {
            buf.clear();
            ShareMsg::Window { stream: i, credit: 32768 }.encode(&mut buf);
            let _ = black_box(kiri_share_proto::decode(&buf));
            buf.clear();
            ShareMsg::Ping(u64::from(i)).encode(&mut buf);
            let _ = black_box(kiri_share_proto::decode(&buf));
        }
        for _ in 0..15 {
            let t0 = Instant::now();
            for i in 0..1000u32 {
                buf.clear();
                ShareMsg::Window { stream: i, credit: 32768 }.encode(&mut buf);
                if kiri_share_proto::decode(&buf).is_err() { errors += 1; }
                bytes = buf.len() as u64;
                buf.clear();
                ShareMsg::Ping(u64::from(i)).encode(&mut buf);
                if kiri_share_proto::decode(&buf).is_err() { errors += 1; }
                bytes += buf.len() as u64;
                black_box(&buf);
                work_ops += 2;
            }
            samples.push(t0.elapsed().as_secs_f64() * 1e6 / 1000.0);
        }
        emit_metric("kiri_share_proto_roundtrip_small", "latency", "small", "us", &samples, bytes, work_ops, errors);
    }
    // Heavy: 32 KiB Data + 32 KiB Chunk
    {
        let payload = vec![0x5Au8; 32 * 1024];
        let mut samples = Vec::with_capacity(15);
        let mut bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        // Warmup
        for i in 0..50u32 {
            buf.clear();
            ShareMsg::Data { stream: 1, data: &payload }.encode(&mut buf);
            let _ = black_box(kiri_share_proto::decode(&buf));
            buf.clear();
            ShareMsg::Chunk { stream: 1, seq: i, fin: false, data: &payload }.encode(&mut buf);
            let _ = black_box(kiri_share_proto::decode(&buf));
        }
        for _ in 0..15 {
            let t0 = Instant::now();
            for i in 0..500u32 {
                buf.clear();
                ShareMsg::Data { stream: 1, data: &payload }.encode(&mut buf);
                let mut total_b = buf.len() as u64;
                match kiri_share_proto::decode(&buf) {
                    Ok(ShareMsg::Data { data, .. }) if data.len() == payload.len() => {}
                    _ => errors += 1,
                }
                buf.clear();
                ShareMsg::Chunk { stream: 1, seq: i, fin: false, data: &payload }.encode(&mut buf);
                total_b += buf.len() as u64;
                match kiri_share_proto::decode(&buf) {
                    Ok(ShareMsg::Chunk { data, .. }) if data.len() == payload.len() => {}
                    _ => errors += 1,
                }
                bytes = total_b;
                black_box(&buf);
                work_ops += 2;
            }
            samples.push(t0.elapsed().as_secs_f64() * 1e6 / 500.0);
        }
        emit_metric("kiri_share_proto_roundtrip_heavy", "latency", "heavy", "us", &samples, bytes, work_ops, errors);
    }
}

fn bench_image_archive() {
    for (name, workload, n_layers, layer_kb, samples_n) in [
        ("image_archive_load_save_small", "small", 2usize, 64usize, 9usize),
        ("image_archive_load_save_heavy", "heavy", 8usize, 256usize, 9usize),
    ] {
        let src_dir = temp_dir(&format!("arch-src-{workload}"));
        let src_store = Store::open(&src_dir).unwrap();
        let mut layers = Vec::with_capacity(n_layers);
        let mut total_layer_size = 0u64;
        for l in 0..n_layers {
            // Deterministic pseudo-random compressible/incompressible mix
            let mut blob = vec![0u8; layer_kb * 1024];
            for (j, b) in blob.iter_mut().enumerate() {
                *b = ((j.wrapping_mul(31) ^ l.wrapping_mul(17)) & 0xff) as u8;
            }
            let mut w = src_store.ingest().unwrap();
            w.write_all(&blob).unwrap();
            let (digest, size, _pin) = w.finish_pinned().unwrap();
            total_layer_size += size;
            layers.push(Layer { digest, size, media_type: "application/vnd.oci.image.layer.v1.tar".into() });
        }
        let cfg = json!({
            "architecture": "arm64",
            "os": "linux",
            "created": "2026-11-27T10:00:00Z",
            "config": {"Env": ["PATH=/usr/bin:/bin"], "Cmd": ["/bin/sh"]},
            "rootfs": {"type": "layers", "diff_ids": layers.iter().map(|l| l.digest.clone()).collect::<Vec<_>>()}
        });
        let mut cw = src_store.ingest().unwrap();
        cw.write_all(&serde_json::to_vec(&cfg).unwrap()).unwrap();
        let (cfg_digest, _, _pin) = cw.finish_pinned().unwrap();
        let img = Image {
            name: format!("bench/app:{workload}"),
            digest: cfg_digest.clone(),
            index_digest: None,
            config_digest: cfg_digest,
            layers,
            size: total_layer_size,
            platform: "linux/arm64".into(),
            created: "2026-11-27T10:00:00Z".into(),
            pulled_at: 1_764_000_000,
            config: RunConfig::default(),
            mirror: None,
        };
        src_store.put_image(img.clone()).unwrap();

        let mut samples = Vec::with_capacity(samples_n);
        let mut archive_bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        for s in 0..samples_n {
            let dst_dir = temp_dir(&format!("arch-dst-{workload}-{s}"));
            let dst_store = Store::open(&dst_dir).unwrap();
            let mut tar_buf = Vec::new();
            let t0 = Instant::now();
            let save_res = kiri_image::archive::save(&src_store, std::slice::from_ref(&img), &mut tar_buf);
            let load_res = save_res.and_then(|()| kiri_image::archive::load(&dst_store, &tar_buf[..]));
            let elapsed_us = t0.elapsed().as_secs_f64() * 1e6;
            match load_res {
                Ok(loaded) if loaded.len() == 1 && loaded[0].layers.len() == n_layers => {
                    archive_bytes = tar_buf.len() as u64;
                    black_box(&loaded);
                    work_ops += 1;
                }
                _ => errors += 1,
            }
            samples.push(elapsed_us);
            let _ = std::fs::remove_dir_all(&dst_dir);
        }
        let _ = std::fs::remove_dir_all(&src_dir);
        emit_metric(name, "latency", workload, "us", &samples, archive_bytes, work_ops, errors);
    }
}

fn bench_logfile_append() {
    for (name, workload, n_lines, samples_n) in [
        ("logfile_append_throughput_small", "small", 200usize, 15usize),
        ("logfile_append_throughput_heavy", "heavy", 10_000usize, 15usize),
    ] {
        // Build realistic 64-line chunks
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut cur = Vec::with_capacity(8192);
        for i in 0..n_lines {
            let line = format!("2026-11-27T18:00:00Z INFO worker={} req={:06} latency_ms=12 status=200\n", i % 8, i);
            cur.extend_from_slice(line.as_bytes());
            if (i + 1) % 32 == 0 || i + 1 == n_lines {
                chunks.push(std::mem::take(&mut cur));
            }
        }
        let mut samples = Vec::with_capacity(samples_n);
        let mut disk_bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        // Warmup
        {
            let dir = temp_dir(&format!("log-{workload}-warm"));
            let mut lg = Log::new(dir.clone(), &LogConfig::default());
            for (idx, c) in chunks.iter().enumerate() {
                lg.append(Stream::Stdout, 1_764_260_000_000_000_000 + idx as u64 * 1000, c);
            }
            lg.flush();
            let _ = std::fs::remove_dir_all(&dir);
        }
        for s in 0..samples_n {
            let dir = temp_dir(&format!("log-{workload}-{s}"));
            let mut lg = Log::new(dir.clone(), &LogConfig::default());
            let (tx, rx) = std::sync::mpsc::channel();
            let _snap = lg.snapshot(Some(tx));
            let t0 = Instant::now();
            for (idx, c) in chunks.iter().enumerate() {
                lg.append(Stream::Stdout, 1_764_260_000_000_000_000 + idx as u64 * 1000, c);
            }
            lg.flush();
            let elapsed_us = t0.elapsed().as_secs_f64() * 1e6;
            let mut got = 0usize;
            while rx.try_recv().is_ok() {
                got += 1;
            }
            if got == n_lines {
                work_ops += got as u64;
            } else {
                errors += 1;
            }
            disk_bytes = std::fs::metadata(dir.join("container.log")).map(|m| m.len()).unwrap_or(0);
            samples.push(elapsed_us);
            let _ = std::fs::remove_dir_all(&dir);
        }
        emit_metric(name, "latency", workload, "us", &samples, disk_bytes, work_ops, errors);
    }
}

#[ignore]
#[test]
fn run_daemon_bench() {
    // 1. Small/idle fixture (5 containers, 5 images, 3 volumes, 2 networks, 100 log lines)
    let small = start_server("small", 5, 5, 3, 2, 100);
    // 2. Heavy/realistic fixture (100 containers, 150 images, 40 volumes, 15 networks, 5000 log lines)
    let heavy = start_server("heavy", 100, 150, 40, 15, 5000);

    // HTTP/API benchmarks (contrasting small vs heavy)
    bench_http_endpoint(&small.sock, "api_ping_keepalive_small", "latency", "small", "/_ping", 100, 15, |b| b == b"OK");
    bench_http_endpoint(&heavy.sock, "api_ping_keepalive_heavy", "latency", "heavy", "/_ping", 300, 15, |b| b == b"OK");

    bench_http_endpoint(&small.sock, "api_info_poll_small", "latency", "small", "/info", 20, 15, |b| {
        serde_json::from_slice::<Value>(b).is_ok_and(|v| v["Containers"].as_u64() == Some(5) && v["Images"].as_u64() == Some(5))
    });
    bench_http_endpoint(&heavy.sock, "api_info_poll_heavy", "latency", "heavy", "/info", 20, 15, |b| {
        serde_json::from_slice::<Value>(b).is_ok_and(|v| v["Containers"].as_u64() == Some(100) && v["Images"].as_u64() == Some(150))
    });

    bench_http_endpoint(&small.sock, "api_containers_list_small", "latency", "small", "/containers/json?all=1", 25, 15, |b| {
        serde_json::from_slice::<Value>(b).is_ok_and(|v| v.as_array().is_some_and(|a| a.len() == 5))
    });
    bench_http_endpoint(&heavy.sock, "api_containers_list_heavy", "latency", "heavy", "/containers/json?all=1", 15, 15, |b| {
        serde_json::from_slice::<Value>(b).is_ok_and(|v| v.as_array().is_some_and(|a| a.len() == 100))
    });

    let filter_path = "/containers/json?all=1&filters=%7B%22name%22%3A%5B%22%5E%2F%3Fsvc-app-%5B0-9%5D%2B%24%22%5D%2C%22label%22%3A%5B%22env%3Dbench%22%5D%2C%22status%22%3A%5B%22running%22%5D%7D";
    bench_http_endpoint(&heavy.sock, "api_containers_filtered_heavy", "latency", "heavy", filter_path, 15, 15, |b| {
        serde_json::from_slice::<Value>(b).is_ok_and(|v| v.as_array().is_some_and(|a| a.len() == 80))
    });

    bench_http_endpoint(&small.sock, "api_images_list_small", "latency", "small", "/images/json", 25, 15, |b| {
        serde_json::from_slice::<Value>(b).is_ok_and(|v| v.as_array().is_some_and(|a| a.len() == 5))
    });
    bench_http_endpoint(&heavy.sock, "api_images_list_heavy", "latency", "heavy", "/images/json", 15, 15, |b| {
        serde_json::from_slice::<Value>(b).is_ok_and(|v| v.as_array().is_some_and(|a| a.len() == 150))
    });

    let small_log_path = format!("/containers/{}/logs?stdout=1&stderr=1&tail=100&timestamps=1", small.log_container_id);
    let heavy_log_path = format!("/containers/{}/logs?stdout=1&stderr=1&tail=2000&timestamps=1", heavy.log_container_id);
    bench_http_endpoint(&small.sock, "api_logs_tail_stream_small", "latency", "small", &small_log_path, 15, 15, |b| b.len() > 5_000);
    bench_http_endpoint(&heavy.sock, "api_logs_tail_stream_heavy", "latency", "heavy", &heavy_log_path, 5, 15, |b| b.len() > 150_000);

    // Exact 4-request UI refresh cycle (Connection: close per request, as client.rs does)
    bench_ui_refresh_cycle(&small.sock, "api_ui_refresh_cycle_small", "small", 15);
    bench_ui_refresh_cycle(&heavy.sock, "api_ui_refresh_cycle_heavy", "heavy", 15);

    // Concurrent lock contention / p99 tail latency
    bench_concurrent_contention(&heavy.sock, &heavy.container_ids[0]);

    drop(small);
    drop(heavy);

    // Compute, protocol, archive, and log ingestion benchmarks
    bench_seccomp();
    bench_kiri_proto();
    bench_kiri_share_proto();
    bench_image_archive();
    bench_logfile_append();
}
