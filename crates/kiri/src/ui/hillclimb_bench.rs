//! Frozen Rust benchmark suite for the Kiri Hillclimb (UI page assembly,
//! i18n lookup/formatting, and WebView IPC snapshot payload generation).
//!
//! Excluded from production binaries (`#[cfg(test)]`) and skipped by normal
//! `cargo test` (`#[ignore]`).

use std::hint::black_box;
use std::time::Instant;

use serde_json::{Value, json};

use super::{PAGE, assemble, brand, brands, lang, state};

#[allow(dead_code)]
#[path = "k8s_items.rs"]
mod k8s_items;

fn summarize(samples: &[f64]) -> (f64, f64, f64, f64, f64) {
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
    (median, p95, p99, q3 - q1, cv_pct)
}

fn emit_metric(name: &str, pillar: &str, workload: &str, unit: &str, samples: &[f64], bytes: u64, work_ops: u64, errors: u64) {
    let (median, p95, p99, iqr, cv_pct) = summarize(samples);
    let row = json!({
        "name": name,
        "pillar": pillar,
        "workload": workload,
        "unit": unit,
        "median": median,
        "p95": p95,
        "p99": p99,
        "iqr": iqr,
        "cv_pct": cv_pct,
        "n": samples.len(),
        "bytes": bytes,
        "work_ops": work_ops,
        "errors": errors,
    });
    println!("HILLCLIMB_JSON:{row}");
}

fn make_lists_fixture(n_containers: usize, n_images: usize, n_volumes: usize, n_networks: usize) -> (Value, Value, Value, Value) {
    let repos = ["postgres", "redis", "nginx", "node", "python", "alpine", "mongo", "grafana/grafana"];
    let containers: Vec<Value> = (0..n_containers)
        .map(|i| {
            let repo = repos[i % repos.len()];
            json!({
                "Id": format!("c{i:063x}"),
                "Names": [format!("/svc-app-{i}")],
                "Image": format!("{repo}:16-alpine"),
                "ImageID": format!("sha256:{i:064x}"),
                "Command": format!("/usr/local/bin/entrypoint.sh --port {}", 8000 + i),
                "Created": 1_764_250_000 + i,
                "State": if i % 5 == 0 { "exited" } else { "running" },
                "Status": "Up 12 minutes",
                "KiriStartedAt": 1_764_250_100 + i,
                "Ports": [{"IP": "0.0.0.0", "PrivatePort": 8080, "PublicPort": 18000 + i, "Type": "tcp"}],
                "Labels": {"com.docker.compose.project": format!("proj-{}", i % 3), "env": "bench"},
                "HostConfig": {"NetworkMode": "bridge"},
                "NetworkSettings": {"Networks": {"bridge": {"IPAddress": format!("172.17.0.{}", (i % 240) + 2)}}},
                "Mounts": [{"Type": "bind", "Source": format!("/Users/dev/src-{i}"), "Destination": "/app", "RW": true}]
            })
        })
        .collect();
    let images: Vec<Value> = (0..n_images)
        .map(|i| {
            let repo = repos[i % repos.len()];
            json!({
                "Id": format!("sha256:{i:064x}"),
                "ParentId": "",
                "RepoTags": [format!("{repo}:v{i}")],
                "RepoDigests": [format!("{repo}@sha256:{i:064x}")],
                "Created": 1_764_200_000 + i,
                "Size": 18_000_000 + i * 250_000,
                "SharedSize": -1,
                "VirtualSize": 18_000_000 + i * 250_000,
                "Labels": {"org.opencontainers.image.source": format!("https://github.com/example/{repo}")},
                "Containers": -1,
                "Pulled": 1_764_210_000 + i
            })
        })
        .collect();
    let volumes: Vec<Value> = (0..n_volumes)
        .map(|i| json!({"Name": format!("vol-{i}"), "Driver": "local", "Mountpoint": format!("/var/lib/kiri/volumes/vol-{i}/_data"), "Labels": {}}))
        .collect();
    let networks: Vec<Value> = (0..n_networks)
        .map(|i| json!({"Name": format!("net-{i}"), "Id": format!("n{i:063x}"), "Driver": "bridge", "Scope": "local"}))
        .collect();
    (Value::Array(containers), Value::Array(images), json!({"Volumes": volumes}), Value::Array(networks))
}

#[ignore]
#[test]
fn run_ui_backend_bench() {
    // 1. Page assembly latency + exact HTML bytes (en vs pt-BR)
    for (name, workload, code) in [
        ("ui_page_assemble_en", "small", "en"),
        ("ui_page_assemble_pt_br", "heavy", "pt-BR"),
    ] {
        // Warmup
        let first = assemble::page(PAGE, Some(code));
        assert!(first.len() > 50_000 && first.contains("<html") && !first.contains("/*ICONS*/") && !first.contains("/*XTERM_JS*/"));

        let mut samples = Vec::with_capacity(11);
        let mut bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        for _ in 0..11 {
            let t0 = Instant::now();
            let out = assemble::page(black_box(PAGE), Some(code));
            let us = t0.elapsed().as_secs_f64() * 1e6;
            if out.len() == first.len() {
                bytes = out.len() as u64;
                black_box(&out);
                work_ops += 1;
            } else {
                errors += 1;
            }
            samples.push(us);
        }
        emit_metric(name, "latency", workload, "us", &samples, bytes, work_ops, errors);
    }

    // 2. i18n lookup + placeholder fill (small=50 vs heavy=2000)
    {
        let keys = [
            "Started {name}",
            "Containers now answer at <name>.kiri.local",
            "Could not change the ports: {error}",
            "{name} restarted with the new environment",
            "Kept {name}: {error}",
        ];
        for (name, workload, n_calls) in [("ui_lang_tr_hot_small", "small", 50usize), ("ui_lang_tr_hot_heavy", "heavy", 2000usize)] {
            // Warmup (ensures OnceLock language tables are initialized before sampling)
            for k in &keys {
                let _ = black_box(lang::fill(lang::tr("pt-BR", k), &[("name", &"postgres-main"), ("error", &"port in use")]));
                let _ = black_box(lang::fill(lang::tr("ar", k), &[("name", &"postgres-main"), ("error", &"port in use")]));
            }
            let mut samples = Vec::with_capacity(15);
            let mut bytes = 0u64;
            let mut work_ops = 0u64;
            let mut errors = 0u64;
            for _ in 0..15 {
                let t0 = Instant::now();
                let mut total_len = 0u64;
                for i in 0..n_calls {
                    let k = keys[i % keys.len()];
                    let l = if i % 4 == 0 { "ar" } else { "pt-BR" };
                    let s = lang::fill(lang::tr(l, k), &[("name", &"postgres-main"), ("error", &"port in use")]);
                    if s.is_empty() {
                        errors += 1;
                    }
                    total_len += s.len() as u64;
                    black_box(s);
                    work_ops += 1;
                }
                bytes = total_len;
                samples.push(t0.elapsed().as_secs_f64() * 1e6);
            }
            emit_metric(name, "latency", workload, "us", &samples, bytes, work_ops, errors);
        }
    }

    // 3. UI lists IPC payload assembly (mirrors ui::mod::refresh icon enrichment + window::eval string)
    for (name, workload, nc, ni, nv, nn) in [
        ("ui_lists_ipc_payload_small", "small", 5usize, 5usize, 3usize, 2usize),
        ("ui_lists_ipc_payload_heavy", "heavy", 100usize, 150usize, 40usize, 15usize),
    ] {
        let (base_c, base_i, base_v, base_n) = make_lists_fixture(nc, ni, nv, nn);
        // Warmup
        {
            let _ = black_box(brand("postgres:16-alpine"));
            let _ = black_box(json!({"type": "lists", "containers": &base_c, "images": &base_i}).to_string());
        }
        let mut samples = Vec::with_capacity(15);
        let mut payload_bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        for _ in 0..15 {
            let mut containers = base_c.clone();
            let mut images = base_i.clone();
            let volumes = base_v.clone();
            let networks = base_n.clone();
            let t0 = Instant::now();
            if let Some(list) = containers.as_array_mut() {
                for item in list {
                    let img = item["Image"].as_str().unwrap_or_default().to_owned();
                    let icon = brand(&img);
                    item["icon"] = serde_json::json!(icon);
                }
            }
            if let Some(list) = images.as_array_mut() {
                for item in list {
                    let tag = item["RepoTags"][0].as_str().unwrap_or_default().to_owned();
                    let icon = brand(&tag);
                    item["icon"] = serde_json::json!(icon);
                }
            }
            let payload = json!({
                "type": "lists",
                "containers": containers,
                "images": images,
                "volumes": volumes["Volumes"],
                "networks": networks,
            });
            let eval_js = format!("window.kiri && kiri.on({})", payload);
            let us = t0.elapsed().as_secs_f64() * 1e6;
            if eval_js.len() > 200 {
                payload_bytes = eval_js.len() as u64;
                black_box(&eval_js);
                work_ops += (nc + ni) as u64;
            } else {
                errors += 1;
            }
            samples.push(us);
        }
        emit_metric(name, "bytes", workload, "us", &samples, payload_bytes, work_ops, errors);
    }

    // 4. UI vm_panel 2s tick payload construction (100 ticks per sample)
    {
        let info = json!({
            "KiriVmAwake": true,
            "KiriStopped": false,
            "KiriMemoryTarget": 2147483648u64,
            "KiriMemoryUsed": 641728512u64,
            "KiriMemoryCeiling": 8589934592u64,
            "KiriMemoryStall": 0,
            "KiriOomKills": 0,
            "ContainersRunning": 80,
            "NCPU": 8,
            "KiriCpuPercent": 4.2,
            "KiriAgentMemory": 43008000u64,
        });
        let mut samples = Vec::with_capacity(15);
        let mut tick_bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        // Warmup
        for _ in 0..10 {
            let _ = black_box(format!("window.kiri && kiri.on({})", state("running", None)));
        }
        for _ in 0..15 {
            let t0 = Instant::now();
            for _ in 0..100 {
                let mib = |k: &str| info[k].as_u64().unwrap_or(0) >> 20;
                let vm_js = format!(
                    "window.kiri && kiri.on({})",
                    json!({
                        "type": "vm",
                        "awake": true,
                        "target_mib": mib("KiriMemoryTarget"),
                        "used_mib": mib("KiriMemoryUsed"),
                        "ceiling_mib": mib("KiriMemoryCeiling"),
                        "stall_pct": info["KiriMemoryStall"],
                        "oom_kills": info["KiriOomKills"],
                        "running": info["ContainersRunning"],
                        "cpus": info["NCPU"],
                        "cpu_pct": info["KiriCpuPercent"],
                        "daemon_kib": info["KiriAgentMemory"].as_u64().unwrap_or(0) >> 10,
                    })
                );
                let st_js = format!("window.kiri && kiri.on({})", state("running", None));
                tick_bytes = (vm_js.len() + st_js.len()) as u64;
                if tick_bytes == 0 {
                    errors += 1;
                }
                black_box((&vm_js, &st_js));
                work_ops += 1;
            }
            samples.push(t0.elapsed().as_secs_f64() * 1e6 / 100.0);
        }
        emit_metric("ui_vm_tick_payload_heavy", "bytes", "heavy", "us", &samples, tick_bytes, work_ops, errors);
    }

    // 5. Real production UI k8s_items::summarize (small=5 pods/2 svcs vs heavy=80 pods/25 svcs)
    for (name, workload, n_pods, n_svcs) in [
        ("ui_k8s_summarize_small", "small", 5usize, 2usize),
        ("ui_k8s_summarize_heavy", "heavy", 80usize, 25usize),
    ] {
        let repos = ["postgres:16-alpine", "redis:7-alpine", "nginx:1.27", "node:22-alpine", "python:3.12-slim", "grafana/grafana:11"];
        let mut items = Vec::with_capacity(n_pods + n_svcs);
        for i in 0..n_pods {
            let img = repos[i % repos.len()];
            let ns = if i % 4 == 0 { "kube-system" } else { "default" };
            items.push(json!({
                "kind": "Pod",
                "metadata": {
                    "namespace": ns,
                    "name": format!("pod-app-{i}"),
                    "uid": format!("uid-{i:08}"),
                    "creationTimestamp": "2026-11-27T10:00:00Z",
                    "labels": {"app": format!("svc-{}", i % 10), "tier": "backend"},
                    "ownerReferences": [{"kind": "ReplicaSet"}]
                },
                "spec": {
                    "nodeName": "kiri",
                    "containers": [
                        {"name": "main", "image": img, "ports": [{"containerPort": 8080, "protocol": "TCP"}]},
                        {"name": "sidecar", "image": "envoyproxy/envoy:v1.31", "ports": [{"containerPort": 9901, "protocol": "TCP"}]}
                    ]
                },
                "status": {
                    "phase": if i % 9 == 0 { "Pending" } else { "Running" },
                    "podIP": format!("10.42.0.{}", (i % 240) + 2),
                    "containerStatuses": [
                        {"name": "main", "ready": i % 9 != 0, "restartCount": i % 3, "state": if i % 9 == 0 { json!({"waiting": {"reason": "CrashLoopBackOff", "message": "back-off"}}) } else { json!({"running": {"startedAt": "2026-11-27T10:01:00Z"}}) }},
                        {"name": "sidecar", "ready": true, "restartCount": 0, "state": {"running": {"startedAt": "2026-11-27T10:01:00Z"}}}
                    ]
                }
            }));
        }
        for i in 0..n_svcs {
            items.push(json!({
                "kind": "Service",
                "metadata": {"namespace": "default", "name": format!("svc-{i}"), "creationTimestamp": "2026-11-27T10:00:00Z"},
                "spec": {"type": if i % 3 == 0 { "LoadBalancer" } else { "ClusterIP" }, "clusterIP": format!("10.43.0.{}", i + 1), "ports": [{"port": 80, "targetPort": 8080, "protocol": "TCP"}], "selector": {"app": format!("svc-{i}")}},
                "status": {"loadBalancer": {"ingress": [{"ip": format!("172.17.0.{}", (i % 200) + 2)}]}}
            }));
        }
        let list = json!({"items": items});
        // Warmup
        let first = k8s_items::summarize(&list, false);
        assert_eq!(first["pods"].as_array().map(Vec::len), Some(n_pods));
        assert_eq!(first["services"].as_array().map(Vec::len), Some(n_svcs));

        let mut samples = Vec::with_capacity(15);
        let mut out_bytes = 0u64;
        let mut work_ops = 0u64;
        let mut errors = 0u64;
        for _ in 0..15 {
            let t0 = Instant::now();
            let v = k8s_items::summarize(black_box(&list), false);
            let s = v.to_string();
            let us = t0.elapsed().as_secs_f64() * 1e6;
            if v["pods"].as_array().map(Vec::len) == Some(n_pods) && v["services"].as_array().map(Vec::len) == Some(n_svcs) {
                out_bytes = s.len() as u64;
                black_box(&s);
                work_ops += (n_pods + n_svcs) as u64;
            } else {
                errors += 1;
            }
            samples.push(us);
        }
        emit_metric(name, "latency", workload, "us", &samples, out_bytes, work_ops, errors);
    }
}
