//! What the page shows of `kubectl get pods,services -A -o json`, and the
//! names it may send back. Shared by the Mac window (ui/k8s.rs) and the
//! Windows one (crates/kiri-win/src/k8s.rs), which include it as a child
//! module; each parent provides `brand` (an image's logo) and `brands`.

use std::borrow::Cow;
use std::collections::HashMap;

use serde_json::{Map, Value, json};

use super::{brand, brands};

/// Deduplicated string table for repeating fields (`ns`, `image`, `created`,
/// `node`, `owner`, `labels`, etc.) in the compact `k8s` IPC snapshot.
struct StringPool {
    map: HashMap<String, usize>,
    list: Vec<Value>,
}

impl StringPool {
    fn new() -> Self {
        Self { map: HashMap::with_capacity(64), list: Vec::with_capacity(64) }
    }

    fn intern(&mut self, s: &str) -> Value {
        if let Some(&id) = self.map.get(s) {
            return Value::from(id);
        }
        let id = self.list.len();
        self.map.insert(s.to_owned(), id);
        self.list.push(Value::String(s.to_owned()));
        Value::from(id)
    }
}

fn trim_nulls(v: &mut Vec<Value>) {
    while matches!(v.last(), Some(Value::Null)) {
        v.pop();
    }
}

fn compact_kv(obj: &Map<String, Value>, pool: &mut StringPool) -> Value {
    let mut out = Vec::with_capacity(obj.len() * 2);
    for (k, v) in obj {
        out.push(pool.intern(k));
        match v.as_str() {
            Some(s) => out.push(pool.intern(s)),
            None => out.push(v.clone()),
        }
    }
    Value::Array(out)
}

/// A Kubernetes name (namespace, pod, container): DNS labels and subdomains.
pub(super) fn valid(name: &str) -> bool {
    name.len() <= 253
        && name.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn insert_brand(used: &mut Map<String, Value>, slug: &'static str) {
    if !used.contains_key(slug)
        && let Ok(i) = brands::BRANDS.binary_search_by_key(&slug, |(s, _, _)| s)
    {
        used.insert(slug.to_owned(), json!([brands::BRANDS[i].1, brands::BRANDS[i].2]));
    }
}

/// What the page shows of `kubectl get pods,services -A -o json`, encoded as
/// compact positional tuples + a deduplicated string table `"s"` unpacked by
/// `k8sOn` in `index.html`.
pub(super) fn summarize(list: &Value, starting: bool) -> Value {
    let items = list["items"].as_array().map(Vec::as_slice).unwrap_or_default();
    let mut used_brands = Map::new();
    insert_brand(&mut used_brands, "kubernetes");
    let mut pool = StringPool::new();
    let mut pods = Vec::new();
    let mut services = Vec::new();
    for item in items {
        match item["kind"].as_str() {
            Some("Pod") => pods.push(pod(item, &mut used_brands, &mut pool)),
            Some("Service") => services.push(service(item, &mut pool)),
            _ => {}
        }
    }
    let mut out = Map::with_capacity(9);
    out.insert("type".into(), "k8s".into());
    out.insert("state".into(), "running".into());
    out.insert("ready".into(), true.into());
    if starting {
        out.insert("starting".into(), true.into());
    }
    out.insert("icon".into(), "kubernetes".into());
    out.insert("brands".into(), Value::Object(used_brands));
    out.insert("s".into(), Value::Array(pool.list));
    out.insert("pods".into(), Value::Array(pods));
    out.insert("services".into(), Value::Array(services));
    Value::Object(out)
}

fn compact_container_ports(ports: &[Value]) -> Value {
    let out: Vec<Value> = ports
        .iter()
        .map(|p| {
            let Some(obj) = p.as_object() else { return p.clone() };
            let plain_tcp = obj.iter().all(|(k, v)| {
                (k == "containerPort" && v.is_u64()) || (k == "protocol" && v.as_str() == Some("TCP"))
            });
            if plain_tcp && let Some(cp) = obj.get("containerPort") {
                return cp.clone();
            }
            let mut m = Map::with_capacity(obj.len());
            for (k, v) in obj {
                if k == "protocol" && v.as_str() == Some("TCP") {
                    continue;
                }
                m.insert(k.clone(), v.clone());
            }
            Value::Object(m)
        })
        .collect();
    Value::Array(out)
}

fn compact_service_ports(ports: &[Value]) -> Value {
    let out: Vec<Value> = ports
        .iter()
        .map(|p| {
            let Some(obj) = p.as_object() else { return p.clone() };
            let plain_tcp = obj.iter().all(|(k, v)| {
                (k == "port" && v.is_u64())
                    || k == "targetPort"
                    || (k == "protocol" && v.as_str() == Some("TCP"))
            });
            if plain_tcp && let Some(port) = obj.get("port") {
                return match obj.get("targetPort") {
                    Some(tp) if tp != port => Value::Array(vec![port.clone(), tp.clone()]),
                    _ => port.clone(),
                };
            }
            let mut m = Map::with_capacity(obj.len());
            for (k, v) in obj {
                if k == "protocol" && v.as_str() == Some("TCP") {
                    continue;
                }
                m.insert(k.clone(), v.clone());
            }
            Value::Object(m)
        })
        .collect();
    Value::Array(out)
}

/// One pod, encoded as a positional tuple (trailing `null`s trimmed):
/// `[name, ready_count, containers, created, ip, node, owner, icon, labels, ns, status, restarts]`.
/// Each container is `[name, image, ready(0|1), since, ports, restarts, state, reason, exit, message]`.
fn pod(p: &Value, used_brands: &mut Map<String, Value>, pool: &mut StringPool) -> Value {
    let (meta, spec, st) = (&p["metadata"], &p["spec"], &p["status"]);
    let statuses = st["containerStatuses"].as_array().map(Vec::as_slice).unwrap_or_default();
    let spec_containers = spec["containers"].as_array().map(Vec::as_slice).unwrap_or_default();
    let mut containers = Vec::with_capacity(spec_containers.len());
    for c in spec_containers {
        let name = c["name"].as_str().unwrap_or_default();
        let s = statuses.iter().find(|s| s["name"].as_str() == Some(name));
        let (state, reason, since) = match s.and_then(|s| s["state"].as_object()).and_then(|o| o.iter().next()) {
            Some((k, v)) => (k.as_str(), v["reason"].as_str().unwrap_or_default(), v["startedAt"].as_str().or(v["finishedAt"].as_str()).unwrap_or_default()),
            None => ("waiting", "", ""),
        };
        let is_ready = s.is_some_and(|s| s["ready"].as_bool() == Some(true));
        let restarts = s.and_then(|s| s["restartCount"].as_u64()).unwrap_or(0);
        let exit = s.map(|s| &s["state"]["terminated"]["exitCode"]).filter(|v| !v.is_null());
        let msg = s.and_then(|s| s["state"]["waiting"]["message"].as_str());
        let mut ct = Vec::with_capacity(10);
        ct.push(pool.intern(name));
        ct.push(match c["image"].as_str() {
            Some(img) => pool.intern(img),
            None => Value::Null,
        });
        ct.push(Value::from(u8::from(is_ready)));
        ct.push(if since.is_empty() { Value::Null } else { pool.intern(since) });
        ct.push(match c["ports"].as_array().filter(|a| !a.is_empty()) {
            Some(ports) => compact_container_ports(ports),
            None => Value::Null,
        });
        ct.push(if restarts > 0 { Value::from(restarts) } else { Value::Null });
        ct.push(if state != "running" { pool.intern(state) } else { Value::Null });
        ct.push(if reason.is_empty() { Value::Null } else { pool.intern(reason) });
        ct.push(exit.cloned().unwrap_or(Value::Null));
        ct.push(match msg {
            Some(m) => pool.intern(m),
            None => Value::Null,
        });
        trim_nulls(&mut ct);
        containers.push(Value::Array(ct));
    }
    let ready = statuses.iter().filter(|s| s["ready"] == true).count();
    let restarts: u64 = statuses.iter().filter_map(|s| s["restartCount"].as_u64()).sum();
    let image = spec_containers.first().and_then(|c| c["image"].as_str()).unwrap_or_default();
    let status = status_of(p);
    let icon = brand(image).map(|slug| {
        insert_brand(used_brands, slug);
        pool.intern(slug)
    });
    let mut pt = Vec::with_capacity(12);
    pt.push(meta["name"].clone());
    pt.push(Value::from(ready));
    pt.push(Value::Array(containers));
    pt.push(match meta["creationTimestamp"].as_str() {
        Some(ts) => pool.intern(ts),
        None => Value::Null,
    });
    pt.push(st["podIP"].clone());
    pt.push(match spec["nodeName"].as_str() {
        Some(n) => pool.intern(n),
        None => Value::Null,
    });
    pt.push(match meta["ownerReferences"].as_array().and_then(|a| a.first()).and_then(|o| o.get("kind")).and_then(Value::as_str) {
        Some(o) => pool.intern(o),
        None => Value::Null,
    });
    pt.push(icon.unwrap_or(Value::Null));
    pt.push(match meta["labels"].as_object().filter(|m| !m.is_empty()) {
        Some(labels) => compact_kv(labels, pool),
        None => Value::Null,
    });
    pt.push(match meta["namespace"].as_str().filter(|&ns| ns != "default") {
        Some(ns) => pool.intern(ns),
        None => Value::Null,
    });
    pt.push(if status.as_ref() != "Running" { pool.intern(status.as_ref()) } else { Value::Null });
    pt.push(if restarts > 0 { Value::from(restarts) } else { Value::Null });
    trim_nulls(&mut pt);
    Value::Array(pt)
}

/// The STATUS column of `kubectl get pods`: the phase, or what holds it up
/// (an init container, a waiting or failed container, a deletion).
fn status_of<'a>(p: &'a Value) -> Cow<'a, str> {
    let st = &p["status"];
    let mut reason: Cow<'a, str> = Cow::Borrowed(st["reason"].as_str().or(st["phase"].as_str()).unwrap_or("Unknown"));
    let inits = st["initContainerStatuses"].as_array().map(Vec::as_slice).unwrap_or_default();
    let total = p["spec"]["initContainers"].as_array().map_or(0, Vec::len);
    for (i, c) in inits.iter().enumerate() {
        let s = &c["state"];
        if s["terminated"]["exitCode"] == 0 && s["terminated"].is_object() {
            continue;
        }
        reason = if let Some(r) = s["terminated"]["reason"].as_str() {
            Cow::Owned(format!("Init:{r}"))
        } else if s["terminated"].is_object() {
            Cow::Owned(format!("Init:ExitCode:{}", s["terminated"]["exitCode"]))
        } else if let Some(r) = s["waiting"]["reason"].as_str().filter(|r| *r != "PodInitializing") {
            Cow::Owned(format!("Init:{r}"))
        } else {
            Cow::Owned(format!("Init:{i}/{total}"))
        };
        return deleting(p, reason);
    }
    let mut running = false;
    for c in st["containerStatuses"].as_array().into_iter().flatten().rev() {
        let s = &c["state"];
        if let Some(r) = s["waiting"]["reason"].as_str() {
            reason = Cow::Borrowed(r);
        } else if let Some(r) = s["terminated"]["reason"].as_str() {
            reason = Cow::Borrowed(r);
        } else if s["terminated"].is_object() {
            reason = Cow::Owned(format!("ExitCode:{}", s["terminated"]["exitCode"]));
        } else if s["running"].is_object() && c["ready"] == true {
            running = true;
        }
    }
    if reason.as_ref() == "Completed" && running {
        reason = Cow::Borrowed("Running");
    }
    deleting(p, reason)
}

fn deleting<'a>(p: &Value, reason: Cow<'a, str>) -> Cow<'a, str> {
    if p["metadata"]["deletionTimestamp"].is_string() { Cow::Borrowed("Terminating") } else { reason }
}

/// One service, encoded as a positional tuple (trailing `null`s trimmed):
/// `[name, clusterIP, ports, created, selector, ns, type, ingress]`.
fn service(s: &Value, pool: &mut StringPool) -> Value {
    let (meta, spec) = (&s["metadata"], &s["spec"]);
    let ingress: Vec<Value> = s["status"]["loadBalancer"]["ingress"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|i| i["ip"].as_str().or(i["hostname"].as_str()))
        .map(|v| Value::String(v.to_owned()))
        .collect();
    let mut st = Vec::with_capacity(8);
    st.push(meta["name"].clone());
    st.push(spec["clusterIP"].clone());
    st.push(match spec["ports"].as_array().filter(|a| !a.is_empty()) {
        Some(ports) => compact_service_ports(ports),
        None => Value::Null,
    });
    st.push(match meta["creationTimestamp"].as_str() {
        Some(ts) => pool.intern(ts),
        None => Value::Null,
    });
    st.push(match spec["selector"].as_object().filter(|m| !m.is_empty()) {
        Some(sel) => compact_kv(sel, pool),
        None => Value::Null,
    });
    st.push(match meta["namespace"].as_str().filter(|&ns| ns != "default") {
        Some(ns) => pool.intern(ns),
        None => Value::Null,
    });
    st.push(match spec["type"].as_str().filter(|&t| t != "ClusterIP") {
        Some(ty) => pool.intern(ty),
        None => Value::Null,
    });
    st.push(if ingress.is_empty() { Value::Null } else { Value::Array(ingress) });
    trim_nulls(&mut st);
    Value::Array(st)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn pod_status_reads_as_kubectl_prints_it() {
        let running = json!({"metadata": {}, "spec": {"containers": [{"name": "a"}]}, "status": {"phase": "Running",
            "containerStatuses": [{"name": "a", "ready": true, "restartCount": 0, "state": {"running": {"startedAt": "2026-01-01T00:00:00Z"}}}]}});
        assert_eq!(super::status_of(&running), "Running");
        let crash = json!({"metadata": {}, "spec": {"containers": [{"name": "a"}]}, "status": {"phase": "Running",
            "containerStatuses": [{"name": "a", "ready": false, "restartCount": 4, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}});
        assert_eq!(super::status_of(&crash), "CrashLoopBackOff");
        let creating = json!({"metadata": {}, "spec": {"containers": [{"name": "a"}]}, "status": {"phase": "Pending",
            "containerStatuses": [{"name": "a", "ready": false, "state": {"waiting": {"reason": "ContainerCreating"}}}]}});
        assert_eq!(super::status_of(&creating), "ContainerCreating");
        let done = json!({"metadata": {}, "spec": {"containers": [{"name": "a"}]}, "status": {"phase": "Succeeded",
            "containerStatuses": [{"name": "a", "ready": false, "state": {"terminated": {"reason": "Completed", "exitCode": 0}}}]}});
        assert_eq!(super::status_of(&done), "Completed");
        let init = json!({"metadata": {}, "spec": {"initContainers": [{"name": "i"}, {"name": "j"}], "containers": [{"name": "a"}]}, "status": {"phase": "Pending",
            "initContainerStatuses": [{"name": "i", "state": {"terminated": {"exitCode": 0, "reason": "Completed"}}}, {"name": "j", "state": {"running": {}}}]}});
        assert_eq!(super::status_of(&init), "Init:1/2");
        let going = json!({"metadata": {"deletionTimestamp": "2026-01-01T00:00:00Z"}, "spec": {"containers": [{"name": "a"}]}, "status": {"phase": "Running"}});
        assert_eq!(super::status_of(&going), "Terminating");
    }

    #[test]
    fn summarizes_pods_and_services() {
        let list = json!({"items": [
            {"kind": "Pod", "metadata": {"namespace": "default", "name": "web-1", "labels": {"app": "web"}, "ownerReferences": [{"kind": "ReplicaSet"}]},
             "spec": {"nodeName": "kiri", "containers": [{"name": "nginx", "image": "nginx", "ports": [{"containerPort": 80, "protocol": "TCP"}]}, {"name": "side", "image": "busybox"}]},
             "status": {"phase": "Running", "podIP": "10.42.0.9", "containerStatuses": [
                {"name": "nginx", "ready": true, "restartCount": 1, "state": {"running": {"startedAt": "t"}}},
                {"name": "side", "ready": false, "restartCount": 2, "state": {"waiting": {"reason": "CrashLoopBackOff", "message": "oops"}}}]}},
            {"kind": "Service", "metadata": {"namespace": "default", "name": "web"}, "spec": {"type": "LoadBalancer", "clusterIP": "10.43.0.5",
             "ports": [{"port": 8080, "targetPort": 80, "protocol": "TCP"}, {"name": "dns", "port": 53, "protocol": "UDP"}]}, "status": {"loadBalancer": {"ingress": [{"ip": "172.17.0.2"}]}}},
        ]});
        let v = super::summarize(&list, false);
        fn resolve<'a>(st: &'a [serde_json::Value], val: &'a serde_json::Value) -> Option<&'a str> {
            val.as_u64().and_then(|i| st.get(i as usize)).and_then(|s| s.as_str()).or_else(|| val.as_str())
        }
        let st = v["s"].as_array().expect("string table");
        let p = v["pods"][0].as_array().expect("compact pod tuple");
        assert_eq!(p[0].as_str(), Some("web-1"));
        assert_eq!(p[1].as_u64(), Some(1), "1 of 2 containers ready");
        let cs = p[2].as_array().expect("containers");
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0][4], json!([80]), "plain TCP containerPort compacts to bare integer");
        assert_eq!(resolve(st, &cs[1][7]), Some("CrashLoopBackOff"));
        assert_eq!(resolve(st, &cs[1][9]), Some("oops"));
        assert_eq!(resolve(st, &p[6]), Some("ReplicaSet"));
        assert_eq!(resolve(st, &p[7]), Some("nginx"), "nginx has a logo slug");
        assert_eq!(resolve(st, &p[10]), Some("CrashLoopBackOff"));
        assert_eq!(p[11].as_u64(), Some(3));
        assert!(v["brands"]["nginx"].is_array(), "nginx logo is in brands map");
        let s = v["services"][0].as_array().expect("compact service tuple");
        assert_eq!(s[0].as_str(), Some("web"));
        assert_eq!(s[2][0], json!([8080, 80]), "plain TCP port+targetPort compacts to 2-tuple");
        assert_eq!(s[2][1]["protocol"].as_str(), Some("UDP"), "non-TCP named port kept as object");
        assert_eq!(resolve(st, &s[6]), Some("LoadBalancer"));
        assert_eq!(s[7][0].as_str(), Some("172.17.0.2"));
        assert_eq!(v["icon"].as_str(), Some("kubernetes"), "the Kubernetes logo slug");
        assert!(v["brands"]["kubernetes"].is_array(), "the Kubernetes logo is in brands map");
    }

    #[test]
    fn only_kubernetes_names_reach_kubectl() {
        assert!(super::valid("web-5fc9f4bf66-cdl9f") && super::valid("kube-system") && super::valid("a.b"));
        assert!(!super::valid("") && !super::valid("--all") && !super::valid("Web") && !super::valid("a b") && !super::valid("a/b"));
    }
}
