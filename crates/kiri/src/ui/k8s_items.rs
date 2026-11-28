//! What the page shows of `kubectl get pods,services -A -o json`, and the
//! names it may send back. Shared by the Mac window (ui/k8s.rs) and the
//! Windows one (crates/kiri-win/src/k8s.rs), which include it as a child
//! module; each parent provides `brand` (an image's logo) and `brands`.

use serde_json::{Map, Value, json};

use super::{brand, brands};

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

/// What the page shows of `kubectl get pods,services -A -o json`.
pub(super) fn summarize(list: &Value, starting: bool) -> Value {
    let items = list["items"].as_array().map(Vec::as_slice).unwrap_or_default();
    let mut used_brands = Map::new();
    insert_brand(&mut used_brands, "kubernetes");
    let pods: Vec<Value> = items.iter().filter(|i| i["kind"] == "Pod").map(|p| pod(p, &mut used_brands)).collect();
    let services: Vec<Value> = items.iter().filter(|i| i["kind"] == "Service").map(service).collect();
    let mut out = Map::with_capacity(8);
    out.insert("type".into(), "k8s".into());
    out.insert("state".into(), "running".into());
    out.insert("ready".into(), true.into());
    if starting {
        out.insert("starting".into(), true.into());
    }
    out.insert("icon".into(), "kubernetes".into());
    out.insert("brands".into(), Value::Object(used_brands));
    out.insert("pods".into(), Value::Array(pods));
    out.insert("services".into(), Value::Array(services));
    Value::Object(out)
}

/// One pod, with the status `kubectl get pods` would print for it.
fn pod(p: &Value, used_brands: &mut Map<String, Value>) -> Value {
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
        let mut cm = Map::with_capacity(8);
        cm.insert("name".into(), name.into());
        if !c["image"].is_null() {
            cm.insert("image".into(), c["image"].clone());
        }
        if s.is_some_and(|s| s["ready"].as_bool() == Some(true)) {
            cm.insert("ready".into(), true.into());
        }
        let restarts = s.and_then(|s| s["restartCount"].as_u64()).unwrap_or(0);
        if restarts > 0 {
            cm.insert("restarts".into(), restarts.into());
        }
        cm.insert("state".into(), state.into());
        if !reason.is_empty() {
            cm.insert("reason".into(), reason.into());
        }
        if !since.is_empty() {
            cm.insert("since".into(), since.into());
        }
        if let Some(exit) = s.map(|s| &s["state"]["terminated"]["exitCode"]).filter(|v| !v.is_null()) {
            cm.insert("exit".into(), exit.clone());
        }
        if let Some(msg) = s.map(|s| &s["state"]["waiting"]["message"]).filter(|v| !v.is_null()) {
            cm.insert("message".into(), msg.clone());
        }
        if let Some(ports) = c["ports"].as_array().filter(|a| !a.is_empty()) {
            cm.insert("ports".into(), Value::Array(ports.clone()));
        }
        containers.push(Value::Object(cm));
    }
    let ready = statuses.iter().filter(|s| s["ready"] == true).count();
    let restarts: u64 = statuses.iter().filter_map(|s| s["restartCount"].as_u64()).sum();
    let image = spec_containers.first().and_then(|c| c["image"].as_str()).unwrap_or_default();
    let mut pm = Map::with_capacity(14);
    if !meta["namespace"].is_null() {
        pm.insert("ns".into(), meta["namespace"].clone());
    }
    if !meta["name"].is_null() {
        pm.insert("name".into(), meta["name"].clone());
    }
    pm.insert("status".into(), status_of(p).into());
    pm.insert("ready".into(), format!("{ready}/{}", containers.len()).into());
    if ready == containers.len() && !containers.is_empty() {
        pm.insert("allReady".into(), true.into());
    }
    if restarts > 0 {
        pm.insert("restarts".into(), restarts.into());
    }
    if !meta["creationTimestamp"].is_null() {
        pm.insert("created".into(), meta["creationTimestamp"].clone());
    }
    if !st["podIP"].is_null() {
        pm.insert("ip".into(), st["podIP"].clone());
    }
    if !spec["nodeName"].is_null() {
        pm.insert("node".into(), spec["nodeName"].clone());
    }
    if let Some(owner) = meta["ownerReferences"].as_array().and_then(|a| a.first()).and_then(|o| o.get("kind")).filter(|v| !v.is_null()) {
        pm.insert("owner".into(), owner.clone());
    }
    if let Some(labels) = meta["labels"].as_object().filter(|m| !m.is_empty()) {
        pm.insert("labels".into(), Value::Object(labels.clone()));
    }
    pm.insert("containers".into(), Value::Array(containers));
    if let Some(slug) = brand(image) {
        insert_brand(used_brands, slug);
        pm.insert("icon".into(), slug.into());
    }
    Value::Object(pm)
}

/// The STATUS column of `kubectl get pods`: the phase, or what holds it up
/// (an init container, a waiting or failed container, a deletion).
fn status_of(p: &Value) -> String {
    let st = &p["status"];
    let mut reason = st["reason"].as_str().or(st["phase"].as_str()).unwrap_or("Unknown").to_owned();
    let inits = st["initContainerStatuses"].as_array().map(Vec::as_slice).unwrap_or_default();
    let total = p["spec"]["initContainers"].as_array().map_or(0, Vec::len);
    for (i, c) in inits.iter().enumerate() {
        let s = &c["state"];
        if s["terminated"]["exitCode"] == 0 && s["terminated"].is_object() {
            continue;
        }
        reason = if let Some(r) = s["terminated"]["reason"].as_str() {
            format!("Init:{r}")
        } else if s["terminated"].is_object() {
            format!("Init:ExitCode:{}", s["terminated"]["exitCode"])
        } else if let Some(r) = s["waiting"]["reason"].as_str().filter(|r| *r != "PodInitializing") {
            format!("Init:{r}")
        } else {
            format!("Init:{i}/{total}")
        };
        return deleting(p, reason);
    }
    let mut running = false;
    for c in st["containerStatuses"].as_array().into_iter().flatten().rev() {
        let s = &c["state"];
        if let Some(r) = s["waiting"]["reason"].as_str() {
            reason = r.to_owned();
        } else if let Some(r) = s["terminated"]["reason"].as_str() {
            reason = r.to_owned();
        } else if s["terminated"].is_object() {
            reason = format!("ExitCode:{}", s["terminated"]["exitCode"]);
        } else if s["running"].is_object() && c["ready"] == true {
            running = true;
        }
    }
    if reason == "Completed" && running {
        reason = "Running".into();
    }
    deleting(p, reason)
}

fn deleting(p: &Value, reason: String) -> String {
    if p["metadata"]["deletionTimestamp"].is_string() { "Terminating".into() } else { reason }
}

fn service(s: &Value) -> Value {
    let (meta, spec) = (&s["metadata"], &s["spec"]);
    let ingress: Vec<&str> = s["status"]["loadBalancer"]["ingress"].as_array().into_iter().flatten().filter_map(|i| i["ip"].as_str().or(i["hostname"].as_str())).collect();
    let mut sm = Map::with_capacity(8);
    if !meta["namespace"].is_null() {
        sm.insert("ns".into(), meta["namespace"].clone());
    }
    if !meta["name"].is_null() {
        sm.insert("name".into(), meta["name"].clone());
    }
    if !spec["type"].is_null() {
        sm.insert("type".into(), spec["type"].clone());
    }
    if !spec["clusterIP"].is_null() {
        sm.insert("clusterIP".into(), spec["clusterIP"].clone());
    }
    if let Some(ports) = spec["ports"].as_array().filter(|a| !a.is_empty()) {
        sm.insert("ports".into(), Value::Array(ports.clone()));
    }
    if !ingress.is_empty() {
        sm.insert("ingress".into(), json!(ingress));
    }
    if let Some(sel) = spec["selector"].as_object().filter(|m| !m.is_empty()) {
        sm.insert("selector".into(), Value::Object(sel.clone()));
    }
    if !meta["creationTimestamp"].is_null() {
        sm.insert("created".into(), meta["creationTimestamp"].clone());
    }
    Value::Object(sm)
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
             "spec": {"nodeName": "kiri", "containers": [{"name": "nginx", "image": "nginx"}, {"name": "side", "image": "busybox"}]},
             "status": {"phase": "Running", "podIP": "10.42.0.9", "containerStatuses": [
                {"name": "nginx", "ready": true, "restartCount": 1, "state": {"running": {"startedAt": "t"}}},
                {"name": "side", "ready": false, "restartCount": 2, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}},
            {"kind": "Service", "metadata": {"namespace": "default", "name": "web"}, "spec": {"type": "LoadBalancer", "clusterIP": "10.43.0.5",
             "ports": [{"port": 8080, "targetPort": 80, "protocol": "TCP"}]}, "status": {"loadBalancer": {"ingress": [{"ip": "172.17.0.2"}]}}},
        ]});
        let v = super::summarize(&list, false);
        let p = &v["pods"][0];
        assert_eq!((p["ready"].as_str(), p["restarts"].as_u64(), p["status"].as_str()), (Some("1/2"), Some(3), Some("CrashLoopBackOff")));
        assert_eq!((p["owner"].as_str(), p["containers"][1]["reason"].as_str()), (Some("ReplicaSet"), Some("CrashLoopBackOff")));
        assert_eq!(p["icon"].as_str(), Some("nginx"), "nginx has a logo slug");
        assert!(v["brands"]["nginx"].is_array(), "nginx logo is in brands map");
        let s = &v["services"][0];
        assert_eq!((s["type"].as_str(), s["ports"][0]["port"].as_u64(), s["ingress"][0].as_str()), (Some("LoadBalancer"), Some(8080), Some("172.17.0.2")));
        assert_eq!(v["icon"].as_str(), Some("kubernetes"), "the Kubernetes logo slug");
        assert!(v["brands"]["kubernetes"].is_array(), "the Kubernetes logo is in brands map");
    }

    #[test]
    fn only_kubernetes_names_reach_kubectl() {
        assert!(super::valid("web-5fc9f4bf66-cdl9f") && super::valid("kube-system") && super::valid("a.b"));
        assert!(!super::valid("") && !super::valid("--all") && !super::valid("Web") && !super::valid("a b") && !super::valid("a/b"));
    }
}
