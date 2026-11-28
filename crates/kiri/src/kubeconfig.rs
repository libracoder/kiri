//! The cluster's entry in kubectl's own file, written by Kiri itself with
//! no kubectl: `kiri k8s` on the Mac and Linux (crates/kiri/src/k8s.rs) and
//! the window on Windows (crates/kiri-win/src/k8s.rs, which includes this
//! file) use it.
//!
//! The file is the first of `$KUBECONFIG`, else `.kube/config` in the home
//! folder (`%USERPROFILE%` on Windows), where kubectl looks. Only the
//! cluster, user and context named after the engine (`kiri`, `kiri-dev`,
//! …) are added, replaced or removed; every other line stays as it was, in
//! its place, comments too. `current-context` changes only when asked
//! (`kiri k8s start --use`), or a new file has ours. It is written to a
//! temporary file beside it and renamed over it, 0600.
//!
//! kubeconfigs are YAML as kubectl writes them, and as other tools (aws,
//! gcloud, k3d) write them too: top-level keys at the left edge and block
//! lists under `clusters`, `contexts` and `users`, flush or indented. That
//! is what is read here, line by line; a file in another shape (JSON, flow
//! lists) is left alone with an error, never rewritten.
//!
//! Input read from inside the `kiri-k8s` container (`/etc/rancher/k3s/k3s.yaml`)
//! is treated as untrusted: [`from_k3s`] / [`from_k3s_named`] never pass raw
//! lines through, strictly allowlist keys, reject `exec`, `auth-provider`,
//! host file paths, YAML anchors/aliases/tags, multi-document markers and flow
//! collections, validate inline credentials, and emit freshly formatted YAML.

use std::io;
use std::path::{Path, PathBuf};

/// The lists a context lives in.
const LISTS: [&str; 3] = ["clusters", "contexts", "users"];

/// kubectl's file: the first of `$KUBECONFIG`, else `.kube/config` at home.
pub fn path() -> Option<PathBuf> {
    #[cfg(windows)]
    let home = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME");
    pick(std::env::var_os("KUBECONFIG"), home.map(PathBuf::from))
}

fn pick(kubeconfig: Option<std::ffi::OsString>, home: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(first) = kubeconfig.as_deref().and_then(|l| std::env::split_paths(l).find(|p| !p.as_os_str().is_empty())) {
        return Some(first);
    }
    home.filter(|h| !h.as_os_str().is_empty()).map(|h| h.join(".kube").join("config"))
}

/// Parses and validates k3s' `/etc/rancher/k3s/k3s.yaml` against a strict
/// credential allowlist, emitting canonical YAML for the `kiri` context on
/// `https://127.0.0.1:{port}`.
pub fn from_k3s(raw: &str, port: u16) -> Result<String, String> {
    from_k3s_named(raw, "kiri", port)
}

/// Same as [`from_k3s`], naming the emitted cluster, context and user `name`
/// (`kiri` or `kiri-dev`).
pub fn from_k3s_named(raw: &str, name: &str, port: u16) -> Result<String, String> {
    if port == 0 {
        return Err("k3s API port must be non-zero".into());
    }
    if !valid_context_name(name) {
        return Err(format!("invalid kubeconfig context name {name:?}"));
    }
    if raw.is_empty() {
        return Err("empty k3s kubeconfig".into());
    }
    if raw.len() > 256 * 1024 {
        return Err("k3s kubeconfig exceeds 256 KiB".into());
    }
    // Reject tabs, NUL, DEL, and all ASCII/Unicode control characters except LF and CR,
    // and reject bare CR not followed by LF.
    let bytes = raw.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b == b'\t' {
            return Err(format!("tab character at byte {idx} is not allowed in k3s kubeconfig"));
        }
        if b == b'\r' && bytes.get(idx + 1) != Some(&b'\n') {
            return Err(format!("bare CR at byte {idx} is not allowed in k3s kubeconfig"));
        }
        if (b < 0x20 && b != b'\n' && b != b'\r') || b == 0x7f {
            return Err(format!("control character 0x{b:02x} is not allowed in k3s kubeconfig"));
        }
    }
    if raw.chars().any(|c| c != '\n' && c != '\r' && c.is_control()) {
        return Err("control characters are not allowed in k3s kubeconfig".into());
    }

    #[derive(Default)]
    struct ClusterIn {
        name: Option<String>,
        has_map: bool,
        ca_data: Option<String>,
        server: Option<String>,
    }
    #[derive(Default)]
    struct UserIn {
        name: Option<String>,
        has_map: bool,
        cert_data: Option<String>,
        key_data: Option<String>,
        token: Option<String>,
    }
    #[derive(Default)]
    struct ContextIn {
        name: Option<String>,
        has_map: bool,
        cluster: Option<String>,
        user: Option<String>,
        namespace: Option<String>,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        None,
        Preferences,
        Clusters { item_indent: Option<usize>, map_indent: Option<usize> },
        Users { item_indent: Option<usize>, map_indent: Option<usize> },
        Contexts { item_indent: Option<usize>, map_indent: Option<usize> },
    }

    let mut api_version: Option<String> = None;
    let mut kind: Option<String> = None;
    let mut current_context: Option<String> = None;
    let mut seen_preferences = false;
    let mut seen_clusters = false;
    let mut seen_users = false;
    let mut seen_contexts = false;
    let mut clusters: Vec<ClusterIn> = Vec::new();
    let mut users: Vec<UserIn> = Vec::new();
    let mut contexts: Vec<ContextIn> = Vec::new();
    let mut section = Section::None;

    for (lineno, raw_line) in raw.split('\n').enumerate() {
        let line_no = lineno + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let uncommented = strip_k3s_comment(line).map_err(|e| format!("line {line_no}: {e}"))?;
        let trimmed = uncommented.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "---" || trimmed == "..." || trimmed.starts_with("--- ") || trimmed.starts_with("... ") {
            return Err(format!("line {line_no}: multi-document YAML markers are not allowed"));
        }
        let line_indent = uncommented.len() - uncommented.trim_start_matches(' ').len();

        // Allow client-go's exact top-level `preferences: {}`, rejecting flow collections everywhere else.
        if line_indent == 0 && trimmed == "preferences: {}" {
            if seen_preferences {
                return Err(format!("line {line_no}: duplicate preferences key"));
            }
            seen_preferences = true;
            section = Section::None;
            continue;
        }
        for bad in ['{', '}', '[', ']'] {
            if uncommented.contains(bad) {
                return Err(format!("line {line_no}: YAML flow collection `{bad}` is not allowed"));
            }
        }
        for bad in ['&', '*', '!', '|', '>', '\\', '`'] {
            if uncommented.contains(bad) {
                return Err(format!("line {line_no}: YAML syntax `{bad}` is not allowed"));
            }
        }
        if uncommented.contains("<<") {
            return Err(format!("line {line_no}: YAML merge key `<<` is not allowed"));
        }
        let after_indent = &uncommented[line_indent..];
        if after_indent == "?" || after_indent.starts_with("? ") {
            return Err(format!("line {line_no}: complex YAML mapping keys are not allowed"));
        }

        // Top-level mapping entry (line_indent == 0, not starting with `-`).
        if line_indent == 0 && !after_indent.starts_with('-') {
            let (key, val) = split_kv(after_indent).ok_or_else(|| format!("line {line_no}: expected key: value"))?;
            match key {
                "apiVersion" => {
                    if api_version.is_some() {
                        return Err(format!("line {line_no}: duplicate apiVersion"));
                    }
                    let v = unquote_scalar(val).map_err(|e| format!("line {line_no}: {e}"))?;
                    if v != "v1" {
                        return Err(format!("line {line_no}: unsupported apiVersion {v:?}"));
                    }
                    api_version = Some(v);
                    section = Section::None;
                }
                "kind" => {
                    if kind.is_some() {
                        return Err(format!("line {line_no}: duplicate kind"));
                    }
                    let v = unquote_scalar(val).map_err(|e| format!("line {line_no}: {e}"))?;
                    if v != "Config" {
                        return Err(format!("line {line_no}: unsupported kind {v:?}"));
                    }
                    kind = Some(v);
                    section = Section::None;
                }
                "current-context" => {
                    if current_context.is_some() {
                        return Err(format!("line {line_no}: duplicate current-context"));
                    }
                    let v = unquote_scalar(val).map_err(|e| format!("line {line_no}: {e}"))?;
                    if !valid_scalar_ident(&v) {
                        return Err(format!("line {line_no}: invalid current-context {v:?}"));
                    }
                    current_context = Some(v);
                    section = Section::None;
                }
                "preferences" => {
                    if seen_preferences {
                        return Err(format!("line {line_no}: duplicate preferences"));
                    }
                    if !val.is_empty() {
                        return Err(format!("line {line_no}: non-empty preferences value is not allowed"));
                    }
                    seen_preferences = true;
                    section = Section::Preferences;
                }
                "clusters" => {
                    if seen_clusters {
                        return Err(format!("line {line_no}: duplicate clusters"));
                    }
                    if !val.is_empty() {
                        return Err(format!("line {line_no}: clusters must be a block sequence"));
                    }
                    seen_clusters = true;
                    section = Section::Clusters { item_indent: None, map_indent: None };
                }
                "users" => {
                    if seen_users {
                        return Err(format!("line {line_no}: duplicate users"));
                    }
                    if !val.is_empty() {
                        return Err(format!("line {line_no}: users must be a block sequence"));
                    }
                    seen_users = true;
                    section = Section::Users { item_indent: None, map_indent: None };
                }
                "contexts" => {
                    if seen_contexts {
                        return Err(format!("line {line_no}: duplicate contexts"));
                    }
                    if !val.is_empty() {
                        return Err(format!("line {line_no}: contexts must be a block sequence"));
                    }
                    seen_contexts = true;
                    section = Section::Contexts { item_indent: None, map_indent: None };
                }
                other => return Err(format!("line {line_no}: unknown top-level key {other:?}")),
            }
            continue;
        }

        match &mut section {
            Section::None => return Err(format!("line {line_no}: unexpected indented line")),
            Section::Preferences => return Err(format!("line {line_no}: preferences entries are not allowed")),
            Section::Clusters { item_indent, map_indent } => {
                if let Some(rest) = strip_list_dash(after_indent) {
                    let expected = *item_indent.get_or_insert(line_indent);
                    if line_indent != expected {
                        return Err(format!("line {line_no}: inconsistent cluster item indentation"));
                    }
                    if !clusters.is_empty() {
                        return Err(format!("line {line_no}: clusters may contain at most 1 item"));
                    }
                    clusters.push(ClusterIn::default());
                    *map_indent = None;
                    let rest = rest.trim();
                    if !rest.is_empty() {
                        parse_cluster_item_kv(rest, map_indent, clusters.last_mut().unwrap(), line_no)?;
                    }
                } else {
                    let Some(item_ind) = *item_indent else {
                        return Err(format!("line {line_no}: expected `-` item under clusters"));
                    };
                    let cur = clusters.last_mut().ok_or_else(|| format!("line {line_no}: missing cluster item"))?;
                    if line_indent == item_ind + 2 {
                        *map_indent = None;
                        parse_cluster_item_kv(after_indent.trim_end(), map_indent, cur, line_no)?;
                    } else if let Some(m_ind) = *map_indent {
                        if line_indent <= item_ind + 2 || (m_ind != 0 && line_indent != m_ind) {
                            return Err(format!("line {line_no}: invalid indentation inside cluster"));
                        }
                        *map_indent = Some(line_indent);
                        let (k, v) = split_kv(after_indent.trim_end()).ok_or_else(|| format!("line {line_no}: expected key: value in cluster"))?;
                        match k {
                            "certificate-authority-data" => {
                                if cur.ca_data.is_some() {
                                    return Err(format!("line {line_no}: duplicate certificate-authority-data"));
                                }
                                let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                                validate_base64(&val).map_err(|e| format!("line {line_no}: certificate-authority-data: {e}"))?;
                                cur.ca_data = Some(val);
                            }
                            "server" => {
                                if cur.server.is_some() {
                                    return Err(format!("line {line_no}: duplicate server"));
                                }
                                let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                                if !val.starts_with("https://") || val.len() <= "https://".len() || !val.bytes().all(|b| b.is_ascii_graphic()) {
                                    return Err(format!("line {line_no}: invalid cluster server URL"));
                                }
                                cur.server = Some(val);
                            }
                            other => return Err(format!("line {line_no}: disallowed cluster key {other:?}")),
                        }
                    } else {
                        return Err(format!("line {line_no}: unexpected indentation under clusters"));
                    }
                }
            }
            Section::Users { item_indent, map_indent } => {
                if let Some(rest) = strip_list_dash(after_indent) {
                    let expected = *item_indent.get_or_insert(line_indent);
                    if line_indent != expected {
                        return Err(format!("line {line_no}: inconsistent user item indentation"));
                    }
                    if !users.is_empty() {
                        return Err(format!("line {line_no}: users may contain at most 1 item"));
                    }
                    users.push(UserIn::default());
                    *map_indent = None;
                    let rest = rest.trim();
                    if !rest.is_empty() {
                        parse_user_item_kv(rest, map_indent, users.last_mut().unwrap(), line_no)?;
                    }
                } else {
                    let Some(item_ind) = *item_indent else {
                        return Err(format!("line {line_no}: expected `-` item under users"));
                    };
                    let cur = users.last_mut().ok_or_else(|| format!("line {line_no}: missing user item"))?;
                    if line_indent == item_ind + 2 {
                        *map_indent = None;
                        parse_user_item_kv(after_indent.trim_end(), map_indent, cur, line_no)?;
                    } else if let Some(m_ind) = *map_indent {
                        if line_indent <= item_ind + 2 || (m_ind != 0 && line_indent != m_ind) {
                            return Err(format!("line {line_no}: invalid indentation inside user"));
                        }
                        *map_indent = Some(line_indent);
                        let (k, v) = split_kv(after_indent.trim_end()).ok_or_else(|| format!("line {line_no}: expected key: value in user"))?;
                        match k {
                            "client-certificate-data" => {
                                if cur.cert_data.is_some() {
                                    return Err(format!("line {line_no}: duplicate client-certificate-data"));
                                }
                                let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                                validate_base64(&val).map_err(|e| format!("line {line_no}: client-certificate-data: {e}"))?;
                                cur.cert_data = Some(val);
                            }
                            "client-key-data" => {
                                if cur.key_data.is_some() {
                                    return Err(format!("line {line_no}: duplicate client-key-data"));
                                }
                                let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                                validate_base64(&val).map_err(|e| format!("line {line_no}: client-key-data: {e}"))?;
                                cur.key_data = Some(val);
                            }
                            "token" => {
                                if cur.token.is_some() {
                                    return Err(format!("line {line_no}: duplicate token"));
                                }
                                let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                                validate_token(&val).map_err(|e| format!("line {line_no}: token: {e}"))?;
                                cur.token = Some(val);
                            }
                            other => return Err(format!("line {line_no}: disallowed user key {other:?}")),
                        }
                    } else {
                        return Err(format!("line {line_no}: unexpected indentation under users"));
                    }
                }
            }
            Section::Contexts { item_indent, map_indent } => {
                if let Some(rest) = strip_list_dash(after_indent) {
                    let expected = *item_indent.get_or_insert(line_indent);
                    if line_indent != expected {
                        return Err(format!("line {line_no}: inconsistent context item indentation"));
                    }
                    if !contexts.is_empty() {
                        return Err(format!("line {line_no}: contexts may contain at most 1 item"));
                    }
                    contexts.push(ContextIn::default());
                    *map_indent = None;
                    let rest = rest.trim();
                    if !rest.is_empty() {
                        parse_context_item_kv(rest, map_indent, contexts.last_mut().unwrap(), line_no)?;
                    }
                } else {
                    let Some(item_ind) = *item_indent else {
                        return Err(format!("line {line_no}: expected `-` item under contexts"));
                    };
                    let cur = contexts.last_mut().ok_or_else(|| format!("line {line_no}: missing context item"))?;
                    if line_indent == item_ind + 2 {
                        *map_indent = None;
                        parse_context_item_kv(after_indent.trim_end(), map_indent, cur, line_no)?;
                    } else if let Some(m_ind) = *map_indent {
                        if line_indent <= item_ind + 2 || (m_ind != 0 && line_indent != m_ind) {
                            return Err(format!("line {line_no}: invalid indentation inside context"));
                        }
                        *map_indent = Some(line_indent);
                        let (k, v) = split_kv(after_indent.trim_end()).ok_or_else(|| format!("line {line_no}: expected key: value in context"))?;
                        match k {
                            "cluster" => {
                                if cur.cluster.is_some() {
                                    return Err(format!("line {line_no}: duplicate context.cluster"));
                                }
                                let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                                if !valid_scalar_ident(&val) {
                                    return Err(format!("line {line_no}: invalid context.cluster {val:?}"));
                                }
                                cur.cluster = Some(val);
                            }
                            "user" => {
                                if cur.user.is_some() {
                                    return Err(format!("line {line_no}: duplicate context.user"));
                                }
                                let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                                if !valid_scalar_ident(&val) {
                                    return Err(format!("line {line_no}: invalid context.user {val:?}"));
                                }
                                cur.user = Some(val);
                            }
                            "namespace" => {
                                if cur.namespace.is_some() {
                                    return Err(format!("line {line_no}: duplicate context.namespace"));
                                }
                                let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                                if !valid_dns_label(&val) {
                                    return Err(format!("line {line_no}: invalid context.namespace {val:?}"));
                                }
                                cur.namespace = Some(val);
                            }
                            other => return Err(format!("line {line_no}: disallowed context key {other:?}")),
                        }
                    } else {
                        return Err(format!("line {line_no}: unexpected indentation under contexts"));
                    }
                }
            }
        }

        fn parse_cluster_item_kv(rest: &str, map_indent: &mut Option<usize>, cur: &mut ClusterIn, line_no: usize) -> Result<(), String> {
            let (k, v) = split_kv(rest).ok_or_else(|| format!("line {line_no}: expected key: value in cluster item"))?;
            match k {
                "name" => {
                    if cur.name.is_some() {
                        return Err(format!("line {line_no}: duplicate cluster item name"));
                    }
                    let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                    if !valid_scalar_ident(&val) {
                        return Err(format!("line {line_no}: invalid cluster name {val:?}"));
                    }
                    cur.name = Some(val);
                }
                "cluster" => {
                    if cur.has_map {
                        return Err(format!("line {line_no}: duplicate cluster map"));
                    }
                    if !v.is_empty() {
                        return Err(format!("line {line_no}: cluster value must be a nested mapping"));
                    }
                    cur.has_map = true;
                    *map_indent = Some(0);
                }
                other => return Err(format!("line {line_no}: disallowed cluster item key {other:?}")),
            }
            Ok(())
        }

        fn parse_user_item_kv(rest: &str, map_indent: &mut Option<usize>, cur: &mut UserIn, line_no: usize) -> Result<(), String> {
            let (k, v) = split_kv(rest).ok_or_else(|| format!("line {line_no}: expected key: value in user item"))?;
            match k {
                "name" => {
                    if cur.name.is_some() {
                        return Err(format!("line {line_no}: duplicate user item name"));
                    }
                    let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                    if !valid_scalar_ident(&val) {
                        return Err(format!("line {line_no}: invalid user name {val:?}"));
                    }
                    cur.name = Some(val);
                }
                "user" => {
                    if cur.has_map {
                        return Err(format!("line {line_no}: duplicate user map"));
                    }
                    if !v.is_empty() {
                        return Err(format!("line {line_no}: user value must be a nested mapping"));
                    }
                    cur.has_map = true;
                    *map_indent = Some(0);
                }
                other => return Err(format!("line {line_no}: disallowed user item key {other:?}")),
            }
            Ok(())
        }

        fn parse_context_item_kv(rest: &str, map_indent: &mut Option<usize>, cur: &mut ContextIn, line_no: usize) -> Result<(), String> {
            let (k, v) = split_kv(rest).ok_or_else(|| format!("line {line_no}: expected key: value in context item"))?;
            match k {
                "name" => {
                    if cur.name.is_some() {
                        return Err(format!("line {line_no}: duplicate context item name"));
                    }
                    let val = unquote_scalar(v).map_err(|e| format!("line {line_no}: {e}"))?;
                    if !valid_scalar_ident(&val) {
                        return Err(format!("line {line_no}: invalid context name {val:?}"));
                    }
                    cur.name = Some(val);
                }
                "context" => {
                    if cur.has_map {
                        return Err(format!("line {line_no}: duplicate context map"));
                    }
                    if !v.is_empty() {
                        return Err(format!("line {line_no}: context value must be a nested mapping"));
                    }
                    cur.has_map = true;
                    *map_indent = Some(0);
                }
                other => return Err(format!("line {line_no}: disallowed context item key {other:?}")),
            }
            Ok(())
        }
    }

    if api_version.as_deref() != Some("v1") {
        return Err("missing apiVersion: v1".into());
    }
    if kind.as_deref() != Some("Config") {
        return Err("missing kind: Config".into());
    }
    let Some(cluster) = clusters.pop() else {
        return Err("missing cluster entry in k3s kubeconfig".into());
    };
    if cluster.name.is_none() || !cluster.has_map {
        return Err("incomplete cluster entry in k3s kubeconfig".into());
    }
    let Some(ca_data) = cluster.ca_data else {
        return Err("missing cluster certificate-authority-data".into());
    };
    if cluster.server.is_none() {
        return Err("missing cluster server".into());
    }

    let Some(user) = users.pop() else {
        return Err("missing user entry in k3s kubeconfig".into());
    };
    if user.name.is_none() || !user.has_map {
        return Err("incomplete user entry in k3s kubeconfig".into());
    }
    if user.cert_data.is_some() != user.key_data.is_some() {
        return Err("user must provide both client-certificate-data and client-key-data".into());
    }
    let has_cert_pair = user.cert_data.is_some() && user.key_data.is_some();
    if !has_cert_pair && user.token.is_none() {
        return Err("user must have client-certificate-data + client-key-data or token".into());
    }

    let namespace = if let Some(ctx) = contexts.pop() {
        if ctx.name.is_none() || !ctx.has_map || ctx.cluster.is_none() || ctx.user.is_none() {
            return Err("incomplete context entry in k3s kubeconfig".into());
        }
        ctx.namespace
    } else {
        None
    };

    let mut out = String::new();
    out.push_str("apiVersion: v1\n");
    out.push_str("clusters:\n");
    out.push_str("- cluster:\n");
    out.push_str(&format!("    certificate-authority-data: {ca_data}\n"));
    out.push_str(&format!("    server: https://127.0.0.1:{port}\n"));
    out.push_str(&format!("  name: {name}\n"));
    out.push_str("contexts:\n");
    out.push_str("- context:\n");
    out.push_str(&format!("    cluster: {name}\n"));
    if let Some(ns) = namespace {
        out.push_str(&format!("    namespace: {ns}\n"));
    }
    out.push_str(&format!("    user: {name}\n"));
    out.push_str(&format!("  name: {name}\n"));
    out.push_str(&format!("current-context: {name}\n"));
    out.push_str("kind: Config\n");
    out.push_str("users:\n");
    out.push_str(&format!("- name: {name}\n"));
    out.push_str("  user:\n");
    if let (Some(cert), Some(key)) = (user.cert_data, user.key_data) {
        out.push_str(&format!("    client-certificate-data: {cert}\n"));
        out.push_str(&format!("    client-key-data: {key}\n"));
    }
    if let Some(tok) = user.token {
        out.push_str(&format!("    token: {tok}\n"));
    }
    Ok(out)
}

fn valid_context_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_dns_label(s: &str) -> bool {
    valid_context_name(s)
}

fn valid_scalar_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn strip_k3s_comment(line: &str) -> Result<&str, &'static str> {
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' && q == b'"' {
                return Err("backslash escapes in double-quoted strings are not allowed");
            }
            if b == q {
                if q == b'\'' && bytes.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                quote = None;
            }
        } else if b == b'\'' || b == b'"' {
            quote = Some(b);
        } else if b == b'#' && (i == 0 || bytes[i - 1] == b' ') {
            return Ok(&line[..i]);
        }
        i += 1;
    }
    if quote.is_some() {
        return Err("unclosed quote");
    }
    Ok(line)
}

fn strip_list_dash(after_indent: &str) -> Option<&str> {
    if after_indent == "-" {
        Some("")
    } else {
        after_indent.strip_prefix("- ")
    }
}

fn split_kv(s: &str) -> Option<(&str, &str)> {
    let (k, rest) = s.split_once(':')?;
    if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    if !rest.is_empty() && !rest.starts_with(' ') {
        return None;
    }
    Some((k, rest.trim()))
}

fn unquote_scalar(v: &str) -> Result<String, &'static str> {
    let v = v.trim();
    if v.is_empty() {
        return Err("empty value");
    }
    if (v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')) {
        if v.len() < 2 {
            return Err("malformed quoted scalar");
        }
        let q = v.as_bytes()[0];
        let inner = &v[1..v.len() - 1];
        if q == b'"' && (inner.contains('"') || inner.contains('\\')) {
            return Err("unexpected quote or escape inside double-quoted scalar");
        }
        if q == b'\'' && inner.replace("''", "").contains('\'') {
            return Err("unexpected quote inside single-quoted scalar");
        }
        let unescaped = if q == b'\'' { inner.replace("''", "'") } else { inner.to_owned() };
        if unescaped.is_empty() {
            return Err("empty quoted value");
        }
        return Ok(unescaped);
    }
    if v.contains(['\'', '"', '#']) || v.split_whitespace().count() != 1 {
        return Err("unquoted scalar must be a single token without quotes");
    }
    Ok(v.to_owned())
}

fn validate_base64(s: &str) -> Result<(), &'static str> {
    if s.is_empty() || !s.len().is_multiple_of(4) {
        return Err("must be non-empty standard base64");
    }
    let eq_pos = s.find('=').unwrap_or(s.len());
    let pad = s.len() - eq_pos;
    if pad > 2 || !s[eq_pos..].bytes().all(|b| b == b'=') {
        return Err("invalid base64 padding");
    }
    let b64_val = |b: u8| -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    for &b in &s.as_bytes()[..eq_pos] {
        if b64_val(b).is_none() {
            return Err("invalid base64 character");
        }
    }
    // Check canonical zero padding bits on trailing quantum so mutated padding cannot slip by.
    if pad == 1 {
        let last = b64_val(s.as_bytes()[eq_pos - 1]).unwrap();
        if last & 0b0011 != 0 {
            return Err("non-canonical base64 padding bits");
        }
    } else if pad == 2 {
        let last = b64_val(s.as_bytes()[eq_pos - 1]).unwrap();
        if last & 0b1111 != 0 {
            return Err("non-canonical base64 padding bits");
        }
    }
    Ok(())
}

fn validate_token(s: &str) -> Result<(), &'static str> {
    if s.is_empty() || s.len() > 8192 {
        return Err("must be non-empty and <= 8192 bytes");
    }
    let eq_pos = s.find('=').unwrap_or(s.len());
    if !s[eq_pos..].bytes().all(|b| b == b'=') || eq_pos == 0 {
        return Err("invalid trailing `=` padding in token");
    }
    if !s.as_bytes()[..eq_pos]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'-'))
    {
        return Err("invalid character in token");
    }
    Ok(())
}

/// `ours`' cluster, user and context called `name` put into the file at
/// `path` (made if missing). Whether the file changed.
pub fn install(path: &Path, ours: &str, name: &str, use_context: bool) -> io::Result<bool> {
    let path = real(path);
    let before = read(&path)?;
    let after = merge(before.as_deref().unwrap_or(""), ours, name, use_context).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
    if before.as_deref() == Some(after.as_str()) {
        return Ok(false);
    }
    write(&path, before.as_deref(), &after)?;
    Ok(true)
}

/// The cluster, user and context called `name` taken out of the file at
/// `path`. Whether the file changed.
pub fn uninstall(path: &Path, name: &str) -> io::Result<bool> {
    let path = real(path);
    let Some(before) = read(&path)? else { return Ok(false) };
    let after = remove(&before, name).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
    if after == before {
        return Ok(false);
    }
    write(&path, Some(&before), &after)?;
    Ok(true)
}

/// A link (dotfiles kept elsewhere) is followed, so the rename replaces
/// its target rather than the link.
fn real(path: &Path) -> PathBuf {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned()),
        _ => path.to_owned(),
    }
}

fn read(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The new text by a temporary file and a rename, 0600; the one before it
/// kept as `config.bak.kiri`.
fn write(path: &Path, before: Option<&str>, text: &str) -> io::Result<()> {
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("config");
    if let Some(before) = before {
        let backup = dir.join(format!("{file}.bak.kiri"));
        std::fs::write(&backup, before)?;
        private(&backup)?;
    }
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = dir.join(format!(".{file}.kiri-{}-{seq}", std::process::id()));
    let done = std::fs::write(&tmp, text).and_then(|()| private(&tmp)).and_then(|()| std::fs::rename(&tmp, path));
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done
}

#[cfg(unix)]
fn private(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
}

// %USERPROFILE% is the user's own already.
#[cfg(not(unix))]
fn private(_: &Path) -> io::Result<()> {
    Ok(())
}

/// One top-level key and the lines under it (the first is the key's own);
/// the lines before any key have the key "".
struct Top<'a> {
    key: &'a str,
    lines: Vec<&'a str>,
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start_matches(' ').len()
}

fn blank(l: &str) -> bool {
    let t = l.trim();
    t.is_empty() || t.starts_with('#')
}

/// Strips a YAML `#` comment starting at index 0 or preceded by whitespace.
fn uncomment(s: &str) -> &str {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t')) {
            return &s[..i];
        }
    }
    s
}

fn is_doc_marker(l: &str, marker: &str) -> bool {
    uncomment(l).trim_end() == marker
}

fn tops(text: &str) -> Result<Vec<Top<'_>>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut tops = vec![Top { key: "", lines: Vec::new() }];
    let mut seen_content = false;
    let mut seen_end = false;
    for l in text.lines() {
        if seen_end && !blank(l) {
            return Err("a multi-document kubeconfig; not changing it".into());
        }
        if is_doc_marker(l, "---") {
            if seen_content {
                return Err("a multi-document kubeconfig; not changing it".into());
            }
            tops.last_mut().expect("there is one").lines.push(l);
            continue;
        }
        if is_doc_marker(l, "...") {
            seen_end = true;
            tops.push(Top { key: "...", lines: vec![l] });
            continue;
        }
        if !blank(l) {
            seen_content = true;
        }
        let top = !l.starts_with([' ', '\t', '-', '#']) && !l.trim().is_empty();
        match l.split_once(':').filter(|_| top) {
            Some((key, _)) => tops.push(Top { key: key.trim(), lines: vec![l] }),
            None => tops.last_mut().expect("there is one").lines.push(l),
        }
    }
    Ok(tops)
}

/// The lines before a list's first item, its items (each its lines), and their indent.
type Items<'a> = (Vec<&'a str>, Vec<Vec<&'a str>>, usize);

/// A list's items; an error for a list that isn't a block list.
fn items<'a>(top: &Top<'a>) -> Result<Items<'a>, String> {
    let value = uncomment(top.lines[0].split_once(':').map_or("", |(_, v)| v)).trim();
    if !matches!(value, "" | "[]" | "null" | "~") {
        return Err(format!("`{}` is not a list kubectl writes; not changing it", top.key));
    }
    let body = &top.lines[1..];
    let at = body.iter().position(|l| !blank(l) && l.trim_start().starts_with('-'));
    let Some(at) = at else { return Ok((body.to_vec(), Vec::new(), 0)) };
    let dash = indent(body[at]);
    let mut items: Vec<Vec<&str>> = Vec::new();
    for &l in &body[at..] {
        if indent(l) == dash && l.trim_start().starts_with('-') {
            items.push(vec![l]);
        } else {
            items.last_mut().expect("starts with one").push(l);
        }
    }
    Ok((body[..at].to_vec(), items, dash))
}

/// An item's `name`, the key at the column after its dash (or on the lines below a bare `-`).
fn item_name<'a>(item: &[&'a str], dash: usize) -> Option<&'a str> {
    let rest = &item[0][dash + 1..];
    let first = rest.trim_start();
    let has_inline_key = !blank(rest);
    let col = if has_inline_key {
        dash + 1 + indent(rest)
    } else {
        item[1..].iter().find(|l| !blank(l)).map(|l| indent(l)).filter(|&c| c > dash)?
    };
    let match_name = |s: &'a str| {
        s.strip_prefix("name:")
            .filter(|after| after.is_empty() || after.starts_with([' ', '\t', '#']))
            .map(scalar)
    };
    if has_inline_key && let Some(n) = match_name(first) {
        return Some(n);
    }
    item[1..].iter().filter(|l| indent(l) == col).find_map(|l| match_name(l.trim_start()))
}

/// A plain or quoted YAML scalar, without a trailing comment.
fn scalar(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|r| r.split(q).next()) {
            return inner;
        }
    }
    uncomment(v).trim()
}

fn not_json(text: &str) -> Result<(), String> {
    if text.strip_prefix('\u{feff}').unwrap_or(text).trim_start().starts_with('{') {
        return Err("a JSON kubeconfig; not changing it".into());
    }
    Ok(())
}

/// The file's line ending: Windows editors may have left CRLF.
fn newline(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

fn join(lines: &[String], nl: &str) -> String {
    let mut out = lines.join(nl);
    out.push_str(nl);
    out
}

/// `existing` with `ours`' cluster, user and context called `name` in
/// place of any it had; the rest of it as it was.
pub fn merge(existing: &str, ours: &str, name: &str, use_context: bool) -> Result<String, String> {
    not_json(existing)?;
    if existing.trim().is_empty() {
        // A new file: ours as it is, its context the current one.
        return Ok(ours.to_owned());
    }
    // Ours, per list: the item called `name`, its lines from its dash on.
    let theirs = tops(ours)?;
    let mut new: Vec<(&str, Vec<String>)> = Vec::new();
    for list in LISTS {
        let Some(top) = theirs.iter().find(|t| t.key == list) else { continue };
        let (_, items, dash) = items(top)?;
        if let Some(item) = items.iter().find(|i| item_name(i, dash) == Some(name)) {
            new.push((list, item.iter().map(|l| l.get(dash..).unwrap_or("").trim_end().to_owned()).collect()));
        }
    }
    let nl = newline(existing);
    let mut out: Vec<String> = Vec::new();
    let mut doc_end: Vec<String> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    let mut current = false;
    for top in tops(existing)? {
        if top.key == "..." {
            doc_end.extend(top.lines.iter().map(|l| l.to_string()));
            continue;
        }
        if top.key == "current-context" && use_context {
            out.push(format!("current-context: {name}"));
            out.extend(top.lines[1..].iter().map(|l| l.to_string()));
            current = true;
            continue;
        }
        let Some((_, lines)) = new.iter().find(|(l, _)| *l == top.key) else {
            out.extend(top.lines.iter().map(|l| l.to_string()));
            continue;
        };
        seen.push(top.key);
        let (before, items, dash) = items(&top)?;
        let dash = if items.is_empty() { 0 } else { dash };
        let header_val = uncomment(top.lines[0].split_once(':').map_or("", |(_, v)| v)).trim();
        out.push(if header_val.is_empty() { top.lines[0].to_owned() } else { format!("{}:", top.key) });
        out.extend(before.iter().map(|l| l.to_string()));
        let kept: Vec<&Vec<&str>> = items.iter().filter(|i| item_name(i, dash) != Some(name)).collect();
        let mut body: Vec<String> = kept.iter().flat_map(|i| i.iter().map(|l| l.to_string())).collect();
        // Ours after the list's last line, before blank lines and comments that close it.
        let at = body.iter().rposition(|l| !blank(l)).map_or(0, |i| i + 1);
        let pad = " ".repeat(dash);
        body.splice(at..at, lines.iter().map(|l| if l.is_empty() { String::new() } else { format!("{pad}{l}") }));
        out.extend(body);
    }
    // Lists the file didn't have, and the current context if asked for.
    for (list, lines) in &new {
        if !seen.contains(list) {
            out.push(format!("{list}:"));
            out.extend(lines.iter().cloned());
        }
    }
    if use_context && !current {
        out.push(format!("current-context: {name}"));
    }
    out.extend(doc_end);
    Ok(join(&out, nl))
}

/// `existing` without the cluster, user and context called `name`; a
/// current context that was it is cleared.
pub fn remove(existing: &str, name: &str) -> Result<String, String> {
    not_json(existing)?;
    if existing.trim().is_empty() {
        return Ok(existing.to_owned());
    }
    let mut out: Vec<String> = Vec::new();
    let mut changed = false;
    for top in tops(existing)? {
        if top.key == "current-context" && scalar(top.lines[0].split_once(':').map_or("", |(_, v)| v)) == name {
            out.push("current-context: \"\"".into());
            out.extend(top.lines[1..].iter().map(|l| l.to_string()));
            changed = true;
            continue;
        }
        if !LISTS.contains(&top.key) {
            out.extend(top.lines.iter().map(|l| l.to_string()));
            continue;
        }
        let (before, items, dash) = items(&top)?;
        let kept: Vec<&Vec<&str>> = items.iter().filter(|i| item_name(i, dash) != Some(name)).collect();
        if kept.len() == items.len() {
            out.extend(top.lines.iter().map(|l| l.to_string()));
            continue;
        }
        changed = true;
        // A list left empty is `null`, as kubectl writes one.
        out.push(if kept.is_empty() { format!("{}: null", top.key) } else { top.lines[0].to_owned() });
        out.extend(before.iter().map(|l| l.to_string()));
        out.extend(kept.iter().flat_map(|i| i.iter().map(|l| l.to_string())));
    }
    // Unchanged files come back byte for byte, whatever their last line.
    if !changed {
        return Ok(existing.to_owned());
    }
    Ok(join(&out, newline(existing)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K3S: &str = "apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: Q0E=
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: default
  user:
    client-certificate-data: Q0VSVA==
    client-key-data: S0VZ
";

    /// A file as kubectl and `aws eks update-kubeconfig` leave it, with another Kiri's context.
    const MINE: &str = "apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: RUtT
    server: https://ABC.gr7.eu-central-1.eks.amazonaws.com
  name: arn:aws:eks:eu-central-1:1:cluster/prod
- cluster:
    certificate-authority-data: REVW
    server: https://127.0.0.1:6444
  name: kiri-dev
contexts:
- context:
    cluster: arn:aws:eks:eu-central-1:1:cluster/prod
    user: arn:aws:eks:eu-central-1:1:cluster/prod
  name: prod
- context:
    cluster: kiri-dev
    user: kiri-dev
  name: kiri-dev
current-context: prod
kind: Config
preferences: {}
users:
- name: arn:aws:eks:eu-central-1:1:cluster/prod
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - --region
      - eu-central-1
      command: aws
- name: kiri-dev
  user:
    client-certificate-data: REVWQ0VSVA==
";

    fn names(text: &str, list: &str) -> Vec<String> {
        let tops = tops(text).unwrap();
        let top = tops.iter().find(|t| t.key == list).unwrap();
        let (_, items, dash) = items(top).unwrap();
        items.iter().map(|i| item_name(i, dash).unwrap().to_owned()).collect()
    }

    #[test]
    fn k3s_names_become_the_engines() {
        let ours = from_k3s(K3S, 6445).unwrap();
        assert!(ours.contains("server: https://127.0.0.1:6445\n  name: kiri\n"));
        assert!(ours.contains("    cluster: kiri\n    user: kiri\n  name: kiri\n"));
        assert!(ours.contains("current-context: kiri\n") && ours.contains("- name: kiri\n"));
        assert!(!ours.contains("default"));
    }

    #[test]
    fn valid_k3s_token_and_namespace_are_supported() {
        let token_k3s = "apiVersion: v1
clusters:
- name: default
  cluster:
    certificate-authority-data: Q0E=
    server: https://0.0.0.0:6443
contexts:
- name: default
  context:
    cluster: default
    namespace: kube-public
    user: default
current-context: default
kind: Config
users:
- name: default
  user:
    token: k10abcDEF0123456789._~+/-==
";
        let ours = from_k3s(token_k3s, 6450).unwrap();
        assert!(ours.contains("server: https://127.0.0.1:6450\n"));
        assert!(ours.contains("    namespace: kube-public\n"));
        assert!(ours.contains("    token: k10abcDEF0123456789._~+/-==\n"));
        assert!(!ours.contains("client-certificate-data"));
    }

    #[test]
    fn rejects_exec_auth_provider_and_host_file_read_payloads() {
        let exec_payload = "apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: Q0E=
    server: https://127.0.0.1:6443
  name: default
contexts:
- context:
    cluster: default
    user: default
  name: default
kind: Config
users:
- name: default
  user:
    client-certificate-data: Q0VSVA==
    client-key-data: S0VZ
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: /bin/sh
      args:
      - -c
      - touch /tmp/pwned
";
        let err = from_k3s(exec_payload, 6443).unwrap_err();
        assert!(err.contains("exec"), "{err}");

        for forbidden_user_line in [
            "    auth-provider:\n      name: oidc",
            "    client-certificate: /Users/victim/.ssh/id_ed25519",
            "    client-key: /Users/victim/.ssh/id_ed25519",
            "    tokenFile: /Users/victim/.aws/credentials",
            "    username: admin",
            "    password: secret",
            "    as: system:admin",
            "    as-uid: 0",
            "    as-groups: system:masters",
            "    as-user-extra: foo",
            "    unknown-field: x",
        ] {
            let doc = format!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    certificate-authority-data: Q0E=\n    server: https://127.0.0.1:6443\nusers:\n- name: default\n  user:\n    client-certificate-data: Q0VSVA==\n    client-key-data: S0VZ\n{forbidden_user_line}\n"
            );
            assert!(from_k3s(&doc, 6443).is_err(), "accepted forbidden user line: {forbidden_user_line}");
        }

        for forbidden_cluster_line in [
            "    certificate-authority: /etc/hosts",
            "    insecure-skip-tls-verify: true",
            "    proxy-url: http://evil.example:8080",
            "    tls-server-name: evil.example",
            "    unknown-cluster-key: 1",
        ] {
            let doc = format!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    certificate-authority-data: Q0E=\n    server: https://127.0.0.1:6443\n{forbidden_cluster_line}\nusers:\n- name: default\n  user:\n    token: tok123\n"
            );
            assert!(from_k3s(&doc, 6443).is_err(), "accepted forbidden cluster line: {forbidden_cluster_line}");
        }
    }

    #[test]
    fn rejects_anchors_flow_collections_tabs_extra_items_and_bad_base64() {
        for bad in [
            K3S.replace("Q0E=", "&a Q0E="),
            K3S.replace("Q0E=", "*a"),
            K3S.replace("Q0E=", "!tag Q0E="),
            format!("{K3S}<<: *x\n"),
            format!("---\n{K3S}"),
            format!("{K3S}...\n"),
            K3S.replace("preferences: {}", "preferences: {a: 1}"),
            "{\"apiVersion\":\"v1\",\"kind\":\"Config\"}".to_owned(),
            "apiVersion: v1\nkind: Config\nclusters: [{name: default}]\n".to_owned(),
            K3S.replace("  name: default", "\tname: default"),
            K3S.replace("Q0E=", "Q0E=\x07"),
            K3S.replace("Q0E=", "not_base64!"),
            K3S.replace("Q0E=", ""),
            K3S.replace("    client-key-data: S0VZ\n", ""),
        ] {
            assert!(from_k3s(&bad, 6443).is_err(), "accepted malformed/unsafe input: {bad:?}");
        }

        let extra_cluster = K3S.replace(
            "  name: default\ncontexts:",
            "  name: default\n- cluster:\n    certificate-authority-data: Q0E=\n    server: https://evil.example:6443\n  name: second\ncontexts:",
        );
        assert!(from_k3s(&extra_cluster, 6443).is_err());

        let extra_user = format!("{K3S}- name: sneaky\n  user:\n    token: abc\n");
        assert!(from_k3s(&extra_user, 6443).is_err());
    }

    #[test]
    fn merging_adds_ours_and_keeps_every_other_line_in_place() {
        let ours = from_k3s(K3S, 6445).unwrap();
        let merged = merge(MINE, &ours, "kiri", false).unwrap();
        for list in LISTS {
            let want = if list == "contexts" { vec!["prod", "kiri-dev", "kiri"] } else { vec!["arn:aws:eks:eu-central-1:1:cluster/prod", "kiri-dev", "kiri"] };
            assert_eq!(names(&merged, list), want, "{list}");
        }
        // Taking ours out again gives the file back exactly.
        assert_eq!(remove(&merged, "kiri").unwrap(), MINE);
        // The current context stays the user's.
        assert!(merged.contains("current-context: prod\n"));
        assert!(merged.contains("    server: https://127.0.0.1:6445\n  name: kiri\ncontexts:\n"));
        // Nothing changes when merged again.
        assert_eq!(merge(&merged, &ours, "kiri", false).unwrap(), merged);
        // --use makes it current.
        assert!(merge(MINE, &ours, "kiri", true).unwrap().contains("current-context: kiri\n"));
    }

    #[test]
    fn a_new_port_replaces_the_old_entry() {
        let merged = merge(MINE, &from_k3s(K3S, 6444).unwrap(), "kiri", false).unwrap();
        let moved = merge(&merged, &from_k3s(&K3S.replace("Q0E=", "TkVXQ0E="), 6445).unwrap(), "kiri", false).unwrap();
        assert!(moved.contains("https://127.0.0.1:6445") && moved.contains("TkVXQ0E="));
        assert_eq!(moved.matches("name: kiri\n").count(), 3);
        // kiri-dev's own port is untouched.
        assert!(moved.contains("server: https://127.0.0.1:6444\n  name: kiri-dev"));
        assert_eq!(names(&moved, "clusters").len(), 3);
    }

    #[test]
    fn indented_lists_and_crlf_are_kept() {
        let indented = "apiVersion: v1\r\nclusters:\r\n  - cluster:\r\n      server: https://x\r\n    name: \"x\"\r\ncontexts:\r\n  - name: x # theirs\r\n    context:\r\n      cluster: x\r\n      user: x\r\ncurrent-context: x\r\nkind: Config\r\nusers:\r\n  - name: x\r\n    user: {}\r\n";
        let merged = merge(indented, &from_k3s(K3S, 6445).unwrap(), "kiri", false).unwrap();
        assert!(merged.contains("\r\n  - cluster:\r\n      certificate-authority-data: Q0E=\r\n      server: https://127.0.0.1:6445\r\n    name: kiri\r\n"));
        assert!(!merged.replace("\r\n", "").contains('\n'));
        assert_eq!(names(&merged, "contexts"), ["x", "kiri"]);
        assert_eq!(remove(&merged, "kiri").unwrap(), indented);
    }

    #[test]
    fn missing_or_empty_lists_and_files() {
        let ours = from_k3s(K3S, 6445).unwrap();
        assert_eq!(merge("", &ours, "kiri", false).unwrap(), ours);
        let bare = "apiVersion: v1\nclusters: null\ncontexts: []\nkind: Config\n";
        let merged = merge(bare, &ours, "kiri", false).unwrap();
        assert_eq!(names(&merged, "clusters"), ["kiri"]);
        assert_eq!(names(&merged, "contexts"), ["kiri"]);
        assert_eq!(names(&merged, "users"), ["kiri"]);
        // It had no current context, and still has none: a plain `kubectl` stays pointed at nothing.
        assert!(!merged.contains("current-context"));
        assert!(merge(bare, &ours, "kiri", true).unwrap().ends_with("current-context: kiri\n"));
        let removed = remove(&merge(bare, &ours, "kiri", true).unwrap(), "kiri").unwrap();
        assert!(removed.contains("clusters: null\n") && removed.contains("users: null\n") && removed.contains("current-context: \"\"\n"));
        assert!(merge("{\"apiVersion\": \"v1\"}", &ours, "kiri", false).is_err());
        assert!(merge("clusters: [{name: a}]\n", &ours, "kiri", false).is_err());
    }

    #[test]
    fn removing_ours_leaves_others_and_clears_a_current_ours() {
        let merged = merge(MINE, &from_k3s_named(K3S, "kiri-dev", 6446).unwrap(), "kiri-dev", true).unwrap();
        let removed = remove(&merged, "kiri-dev").unwrap();
        assert_eq!(names(&removed, "contexts"), ["prod"]);
        assert!(removed.contains("current-context: \"\"\n"));
        assert_eq!(remove(MINE, "kiri").unwrap(), MINE);
    }

    #[test]
    fn the_file_is_kubeconfigs_first_else_home() {
        let home = Some(PathBuf::from("/home/me"));
        assert_eq!(pick(None, home.clone()), Some(PathBuf::from("/home/me/.kube/config")));
        let sep = if cfg!(windows) { ";" } else { ":" };
        assert_eq!(pick(Some(format!("/a/one{sep}/b/two").into()), home.clone()), Some(PathBuf::from("/a/one")));
        assert_eq!(pick(Some("".into()), home), Some(PathBuf::from("/home/me/.kube/config")));
        assert_eq!(pick(None, None), None);
    }

    #[test]
    fn install_writes_atomically_and_privately() {
        let dir = std::env::temp_dir().join(format!("kiri-kubeconfig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join(".kube").join("config");
        let ours = from_k3s(K3S, 6445).unwrap();
        assert!(install(&path, &ours, "kiri", false).unwrap());
        assert!(!install(&path, &ours, "kiri", false).unwrap());
        std::fs::write(&path, MINE).unwrap();
        assert!(install(&path, &ours, "kiri", false).unwrap());
        assert_eq!(std::fs::read_to_string(dir.join(".kube").join("config.bak.kiri")).unwrap(), MINE);
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&path).unwrap().permissions()) & 0o777, 0o600);
        assert!(uninstall(&path, "kiri").unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), MINE);
        assert!(!uninstall(&path, "kiri").unwrap());
        // No temporary files left beside it.
        assert_eq!(std::fs::read_dir(dir.join(".kube")).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handles_bare_dashes_document_markers_and_comments() {
        let ours = from_k3s(K3S, 6445).unwrap();
        let bare_dash = "apiVersion: v1\nclusters:\n-\n  cluster:\n    server: https://127.0.0.1:6443\n  name: kiri\n-\n  cluster:\n    server: https://prod\n  name: prod\ncontexts:\n-\n  context:\n    cluster: kiri\n    user: kiri\n  name: kiri\n-\n  context:\n    cluster: prod\n    user: prod\n  name: prod\ncurrent-context: prod\nkind: Config\nusers:\n-\n  name: kiri\n  user: {}\n-\n  name: prod\n  user: {}\n";
        let merged = merge(bare_dash, &ours, "kiri", false).unwrap();
        assert_eq!(merged.matches("name: kiri").count(), 3);
        assert!(merged.contains("https://127.0.0.1:6445"));
        let removed = remove(&merged, "kiri").unwrap();
        assert!(!removed.contains("name: kiri"));
        assert_eq!(removed.matches("name: prod").count(), 3);

        let markers = "\u{feff}---\napiVersion: v1\nclusters:\t# managed\n- cluster:\n    server: https://x\n  name: prod\ncontexts:# ctxs\n- context:\n    cluster: prod\n    user: prod\n  name: prod\nkind: Config\n...\n";
        let merged_doc = merge(markers, &ours, "kiri", true).unwrap();
        assert!(merged_doc.trim_end().ends_with("\n..."), "{merged_doc:?}");
        assert!(merged_doc.contains("clusters:\t# managed\n"));
        assert!(merged_doc.contains("contexts:# ctxs\n"));
        assert!(merged_doc.contains("users:\n- name: kiri\n"));
        assert!(merged_doc.contains("current-context: kiri\n"));

        assert!(merge("apiVersion: v1\nclusters: []\n---\napiVersion: v1\n", &ours, "kiri", false).is_err());
    }
}
