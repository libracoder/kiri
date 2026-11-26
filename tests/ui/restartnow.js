// Every restart trigger opens the universal Restarting… overlay (#rscrim) with
// the shared .rspin spinner, syncs the VM card and status bar, and clears when
// the restart completes or fails.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };

kiri.on({ type: "status", version: "0.2.3", dev: false, share: true, app: "Kiri", ours: "kiri", context: "kiri" });
kiri.on({ type: "state", state: "running" });

t("toast Restart now opens universal Restarting overlay with .rspin and syncs VM card + status bar", () => {
  kiri.on({ type: "notice", kind: "ok", text: "Saved. The VM uses these from its next start", act: "restartvm" });
  const b = document.querySelector("#toasts [data-trestart]");
  if (!b) throw new Error("no link");
  b.click();
  if (!sent.some((m) => m.type === "restartvm")) throw new Error("sent " + sent.map((m) => m.type).join(","));
  if (document.querySelector("#toasts [data-trestart]")) throw new Error("toast stayed");
  const scrim = document.getElementById("rscrim");
  if (!scrim || scrim.hidden) throw new Error("Restarting overlay did not open");
  if (!scrim.querySelector(".rspin")) throw new Error("missing .rspin spinner");
  eq(scrim.querySelector("h3")?.textContent.trim(), "Restarting…", "overlay heading");
  eq(document.body.dataset.vm, "restarting", "body data-vm");
  eq(document.getElementById("vm-state")?.textContent.trim(), "Restarting…", "sidebar VM state");
  if (!document.querySelector("#statusbar .dot.restarting")) throw new Error("status bar missing restarting dot");

  // Live step updates as VM stops and starts
  kiri.on({ type: "state", state: "booting" });
  eq(scrim.querySelector(".rstep span")?.textContent.trim(), "Starting…", "step updated on booting");

  // Completion clears overlay and restores running state
  kiri.on({ type: "state", state: "running" });
  kiri.on({ type: "vmrestarted", ok: true });
  if (!scrim.hidden) throw new Error("overlay stayed after vmrestarted");
  eq(document.body.dataset.vm, "running", "restored to running");
});

t("no Restart now link while the VM is asleep", () => {
  kiri.on({ type: "notice", kind: "ok", text: "Saved. The VM uses these from its next start", act: "" });
  if (document.querySelector("#toasts [data-trestart]")) throw new Error("link shown");
});

t("Resources Restart VM to apply and Network Restart VM to apply open Restarting overlay", () => {
  kiri.on({
    type: "resources", cpus: 4, memory_mib: 11264, disk_gb: 160,
    running_cpus: 2, running_memory_mib: 12288, running_disk_gb: 160,
    awake: true, max_cpus: 12, max_memory_mib: 32768, min_disk_gb: 64, max_disk_gb: 1024, overridden: false,
  });
  prefs.tab = "resources";
  show("settings");
  const resBtn = document.getElementById("res-restart");
  if (!resBtn) throw new Error("missing #res-restart");
  sent.length = 0;
  resBtn.click();
  if (!sent.some((m) => m.type === "restartvm")) throw new Error("did not send restartvm");
  if (document.getElementById("rscrim").hidden) throw new Error("overlay not shown for #res-restart");
  kiri.on({ type: "vmrestarted", ok: true });
  if (!document.getElementById("rscrim").hidden) throw new Error("overlay did not close");

  prefs.tab = "network";
  show("settings");
  kiri.on({ type: "proxy", settings: { mode: "system", containers: false }, effective: { http: null, https: null, no_proxy: [], pac: false } });
  kiri.on({ type: "vmnet", supported: true, shared_nat: false, env: false, awake: true, running_shared_nat: true });
  const netRestart = document.querySelector(".settings .pane [data-restartvm]");
  if (!netRestart) throw new Error("missing Restart VM to apply in Network when pending");
  netRestart.click();
  if (document.getElementById("rscrim").hidden) throw new Error("overlay not shown from Network restart");
  kiri.on({ type: "vmrestarted", ok: false });
  if (!document.getElementById("rscrim").hidden) throw new Error("overlay did not close on failed vmrestarted");
});

t("Update Restart now and Stale engine Restart engine open Restarting overlay", () => {
  kiri.on({ type: "updateready", version: "0.2.4" });
  const updBtn = document.querySelector('#updcard [data-upd="restart"]');
  if (!updBtn) throw new Error("missing update restart button");
  updBtn.click();
  if (document.getElementById("rscrim").hidden || !document.querySelector("#rscrim .rspin")) throw new Error("overlay missing on updaterestart");
  kiri.on({ type: "updateerror", error: "staged bundle missing" });
  if (!document.getElementById("rscrim").hidden) throw new Error("overlay stayed after updateerror");

  ui.upd = null;
  kiri.on({ type: "enginestale", version: "0.2.2" });
  const engBtn = document.querySelector('#updcard [data-upd="engine"]');
  if (!engBtn) throw new Error("missing stale engine restart button");
  engBtn.click();
  if (document.getElementById("rscrim").hidden || !document.querySelector("#rscrim .rspin")) throw new Error("overlay missing on restartengine");
  kiri.on({ type: "enginerestarted", version: "0.2.3", ms: 420 });
  if (!document.getElementById("rscrim").hidden) throw new Error("overlay stayed after enginerestarted");
});

t("Storage move shows Restarting overlay with progress bar and .rspin in pane", () => {
  prefs.tab = "storage";
  show("settings");
  kiri.on({
    type: "storage",
    path: "/Users/me/Library/Application Support/Kiri",
    default: "/Users/me/Library/Application Support/Kiri",
    custom: false, env: false, state: "moving",
    used: null, free: 120_000_000_000, fs: "apfs",
    moving: { to: "/Volumes/SSD/kiri", phase: "restarting", done: 3_000_000_000, total: 4_000_000_000 },
    error: null, old: null,
  });
  const scrim = document.getElementById("rscrim");
  if (scrim.hidden || !scrim.querySelector(".rspin")) throw new Error("storage moving did not show Restarting overlay");
  eq(scrim.querySelector(".rstep span")?.textContent.trim(), "Restarting engine…", "storage phase step");
  eq(scrim.querySelector(".rbar span")?.style.width, "75%", "storage progress bar");
  if (!document.querySelector(".settings .st-box .rspin")) throw new Error("storage pane box missing .rspin");

  kiri.on({
    type: "storage",
    path: "/Volumes/SSD/kiri",
    default: "/Users/me/Library/Application Support/Kiri",
    custom: true, env: false, state: "ok",
    used: 4_000_000_000, free: 300_000_000_000, fs: "apfs",
    moving: null, error: null, old: null,
  });
  if (!scrim.hidden) throw new Error("storage overlay stayed after state=ok");
});

t("Kubernetes set while running opens Restarting overlay and streams progress", () => {
  ui.containers = [{ Id: "k8s1", Names: ["/kiri-k8s"], Image: "rancher/k3s:v1.37.1-k3s1", State: "running", Ports: [], Labels: { "dev.kiri.k8s": "1" } }];
  kiri.on({
    type: "k8s", state: "running", ready: true, context: "kiri", port: 6443, want_port: 6443,
    config: { lan: false, tls_san: [] }, pods: [], services: [],
  });
  prefs.tab = "kubernetes";
  show("settings");
  document.querySelector('[data-k8slan="1"]').click();
  const scrim = document.getElementById("rscrim");
  if (scrim.hidden || !scrim.querySelector(".rspin")) throw new Error("k8s restart did not open Restarting overlay");
  kiri.on({ type: "k8sop", op: "set", state: "progress", line: "Waiting for the API server" });
  eq(scrim.querySelector(".rstep span")?.textContent.trim(), "Waiting for the API server…", "k8s progress line");
  kiri.on({ type: "k8sop", op: "set", state: "done", context: "kiri", port: 6443, want_port: 6443 });
  if (!scrim.hidden) throw new Error("k8s overlay stayed after k8sop done");
});

report(R);
