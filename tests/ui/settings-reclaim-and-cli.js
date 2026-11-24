// Settings: VM disk space reclaim & Docker cleanup (#879), Builds cache/idle
// settings, macOS outbound VM traffic, Kubernetes cluster controls, shell PATH
// toggle (#556), and Uninstall Kiri confirmation dialog.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const last = (cmd) => sent.filter((m) => m.type === cmd).at(-1);

t("Resources disk description links to Settings → Storage instead of saying never shrinks", () => {
  kiri.on({
    type: "resources", cpus: 4, memory_mib: 8192, disk_gb: 64,
    running_cpus: 4, running_memory_mib: 8192, running_disk_gb: 64,
    awake: true, max_cpus: 12, max_memory_mib: 32768, min_disk_gb: 64, max_disk_gb: 1024, overridden: false,
  });
  prefs.tab = "resources";
  show("settings");
  const pane = document.querySelector(".settings .panes");
  if (/never shrinks/i.test(pane.textContent)) throw new Error("still says never shrinks");
  const link = pane.querySelector("[data-stgoto]");
  if (!link) throw new Error("missing Settings → Storage link button");
  link.click();
  if (prefs.tab !== "storage") throw new Error("link did not switch to storage tab");
});

t("Storage: VM disk space row reclaims online on macOS and disables when clean", () => {
  kiri.on({
    type: "storage",
    path: "/Users/me/.kiri/data",
    default: "/Users/me/.kiri/data",
    custom: false, env: false, state: "ok",
    used: 29_400_000_000, free: 412_600_000_000, fs: "apfs",
    disk_host: 29_400_000_000, disk_in_use: 17_300_000_000, disk_limit: 64 * 1073741824, reclaimable: 12_100_000_000,
    moving: null, error: null, old: null,
  });
  const pane = document.querySelector(".settings .pane");
  if (!pane.textContent.includes("VM disk space")) throw new Error("missing VM disk space row");
  if (!pane.textContent.includes("can be given back")) throw new Error("missing reclaimable summary");
  const btn = pane.querySelector("[data-streclaim]");
  if (!btn || btn.disabled) throw new Error("Reclaim space button missing or disabled");
  btn.click();
  if (!last("storagereclaim")) throw new Error("didn't send storagereclaim");
  if (!document.querySelector(".settings .pane .hspin")) throw new Error("missing busy spinner while reclaiming");

  kiri.on({ type: "storagereclaimed", before: 29_400_000_000, after: 17_300_000_000, reclaimed: 12_100_000_000, in_use: 17_300_000_000, elapsed_ms: 800 });
  const afterPane = document.querySelector(".settings .pane");
  if (!afterPane.textContent.includes("Freed")) throw new Error("missing Freed summary after reclaim");
  const afterBtn = afterPane.querySelector("[data-streclaim]");
  if (!afterBtn?.disabled) throw new Error("Reclaim button should be disabled when nothing left to reclaim");
});

t("Storage: Unused Docker data row confirms and sends storageprune", () => {
  ui.containers.push({ Id: "stopped1", Names: ["/old-web"], Image: "nginx", State: "exited", Ports: [], Labels: {} });
  ui.images.push({ Id: "sha256:deadbeef", RepoTags: ["<none>:<none>"], Size: 500_000_000, Created: Date.now() / 1000 - 100 });
  ui.builderVolume = { Name: "buildx_buildkit_kiri-build0_state" };
  render();
  const btn = document.querySelector("[data-stprune]");
  if (!btn || btn.disabled) throw new Error("Clean up… button missing or disabled");
  btn.click();
  const go = document.querySelector(".scrim [data-go]");
  if (!go) throw new Error("Clean up… didn't open confirmation dialog");
  go.click();
  if (!last("storageprune")) throw new Error("didn't send storageprune");
  ui.containers = [];
  ui.images = [];
  ui.builderVolume = null;
  kiri.on({ type: "storagepruned", freed: 500_000_000, containers: 1, images: 1 });
  const pane = document.querySelector(".settings .pane");
  if (!pane.textContent.includes("No stopped containers")) throw new Error("missing clean summary");
  if (!pane.querySelector("[data-stprune]")?.disabled) throw new Error("Clean up… should be disabled when clean");
});

t("Builds: Build cache limit slider and idle timeout wire /kiri/builder", () => {
  document.querySelector('[data-stab="builds"]').click();
  if (!last("buildersettings")) throw new Error("opening Builds did not request buildersettings");
  kiri.on({ type: "buildwith", with: "kiri", ask: false, engine: null, taken: true, ready: true });
  kiri.on({ type: "buildersettings", cache_gb: 20, default_cache_gb: 20, idle_secs: 600, state: "running", overridden: false });
  const slider = document.getElementById("bld-cache");
  if (!slider || slider.value !== "20") throw new Error("missing or wrong #bld-cache");
  slider.value = "40";
  slider.dispatchEvent(new Event("input", { bubbles: true }));
  if (document.getElementById("bld-cache-v").textContent !== "40 GB") throw new Error("slider label did not update");
  slider.dispatchEvent(new Event("change", { bubbles: true }));
  const savedCache = last("setbuildersettings");
  if (!savedCache || savedCache.value?.cache_gb !== 40) throw new Error("bad setbuildersettings for cache: " + JSON.stringify(savedCache));

  const idle30 = document.querySelector('[data-bldidle="1800"]');
  if (!idle30) throw new Error("missing 30 min idle button");
  idle30.click();
  const savedIdle = last("setbuildersettings");
  if (!savedIdle || savedIdle.value?.idle_secs !== 1800) throw new Error("bad setbuildersettings for idle: " + JSON.stringify(savedIdle));
  if (document.querySelector('[data-bldidle="1800"]').getAttribute("aria-pressed") !== "true") throw new Error("30 min button not pressed");

  kiri.on({ type: "buildersettings", cache_gb: 40, default_cache_gb: 20, idle_secs: 1800, overridden: true });
  if (!document.querySelector(".settings .pane").textContent.includes("KIRI_BUILD_CACHE_GB")) throw new Error("missing env override note");
});

t("Network: Outbound VM traffic toggles macOS NAT and Host relay", () => {
  document.querySelector('[data-stab="network"]').click();
  if (!last("vmnet")) throw new Error("opening Network did not request vmnet");
  kiri.on({ type: "proxy", settings: { mode: "system", containers: false }, effective: { http: null, https: null, no_proxy: [], pac: false } });
  kiri.on({ type: "vmnet", supported: true, shared_nat: true, env: false, awake: true, running_shared_nat: true });
  const natOn = document.querySelector('[data-vmnat="1"]');
  const natOff = document.querySelector('[data-vmnat="0"]');
  if (!natOn || !natOff || natOn.getAttribute("aria-pressed") !== "true") throw new Error("Outbound VM traffic buttons wrong");
  natOff.click();
  const req = last("setvmnet");
  if (!req || req.value?.shared_nat !== false) throw new Error("bad setvmnet: " + JSON.stringify(req));
  if (document.querySelector('[data-vmnat="0"]').getAttribute("aria-pressed") !== "true") throw new Error("Host relay not pressed");

  kiri.on({ type: "vmnet", supported: false });
  if (document.querySelector('[data-vmnat="0"]')) throw new Error("Outbound VM traffic should hide when unsupported");
});

t("Kubernetes: Cluster section exposes k3s version, extra server flags, and startup manifests", () => {
  kiri.on({
    type: "k8s", state: "running", ready: true, context: "kiri", port: 6443, want_port: 6443,
    default_version: "v1.37.1-k3s1", manifests_dir: "/Users/me/.kiri/k8s-manifests",
    config: { lan: false, tls_san: [], version: null, k3s_args: [] },
    pods: [], services: [],
  });
  document.querySelector('[data-stab="kubernetes"]').click();
  const pane = document.querySelector(".settings .pane");
  if (!pane.textContent.includes("Cluster") || !pane.textContent.includes("k3s version")) throw new Error("missing Cluster section");
  if (!pane.textContent.includes("/Users/me/.kiri/k8s-manifests")) throw new Error("missing manifests dir");

  const ver = document.getElementById("k8s-ver");
  if (!ver) throw new Error("missing #k8s-ver");
  ver.value = "v1.31.4-k3s1";
  ver.dispatchEvent(new Event("change", { bubbles: true }));
  const setVer = sent.filter((m) => m.type === "k8s" && m.action === "set").at(-1);
  if (!setVer || setVer.value?.version !== "v1.31.4-k3s1") throw new Error("bad k8s set version: " + JSON.stringify(setVer));

  // Clear pending op so we can test k3s args and manifests.
  kiri.on({ type: "k8sop", op: "set", state: "done", context: "kiri", port: 6443, want_port: 6443 });
  const argsInput = document.getElementById("k8s-args");
  const argsBtn = document.querySelector("[data-k8sargs]");
  if (!argsInput || !argsBtn?.disabled) throw new Error("k8s-args missing or save not initially disabled");
  argsInput.value = "--disable=servicelb --flannel-backend=none";
  argsInput.dispatchEvent(new Event("input", { bubbles: true }));
  if (argsBtn.disabled) throw new Error("k8s-args save button did not enable");
  argsBtn.click();
  const setArgs = sent.filter((m) => m.type === "k8s" && m.action === "set").at(-1);
  if (JSON.stringify(setArgs?.value?.k3s_args) !== JSON.stringify(["--disable=servicelb", "--flannel-backend=none"])) {
    throw new Error("bad k8s set k3s_args: " + JSON.stringify(setArgs));
  }

  document.querySelector("[data-k8smanifests]").click();
  const man = sent.filter((m) => m.type === "k8s" && m.action === "manifests").at(-1);
  if (!man) throw new Error("Open folder did not send k8s manifests action");
});

t("Appearance & About: shell PATH toggle and Uninstall Kiri confirmation", () => {
  document.querySelector('[data-stab="appearance"]').click();
  kiri.on({ type: "shellpath", supported: true, enabled: true });
  const shOff = document.querySelector('[data-shellpath="0"]');
  const shOn = document.querySelector('[data-shellpath="1"]');
  if (!shOff || !shOn || shOn.getAttribute("aria-pressed") !== "true") throw new Error("shellpath controls missing");
  shOff.click();
  const setSh = last("setshellpath");
  if (!setSh || setSh.value?.enabled !== false) throw new Error("bad setshellpath: " + JSON.stringify(setSh));

  document.querySelector('[data-stab="about"]').click();
  kiri.on({ type: "about", app: "0.2.0", running: true, engine: "0.2.0", api: "1.47", kernel: "6.12", cpus: 4, memory: 8 * 1073741824, awake: true, can_uninstall: true });
  const unBtn = document.querySelector("[data-uninstall]");
  if (!unBtn) throw new Error("missing Uninstall Kiri… button");
  unBtn.click();
  const go = document.querySelector(".scrim [data-go]");
  if (!go) throw new Error("Uninstall Kiri… did not open confirmation dialog");
  go.click();
  if (!last("uninstall")) throw new Error("Confirming uninstall did not send uninstall");
});

report(R);
