// parity: macos windows linux
// window: 820x760
// Narrow-window (~820px) layout of long DOCKER_HOST=unix://... socket hints in
// Settings -> Network, and OS-accurate copy in Settings -> Network, Resources,
// and Diagnostics (no "this Mac", "macOS", "Finder", or "the VM" on Linux).
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${m}: got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`); };

kiri.on({ type: "status", version: "0.2.3", dev: false, share: true, app: "Kiri", ours: "kiri", context: "kiri", pinned: null });
kiri.on({
  type: "dockersock",
  path: WIN ? "\\\\.\\pipe\\docker_engine" : "/var/run/docker.sock",
  owner: "other",
  engine: WIN ? "Docker Desktop" : "Docker",
  target: WIN ? "Docker Desktop.exe" : "/var/run/dockerd.sock",
  hint: WIN ? "DOCKER_HOST=npipe:////./pipe/kiri-custom-developer-instance" : "DOCKER_HOST=unix:///home/alexandra-workstation/.kiri/custom/docker.sock",
  take: false,
});
kiri.on({
  type: "proxy",
  settings: { mode: "system", http: "", https: "", no_proxy: "", containers: true },
  effective: { http: "http://127.0.0.1:3128", https: "http://127.0.0.1:3128", no_proxy: ["localhost"], pac: false },
});

prefs.tab = "network";
show("settings");

t("Long DOCKER_HOST socket hint wraps without horizontal overflow at 820x760 and keeps Copy aligned", () => {
  const content = document.getElementById("content");
  if (content.scrollWidth > content.clientWidth + 1) {
    throw new Error(`horizontal overflow: scrollWidth=${content.scrollWidth} > clientWidth=${content.clientWidth}`);
  }
  const hint = content.querySelector(".pref .sockhint");
  const code = hint?.querySelector("code");
  const copy = hint?.querySelector(".copy");
  const pref = hint?.closest(".pref");
  const prefD = hint?.closest(".d");
  const pact = pref?.querySelector(".pact");
  const pane = pref?.closest(".pane");
  if (!hint || !code || !copy || !prefD || !pact || !pane) throw new Error("missing socket hint elements");
  const cr = code.getBoundingClientRect();
  const cpr = copy.getBoundingClientRect();
  const dr = prefD.getBoundingClientRect();
  const pr = pact.getBoundingClientRect();
  const paner = pane.getBoundingClientRect();
  if (cr.right > dr.right + 1) throw new Error(`code right (${Math.round(cr.right)}) overflows .pref .d (${Math.round(dr.right)})`);
  if (cpr.right > dr.right + 1) throw new Error(`copy right (${Math.round(cpr.right)}) overflows .pref .d (${Math.round(dr.right)})`);
  if (pr.right > paner.right + 1) throw new Error(`badge right (${Math.round(pr.right)}) clipped past pane (${Math.round(paner.right)})`);
  if (cpr.left < cr.right - 1) throw new Error(`copy button dropped below code instead of sitting beside it (copy.left=${Math.round(cpr.left)}, code.right=${Math.round(cr.right)})`);
  if (cpr.top < cr.top - 4 || cpr.bottom > cr.bottom + 4) {
    throw new Error(`copy button not vertically aligned with code (copy=${Math.round(cpr.top)}..${Math.round(cpr.bottom)}, code=${Math.round(cr.top)}..${Math.round(cr.bottom)})`);
  }
});

t("Settings -> Network uses OS-appropriate wording (never macOS / this Mac on Linux or Windows)", () => {
  const txt = document.getElementById("content").textContent;
  if (LINUX) {
    eq(txt.includes("this Mac") || txt.includes("macOS"), false, "no Mac copy on Linux Network");
    eq(txt.includes("A proxy on this computer is reached as host.docker.internal."), true, "Linux host proxy wording");
    eq(txt.includes("VPNs need no setting: container traffic leaves through Linux."), true, "Linux VPN wording");
  } else if (WIN) {
    eq(txt.includes("this Mac") || txt.includes("macOS"), false, "no Mac copy on Windows Network");
    eq(txt.includes("Container traffic leaves through WSL's network."), true, "Windows WSL wording");
  } else {
    eq(txt.includes("A proxy on this Mac is reached as host.docker.internal."), true, "macOS host proxy wording");
    eq(txt.includes("VPNs need no setting: container traffic leaves through macOS."), true, "macOS VPN wording");
  }
});

t("Settings -> Resources and Diagnostics report dialog avoid macOS / VM wording on Linux", () => {
  kiri.on({
    type: "resources", cpus: 8, memory_mib: 16384, running_cpus: 4, running_memory_mib: 16384,
    awake: false, max_cpus: 16, max_memory_mib: 32768, overridden: false,
  });
  prefs.tab = "resources";
  show("settings");
  let txt = document.getElementById("content").textContent;
  if (LINUX) {
    eq(txt.includes("this Mac") || txt.includes("macOS") || txt.includes("the VM"), false, "no VM/Mac copy on Linux Resources (off)");
    eq(txt.includes("Shared with Linux: containers only use them while busy."), true, "Linux CPUs copy");
    eq(txt.includes("The engine is off; it starts with these next time."), true, "Linux off footer");
  }
  kiri.on({
    type: "resources", cpus: 8, memory_mib: 16384, running_cpus: 4, running_memory_mib: 16384,
    awake: true, max_cpus: 16, max_memory_mib: 32768, overridden: false,
  });
  txt = document.getElementById("content").textContent;
  if (LINUX) {
    eq(document.getElementById("res-restart")?.textContent.trim(), "Restart engine to apply", "Linux restart button");
  } else {
    eq(document.getElementById("res-restart")?.textContent.trim(), "Restart VM to apply", "VM restart button");
  }
  reportDialog("save");
  const dlg = document.getElementById("rp")?.textContent || "";
  rp.close();
  if (LINUX || WIN) {
    eq(dlg.includes("this Mac") || dlg.includes("macOS") || dlg.includes("Finder"), false, "no Mac/Finder copy in non-macOS report dialog");
  }
});

report(R);
