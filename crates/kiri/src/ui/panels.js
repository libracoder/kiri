/* Deferred non-boot UI panels (Settings, Builds/Scan, Diagnostics), loaded on demand via `loadpanels`. */
(() => {
"use strict";
function importPane() {
  const im = ui.imp;
  if (!im.sources) return `<div class="pane"><h3>${tr("Import")}</h3><p class="muted">${tr("Looking for OrbStack and Docker Desktop…")}</p></div>`;
  if (!im.sources.length) return `<div class="pane"><h3>${tr("Import")}</h3><p class="muted">${tr("Nothing to import from: OrbStack and Docker Desktop aren't on this {host}.", { host: tr(HOST) })}</p></div>`;
  const src = im.sources.find((s) => s.id === im.source) || im.sources[0];
  const seg = im.sources.map((s) => `<button data-impsrc="${s.id}" aria-pressed="${s.id === src.id}">${esc(s.label)}</button>`).join("");
  let body;
  if (!src.running) body = `<p class="muted">${tr("{name} isn't running. Start it to import from it; it doesn't need to stay open afterwards.", { name: esc(src.label) })}</p>`;
  else if (!im.inv || im.inv.source !== src.id) body = `<p class="muted">${tr("Reading what {name} has…", { name: esc(src.label) })}</p>`;
  else if (im.inv.error) body = `<p class="muted">${esc(im.inv.error)}</p>`;
  else body = `${importSections()}
      <div class="res-foot"><span class="muted">${im.summary ? esc(im.summary) : tr("{name} isn't changed: images are copied, and volumes are read through a temporary read-only helper that's removed after. Containers arrive stopped.", { name: esc(src.label) })}</span>
        <span style="flex:1"></span>${importGo()}</div>`;
  return `<div class="pane"><h3>${tr("Import")}</h3>
    <div class="pref"><span class="t">${tr("From")}</span><span class="d">${tr("Bring images, volumes and containers over to Kiri.")}</span><div class="seg" role="group" aria-label="${tr("Import from")}">${seg}</div></div>
    ${body}</div>`;
}

/* The first time, with another engine on this machine: which builder plain
   `docker build` uses. Keeping Docker's changes nothing, and is the default
   (Escape and the scrim mean it too). Settings → Builds switches it later. */
function buildAsk(engine) {
  if ($("bw-dlg")) return;
  if (document.querySelector('[aria-labelledby="welcome-title"], [aria-labelledby="lang-title"]')) { ui.bwAsk = engine; return; }
  const e = esc(engine || "Docker");
  const scrim = document.createElement("div");
  scrim.className = "scrim"; scrim.id = "bw-dlg";
  scrim.innerHTML = `<div class="dialog alert" role="dialog" aria-modal="true" aria-labelledby="bw-h">${alertIco("info")}<h3 id="bw-h">${tr("You already have {engine}. Which should build your images?", { engine: e })}</h3>
    <p class="bw-opt"><b>${tr("Keep building with Docker.")}</b> ${tr("Nothing changes: {build} builds where it does now, and the images stay in {engine}.", { build: `<span class="mono">docker build</span>`, engine: e })}</p>
    <p class="bw-opt"><b>${tr("Build with Kiri.")}</b> ${tr("{build} and {compose} run on Kiri, and the images are in Kiri. {engine} won't see them; run them with Kiri.", { build: `<span class="mono">docker build</span>`, compose: `<span class="mono">docker compose build</span>`, engine: e })}</p>
    <p class="bw-later">${tr("You can switch any time in Settings → Builds.")}</p>
    <div class="row-end"><span></span><span><button class="btn" data-bwpick="kiri">${tr("Build with Kiri")}</button> <button class="btn primary" data-bwpick="docker">${tr("Keep building with Docker")}</button></span></div></div>`;
  document.body.append(scrim);
  const pick = (v) => { scrim.remove(); document.removeEventListener("keydown", onKey); ui.bw = { ...(ui.bw || {}), with: v, ask: false }; send("buildwith", { value: v }); if (ui.view === "settings") render(); };
  const onKey = (ev) => { if (ev.key === "Escape") pick("docker"); };
  document.addEventListener("keydown", onKey);
  scrim.addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-bwpick]");
    if (b) pick(b.dataset.bwpick);
    else if (ev.target === scrim) pick("docker");
  });
  scrim.querySelector('[data-bwpick="docker"]').focus();
}

/* Settings → Builds: Kiri's builder, which Images and Volumes don't list: what
   it takes, and clearing its cache. Made on the first build, not before. */
function builderPref() {
  const img = ui.builderImage, vol = ui.builderVolume;
  if (!img && !vol) return `<div class="pref"><span class="t">${tr("Kiri's builder")}</span><span class="d">${tr("Not set up yet. It's made on your first build, which downloads BuildKit (about 110 MB) once.")}</span></div>`;
  const parts = img && vol ? tr("BuildKit {size} and its build cache", { size: size(img.Size) }) : img ? tr("BuildKit {size}", { size: size(img.Size) }) : tr("its build cache");
  return `<div class="pref"><span class="t">${tr("Kiri's builder")}</span><span class="d">${tr("{parts}. Not listed in Images or Volumes: it's docker build's machinery.", { parts })}</span>
    <button class="btn sm" data-buildprune${ui.bwPruning ? " disabled" : ""}>${ui.bwPruning ? tr("Clearing…") : tr("Clear build cache")}</button></div>`;
}

/* Settings → Builds: cache limit and idle sleep (/kiri/builder). */
function builderSettingsPrefs() {
  const s = ui.bset;
  if (!s || s.error) return "";
  const cacheVal = Math.min(128, Math.max(2, Number(ui.bsetDraft?.cache_gb ?? s.cache_gb ?? s.default_cache_gb ?? 20)));
  const idleVal = Number(ui.bsetDraft?.idle_secs ?? s.idle_secs ?? 300);
  const idleOpts = [[300, tr("5 min")], [600, tr("10 min")], [1800, tr("30 min")], [0, tr("Never")]];
  return `<div class="pref"><span class="t">${tr("Build cache limit")}</span>
      <span class="d">${tr("Oldest cached layers are pruned automatically once BuildKit's cache passes this size.")}</span>
      <div class="range"><input type="range" id="bld-cache" min="2" max="128" step="2" value="${cacheVal}" aria-label="${tr("Build cache limit")}" style="--fill:${rangeFill(cacheVal, 2, 128)}"><span class="num" id="bld-cache-v">${diskGb(cacheVal)}</span></div></div>
    <div class="pref"><span class="t">${tr("Stop builder when idle")}</span>
      <span class="d">${tr("Stops BuildKit between builds so it uses no memory while idle; the next build wakes it in under a second.")}</span>
      <div class="seg" role="group" aria-label="${tr("Stop builder when idle")}">${idleOpts.map(([v, l]) => `<button data-bldidle="${v}" aria-pressed="${idleVal === v}">${l}</button>`).join("")}</div></div>
    ${s.overridden ? `<p class="muted">${tr("KIRI_BUILD_CACHE_GB or KIRI_BUILDER_IDLE_SECS is set for the daemon, and it takes precedence over these.")}</p>` : ""}`;
}

/* Settings → Builds: Docker's builder or Kiri's for plain `docker build`, at once. */
function buildsPane() {
  const b = ui.bw;
  if (!b) return `<div class="pane"><h3>${tr("Builds")}</h3><p class="muted">${tr("Loading…")}</p></div>`;
  if (b.error) return `<div class="pane"><h3>${tr("Builds")}</h3><p class="muted">${esc(b.error)}</p></div>`;
  const kiri = b.with === "kiri", e = b.engine ? esc(b.engine) : "";
  const cmd = (c) => `<span class="mono">${c}</span>`;
  const desc = kiri
    ? `${tr("{build} and {compose} run on Kiri, and the images are in Kiri, whichever engine docker uses.", { build: cmd("docker build"), compose: cmd("docker compose build") })}${e ? ` ${tr("{engine} doesn't see them.", { engine: e })}` : ""}`
    : e ? tr("{build} builds wherever docker points, so {engine}'s builds stay in {engine}. When docker uses Kiri, builds run on Kiri.", { build: cmd("docker build"), engine: e })
    : tr("{build} builds wherever docker points. When docker uses Kiri, builds run on Kiri.", { build: cmd("docker build") });
  const note = kiri && !b.ready ? `<p class="muted">${tr("Kiri sets up its builder once its engine is running, and builds go to it from then on.")}</p>`
    : kiri && !b.taken ? `<p class="muted">${tr("Another builder has been picked for {build} since ({use}). Choose Kiri again to build on Kiri.", { build: cmd("docker build"), use: cmd("docker buildx use") })}</p>` : "";
  return `<div class="pane"><h3>${tr("Builds")}</h3>
    <div class="pref"><span class="t">${tr("Build with")}</span><span class="d">${desc}</span>
      <div class="seg" role="group" aria-label="${tr("Build with")}"><button data-bw="docker" aria-pressed="${!kiri}">Docker</button><button data-bw="kiri" aria-pressed="${kiri}">Kiri</button></div></div>
    ${note}
    ${builderPref()}
    ${builderSettingsPrefs()}
    <p class="muted">${tr("{cmd} always builds on Kiri. A switch applies at once, in terminals already open too. Switching back to Docker puts docker's build settings back as they were before Kiri changed them.", { cmd: cmd("kiri build") })}</p>
  </div>`;
}

/* Settings → Network: Docker's default socket + CLI binding, and the proxy. */
function dockerSockRows() {
  const app = ui.status?.app || "Kiri";
  const mono = (t) => `<span class="mono">${esc(String(t))}</span>`;
  const s = ui.dockersock;
  let sockRow = "";
  if (s) {
    let desc = "", pact = "";
    if (s.owner === "kiri") {
      desc = tr("{path} leads to {app}. Tools like Testcontainers, IDE plugins and SDKs use it directly.", { path: mono(s.path), app: esc(app) });
      pact = `<span class="pact kstate"><i class="on"></i>${esc(app)}</span>`;
    } else if (s.owner === "other") {
      const who = s.engine ? (s.target?.includes("/") ? `${esc(s.engine)} (${mono(s.target)})` : esc(s.engine)) : s.target ? mono(s.target) : tr("another engine");
      desc = `${tr("{path} belongs to {engine} and stays so.", { path: mono(s.path), engine: who })}<br><span class="sockhint">${tr("Tools that ignore docker contexts can use {hint}", { hint: `<code>${esc(s.hint)}</code>` })}${copyBtn(s.hint, tr("command"))}</span>`;
      pact = `<span class="pact kstate"><i></i>${s.engine ? esc(s.engine) : tr("In use")}</span>`;
    } else {
      desc = s.take
        ? tr("{path} is free. Link it to {app} so tools that ignore docker contexts find {app} there.", { path: mono(s.path), app: esc(app) })
        : WIN
          ? tr("{path} is free. {app} serves it whenever it runs and no other Docker engine does.", { path: mono(s.path), app: esc(app) })
          : LINUX
            ? tr("{path} is free. {service} links it when Kiri starts while no other Docker engine has it.", { path: mono(s.path), service: mono("kiri.service") })
            : tr("{path} is free. {app} leaves it for the installed Kiri.", { path: mono(s.path), app: esc(app) });
      pact = s.take
        ? `<span class="pact"><button class="btn primary" data-takesock${ui.sockTaking ? " disabled" : ""}>${ui.sockTaking ? tr("Linking…") : tr("Use {app}", { app: esc(app) })}</button></span>`
        : `<span class="pact kstate"><i></i>${tr("Free")}</span>`;
    }
    sockRow = `<div class="pref"><span class="t">${tr("Docker socket")}</span><span class="d">${desc}</span>${pact}</div>`;
  }
  let cliRow = "";
  if (ui.status) {
    const pinned = ctxPinned();
    let desc = "", pact = "";
    if (!ctxOther()) {
      desc = tr("The {docker} command uses {app}.", { docker: mono("docker"), app: esc(app) });
      pact = `<span class="pact kstate"><i class="on"></i>${esc(app)}</span>`;
    } else if (pinned) {
      desc = tr("{env} is set in this session, so {docker} uses another engine.", { env: mono(pinned), docker: mono("docker") });
      pact = `<span class="pact kstate"><i class="busy"></i>${esc(pinned)}</span>`;
    } else {
      desc = tr("The {docker} command uses {engine}.", { docker: mono("docker"), engine: esc(ctxLabel(ui.status.context)) });
      pact = `<span class="pact"><button class="btn primary" data-usekiri${ui.ctxSwitching ? " disabled" : ""}>${ui.ctxSwitching ? tr("Switching…") : tr("Use {app}", { app: esc(app) })}</button></span>`;
    }
    cliRow = `<div class="pref"><span class="t">${tr("{docker} command", { docker: mono("docker") })}</span><span class="d">${desc}</span>${pact}</div>`;
  }
  return sockRow + cliRow;
}

function vmNetRow() {
  const v = ui.vmnet;
  if (!v || v.supported === false) return "";
  const nat = v.shared_nat !== false, on = v.awake || engineShown().on;
  if (v.awake && v.running_shared_nat === nat) ui.vmNetSaved = false;
  const pending = on && ((v.awake && v.running_shared_nat != null && v.running_shared_nat !== nat) || (!v.awake && ui.vmNetSaved));
  const desc = nat
    ? tr("macOS NAT: fastest. Switch to Host relay if Cloudflare WARP or a corporate firewall blocks container HTTPS. Applies on VM restart.")
    : tr("Host relay: connections leave from Kiri on macOS instead of Virtualization.framework NAT. Applies on VM restart.");
  const envNote = v.env ? ` ${tr("KIRI_SHARED_NAT is set in the environment and takes precedence.")}` : "";
  return `<div class="pref"><span class="t">${tr("Outbound VM traffic")}</span>
    <span class="d">${desc}${envNote}</span>
    <div class="pact">${pending ? `<button class="btn" data-restartvm>${tr("Restart VM to apply")}</button>` : ""}<div class="seg" role="group" aria-label="${tr("Outbound VM traffic")}"><button data-vmnat="1" aria-pressed="${nat}"${v.env ? " disabled" : ""}>${tr("macOS NAT")}</button><button data-vmnat="0" aria-pressed="${!nat}"${v.env ? " disabled" : ""}>${tr("Host relay")}</button></div></div></div>`;
}

function networkPane() {
  const p = ui.proxy, sock = dockerSockRows(), vmnet = vmNetRow();
  if (!p) return `<div class="pane"><h3>${tr("Network")}</h3>${sock}${vmnet}<p class="muted">${tr("Loading…")}</p></div>`;
  if (p.error) return `<div class="pane"><h3>${tr("Network")}</h3>${sock}${vmnet}<p class="muted">${tr("Start Kiri to change its network settings. ({error})", { error: esc(p.error) })}</p></div>`;
  const d = ui.pxDraft, eff = p.effective;
  const seg = [["system", tr("{os} settings", { os: OS })], ["custom", tr("Custom")], ["none", tr("None")]].map(([v, l]) => `<button data-pxmode="${v}" aria-pressed="${d.mode === v}">${l}</button>`).join("");
  const now = eff.https || eff.http ? (eff.no_proxy.length ? tr("In use: {proxy}, except {hosts}.", { proxy: `<span class="mono">${esc(eff.https || eff.http)}</span>`, hosts: `<span class="mono">${esc(eff.no_proxy.join(", "))}</span>` }) : tr("In use: {proxy}.", { proxy: `<span class="mono">${esc(eff.https || eff.http)}</span>` })) : tr("No proxy is in use.");
  const field = (k, label, ph) => `<label class="pxf"><span>${label}</span><input class="field" id="px-${k}" value="${esc(d[k] || "")}" placeholder="${ph}" spellcheck="false" autocomplete="off"></label>`;
  return `<div class="pane"><h3>${tr("Network")}</h3>
    ${sock}
    ${vmnet}
    <div class="pref"><span class="t">${tr("Proxy")}</span><span class="d">${tr("For pulling and pushing images.")} ${d.mode === p.settings.mode ? now : ""}</span>
      <div class="seg" role="group" aria-label="${tr("Proxy")}">${seg}</div></div>
    ${d.mode === "system" && eff.pac ? `<p class="muted">${tr("{os} uses an automatic proxy configuration (PAC) file, which Kiri can't follow. Choose Custom and enter the proxy.", { os: OS })}</p>` : ""}
    ${d.mode === "custom" ? `<div class="pxgrid">${field("http", tr("HTTP proxy"), "proxy.example.com:3128")}${field("https", tr("HTTPS proxy"), "proxy.example.com:3128")}${field("no_proxy", tr("Bypass for"), "*.internal, registry.corp")}</div>` : ""}
    <div class="pref"><span class="t">${tr("Pass to containers")}</span><span class="d">${tr("New containers get {http}, {https} and {no}.", { http: `<span class="mono">HTTP_PROXY</span>`, https: `<span class="mono">HTTPS_PROXY</span>`, no: `<span class="mono">NO_PROXY</span>` })}${WIN ? "" : ` ${LINUX ? tr("A proxy on this computer is reached as {host}.", { host: `<span class="mono">host.docker.internal</span>` }) : tr("A proxy on this Mac is reached as {host}.", { host: `<span class="mono">host.docker.internal</span>` })}`}</span>
      <div class="seg" role="group" aria-label="${tr("Pass to containers")}"><button data-pxc="0" aria-pressed="${!d.containers}">${tr("Off")}</button><button data-pxc="1" aria-pressed="${!!d.containers}">${tr("On")}</button></div></div>
    <div class="res-foot"><span class="muted">${WIN ? tr("Container traffic leaves through WSL's network.") : LINUX ? tr("VPNs need no setting: container traffic leaves through Linux.") : tr("VPNs need no setting: container traffic leaves through macOS.")}</span><span style="flex:1"></span><button class="btn primary" data-savepx>${tr("Save")}</button></div>
  </div>`;
}

/* Settings → Domains: the ports the name routers listen on. Moving them
   needs no restart; a port that's taken changes nothing and says so. */
function routerPortsPref() {
  const r = ui.rports;
  if (!r) return "";
  if (r.error) return `<div class="pref"><span class="t">${tr("Ports")}</span><span class="d">${tr("Start Kiri to change the ports names answer on.")}</span></div>`;
  const mono = (t) => `<span class="mono">${esc(String(t))}</span>`;
  const field = (k, label) => `<label title="${label}"><span>${label}</span><input id="rp-${k}" type="number" min="1" max="65535" inputmode="numeric" aria-label="${label}" value="${esc(String(ui.rpDraft[k] ?? r[k].port))}"${r[k].env ? " disabled" : ""}></label>`;
  const notes = ["http", "https"].flatMap((k) => [
    r[k].env ? tr("{var} sets the {kind} port, so it can't be changed here.", { var: mono(r[k].env), kind: k.toUpperCase() }) : "",
    r[k].running === false ? tr("{kind} names are off: port {port} is in use. Pick another.", { kind: k.toUpperCase(), port: mono(r[k].port) })
      : !r[k].serving ? tr("{kind} names are paused: a container has port {port}.", { kind: k.toUpperCase(), port: mono(r[k].port) }) : "",
  ]).filter(Boolean);
  const url = `http://web.${ui.suffix}:${r.http.port === 8080 ? 8081 : 8080}`;
  return `<div class="pref"><span class="t">${tr("Ports")}</span><span class="d">${tr("Names answer on {http} and {https}. Pick other ports when another app needs these; links then carry the port, like {url}.", { http: mono(r.http.port), https: mono(r.https.port), url: mono(url) })}</span>
      <div class="rports">${field("http", "HTTP")}${field("https", "HTTPS")}<button class="btn primary" data-saverp${rpChanged() ? "" : " disabled"}>${tr("Change ports")}</button></div></div>
    <p class="muted rp-notes">${notes.length ? notes.join(" ") + " " : ""}${tr("A container that publishes one of these ports gets it; names on that port pause until it lets go.")}</p>`;
}

/* Settings › Resources: the engine's on/off, the same switch as the card. */
function enginePane() {
  const { shown } = engineShown(), off = shown === "stopped";
  const d = off ? tr("Off: press Start engine to run containers. It stays off after a restart until you start it.")
    : shown === "running" ? tr("Running: it rests by itself when nothing runs and wakes when you use it.")
    : shown === "booting" ? tr("Starting…") : shown === "stopping" ? tr("Stopping…") : shown === "restarting" ? tr("Restarting…") : "";
  const busy = shown === "booting" || shown === "stopping" || shown === "restarting";
  const btn = off ? `<button class="btn primary" data-vmpower="start"${busy ? " disabled" : ""}>${tr("Start engine")}</button>`
    : `<button class="btn" data-vmpower="stop"${busy ? " disabled" : ""}>${tr("Turn off engine")}</button>`;
  return `<div class="pane"><h3>${tr(VM)}</h3><div class="pref"><span class="t">${vmLabels[shown] != null ? tr(vmLabels[shown]) : "—"}</span><span class="d">${d}</span><span class="pact">${btn}</span></div></div>`;
}
/* i18n */ void [tr("Off"), tr("Starting…"), tr("Running"), tr("Stopping…"), tr("Linux VM"), tr("Engine")];

function resourcesPane() {
  const r = ui.res;
  if (!r) return `<div class="pane"><h3>${tr("Resources")}</h3><p class="muted">${tr("Loading…")}</p></div>`;
  if (r.error) return `<div class="pane"><h3>${tr("Resources")}</h3><p class="muted">${tr("Start Kiri to change its resources. ({error})", { error: esc(r.error) })}</p></div>`;
  const d = ui.resDraft;
  const maxGb = Math.max(1, Math.floor(r.max_memory_mib / 1024));
  const hasDisk = r.disk_gb != null;
  const minDisk = r.min_disk_gb ?? 64;
  const maxDisk = Math.max(minDisk, r.max_disk_gb ?? 1024);
  const diskVal = hasDisk ? Math.min(Math.max(d.disk_gb ?? r.disk_gb, minDisk), maxDisk) : minDisk;
  const diskStep = minDisk % 8 === 0 && diskVal % 8 === 0 && maxDisk % 8 === 0 ? 8 : 1;
  const hasSwap = r.swap_mib != null;
  const maxSwap = r.max_swap_mib ?? 16384;
  const swapVal = hasSwap ? Math.min(d.swap_mib ?? r.swap_mib, maxSwap) : 0;
  const diff = r.running_cpus !== r.cpus || Math.abs(r.running_memory_mib - r.memory_mib) > 64 || (hasDisk && r.running_disk_gb != null && r.running_disk_gb !== r.disk_gb) || (hasSwap && r.running_swap_mib != null && r.running_swap_mib !== r.swap_mib);
  if (r.awake && !diff) ui.resSaved = false;
  const pending = (r.awake || engineShown().on) && (diff || (!r.awake && ui.resSaved));
  return `<div class="pane"><h3>${tr("Resources")}</h3>
    <div class="pref"><span class="t">${tr("CPUs")}</span><span class="d">${LINUX ? tr("Shared with Linux: containers only use them while busy.") : tr("Shared with {os}: the VM only uses them while containers are busy.", { os: OS })}</span>
      <div class="range"><input type="range" id="res-cpus" min="1" max="${r.max_cpus}" step="1" value="${d.cpus}" aria-label="${tr("CPUs")}" style="--fill:${rangeFill(d.cpus, 1, r.max_cpus)}"><span class="num" id="res-cpus-v">${cpuText(d.cpus)}</span></div></div>
    <div class="pref"><span class="t">${tr("Memory")}</span><span class="d">${LINUX ? tr("The most containers and the engine may take. Unused memory stays free on Linux.") : tr("The most the VM may take. It uses memory only as containers need it and gives the rest back to {os}.", { os: OS })}</span>
      <div class="range"><input type="range" id="res-mem" min="1024" max="${maxGb * 1024}" step="1024" value="${Math.min(d.memory_mib, maxGb * 1024)}" aria-label="${tr("Memory")}" style="--fill:${rangeFill(Math.min(d.memory_mib, maxGb * 1024), 1024, maxGb * 1024)}"><span class="num" id="res-mem-v">${gb(d.memory_mib)}</span></div></div>
    ${hasSwap ? `<div class="pref"><span class="t">${tr("Swap")}</span><span class="d">${tr("Disk space the VM may use when its memory runs out, so containers slow down instead of being stopped. Applies on restart.")}</span>
      <div class="range"><input type="range" id="res-swap" min="0" max="${maxSwap}" step="512" value="${swapVal}" aria-label="${tr("Swap")}" style="--fill:${rangeFill(swapVal, 0, maxSwap)}"><span class="num" id="res-swap-v">${swapText(swapVal)}</span></div></div>` : ""}
    ${hasDisk ? `<div class="pref"><span class="t">${tr("Disk image size")}</span><span class="d">${tr("The most the VM disk may grow to. Space is used on {os} only as data is written, and unused space can be reclaimed in {storage}. Applies on restart.", { os: OS, storage: `<button class="linkbtn" data-stgoto>${tr("Settings → Storage")}</button>` })}</span>
      <div class="range"><input type="range" id="res-disk" min="${minDisk}" max="${maxDisk}" step="${diskStep}" value="${diskVal}" aria-label="${tr("Disk image size")}" style="--fill:${rangeFill(diskVal, minDisk, maxDisk)}"><span class="num" id="res-disk-v">${diskGb(diskVal)}</span></div></div>` : ""}
    ${r.overridden ? `<p class="muted">${hasDisk ? tr("KIRI_CPUS, KIRI_MEMORY_MIB or KIRI_DISK_GB is set for the daemon, and it takes precedence over these.") : tr("KIRI_CPUS or KIRI_MEMORY_MIB is set for the daemon, and it takes precedence over these.")}</p>` : ""}
    <div class="res-foot"><span class="muted">${r.awake ? (hasDisk ? tr("Running now with {cpus}, up to {mem}, and a {disk} disk.", { cpus: cpuText(r.running_cpus), mem: gb(r.running_memory_mib), disk: diskGb(r.running_disk_gb ?? r.disk_gb) }) : tr("Running now with {cpus} and up to {mem}.", { cpus: cpuText(r.running_cpus), mem: gb(r.running_memory_mib) })) : LINUX ? tr("The engine is off; it starts with these next time.") : tr("The VM is asleep; it starts with these next time.")}</span>
      <span style="flex:1"></span>
      ${pending ? `<button class="btn" id="res-restart" data-restartvm>${LINUX ? tr("Restart engine to apply") : tr("Restart VM to apply")}</button>` : ""}
      <button class="btn primary" id="res-save" data-saveres${resChanged() ? "" : " disabled"}>${tr("Save")}</button></div>
    ${pending ? `<p class="muted">${esc(r.restart_note || tr("Restarting stops the running containers; start them again afterwards."))}</p>` : ""}
  </div>`;
}

function wslPane() {
  const list = ui.res?.wsl_distros;
  const hasWatch = prefs.watchBindMounts != null || ui.res?.watch_bind_mounts != null;
  if (!WIN && !Array.isArray(list) && !hasWatch) return "";
  const watchOn = !!(prefs.watchBindMounts ?? ui.res?.watch_bind_mounts);
  const watchRow = `<div class="pref"><span class="t">${tr("Windows bind-mount file events")}</span><span class="d">${tr("Forward file changes on Windows drives (like {path}) into containers for live reload. Uses no CPU when idle.", { path: '<span class="mono">C:\\</span>' })}</span>
    <div class="seg" role="group" aria-label="${tr("Windows bind-mount file events")}"><button data-watchbinds="0" aria-pressed="${!watchOn}">${tr("Off")}</button><button data-watchbinds="1" aria-pressed="${watchOn}">${tr("On")}</button></div></div>`;
  const distros = Array.isArray(list)
    ? (list.length
      ? list.map((w) => `<div class="pref"><span class="t">${esc(w.name)}</span><span class="d">${tr("docker, Compose and Docker-socket tools reach Kiri")}</span>
    <div class="seg" role="group" aria-label="${esc(w.name)}"><button data-wsldistro="${esc(w.name)}" data-wslon="0" aria-pressed="${!w.on}">${tr("Off")}</button><button data-wsldistro="${esc(w.name)}" data-wslon="1" aria-pressed="${!!w.on}">${tr("On")}</button></div></div>`).join("")
      : `<p class="muted">${tr("No other WSL distros installed.")}</p>`)
    : WIN ? `<p class="muted">${tr("Loading…")}</p>` : "";
  return `<div class="pane"><h3>${tr("WSL integration")}</h3>${watchRow}${distros}</div>`;
}

function storageUnavailableBox(s, linkSettings) {
  return `<div class="st-box warn" role="alert">
    <div class="st-hd"><svg class="i" viewBox="0 0 256 256" aria-hidden="true"><path d="${PH.warning}"/></svg><span>${tr("Storage location unavailable")}</span></div>
    <p>${tr("Kiri couldn't find its data in {path}. Connect its drive and retry, choose another folder, or reset to the default location.", { path: `<span class="mono st-path">${esc(s.path || "")}</span>` })}</p>
    <div class="st-row">
      <button class="btn primary" data-stretry>${tr("Retry")}</button>
      <button class="btn" data-stpick>${tr("Change…")}</button>
      <button class="btn" data-streset>${tr("Reset to default")}</button>
      ${linkSettings ? `<button class="btn" data-stgoto>${tr("Open storage settings")}</button>` : ""}
    </div>
  </div>`;
}

function renderStorageUnavailable() {
  const s = ui.storage || {};
  $("content").innerHTML = `<div class="empty"><div><svg class="i art" viewBox="0 0 256 256"><path d="${PH.harddrive}"/></svg>
    <h3>${tr("Storage location unavailable")}</h3>
    <p>${tr("Kiri couldn't find its data in {path}. Connect its drive and retry, choose another folder, or reset to the default location.", { path: `<span class="mono st-path">${esc(s.path || "")}</span>` })}</p>
    <div class="st-row" style="justify-content:center">
      <button class="btn primary" data-stretry>${tr("Retry")}</button>
      <button class="btn" data-stpick>${tr("Change…")}</button>
      <button class="btn" data-streset>${tr("Reset to default")}</button>
      <button class="btn" data-stgoto>${tr("Open storage settings")}</button>
    </div></div></div>`;
}

function storageDiskRow(s, moving) {
  if (LINUX) {
    return `<div class="pref"><span class="t">${tr("VM disk space")}</span>
      <span class="d">${tr("Native Linux uses your host filesystem directly — deleted images and volumes free space immediately.")}</span></div>`;
  }
  const vhdx = '<span class="mono">ext4.vhdx</span>';
  const diskHost = s.disk_host, diskInUse = s.disk_in_use, reclaimable = s.reclaimable;
  const btnLbl = WIN ? tr("Compact disk…") : tr("Reclaim space");
  const busyLbl = WIN ? tr("Compacting…") : tr("Reclaiming…");
  let d = "";
  if (ui.stReclaiming) {
    d = WIN
      ? tr("Compacting {vhdx} and restarting the engine…", { vhdx })
      : diskHost != null && diskInUse != null
        ? tr("{host} on {os}, {inUse} in use inside the VM · trimming unused blocks…", { host: size(diskHost), os: OS, inUse: size(diskInUse) })
        : tr("Trimming unused blocks inside the VM disk…");
  } else if (ui.stReclaimed) {
    const r = ui.stReclaimed, after = r.after ?? diskHost, inUse = r.in_use ?? diskInUse, freed = r.reclaimed || 0;
    const freedHtml = `<span style="color:var(--moss)">${tr("Freed {size}", { size: size(freed) })}</span>`;
    if (freed > 0) {
      d = after != null && inUse != null
        ? (WIN
          ? tr("{host} on Windows ({vhdx}), {inUse} in use · {freed}.", { host: size(after), vhdx, inUse: size(inUse), freed: freedHtml })
          : tr("{host} on {os}, {inUse} in use inside the VM · {freed}.", { host: size(after), os: OS, inUse: size(inUse), freed: freedHtml }))
        : freedHtml;
    } else {
      d = after != null && inUse != null
        ? (WIN
          ? tr("{host} on Windows ({vhdx}), {inUse} in use · nothing to reclaim.", { host: size(after), vhdx, inUse: size(inUse) })
          : tr("{host} on {os}, {inUse} in use inside the VM · nothing to reclaim.", { host: size(after), os: OS, inUse: size(inUse) }))
        : tr("Nothing to reclaim.");
    }
  } else if (diskHost != null && diskInUse != null && reclaimable > 0) {
    const can = `<b style="color:var(--text)">${tr("{size} can be given back", { size: size(reclaimable) })}</b>`;
    d = WIN
      ? tr("{host} on Windows ({vhdx}), {inUse} in use · {can}. Compacting restarts the engine.", { host: size(diskHost), vhdx, inUse: size(diskInUse), can })
      : tr("{host} on {os}, {inUse} in use inside the VM · {can} without stopping containers.", { host: size(diskHost), os: OS, inUse: size(diskInUse), can });
  } else if (diskHost != null && diskInUse != null) {
    d = WIN
      ? tr("{host} on Windows ({vhdx}), {inUse} in use · nothing to reclaim.", { host: size(diskHost), vhdx, inUse: size(diskInUse) })
      : tr("{host} on {os}, {inUse} in use inside the VM · nothing to reclaim.", { host: size(diskHost), os: OS, inUse: size(diskInUse) });
  } else if (diskHost != null) {
    d = WIN
      ? tr("{host} on Windows ({vhdx}). Compacting returns unused space and restarts the engine.", { host: size(diskHost), vhdx })
      : tr("{host} on {os}. Reclaiming trims unused blocks in the VM disk without stopping containers.", { host: size(diskHost), os: OS });
  } else {
    d = WIN
      ? tr("Returns unused space in {vhdx} to Windows. Compacting restarts the engine.", { vhdx })
      : tr("Returns unused blocks in the VM disk to {os} without stopping containers.", { os: OS });
  }
  const dis = moving || (diskHost != null && diskInUse != null && !(reclaimable > 0));
  const ctl = ui.stReclaiming
    ? `<span class="st-acts"><span class="hbusy"><i class="hspin"></i>${busyLbl}</span></span>`
    : `<span class="st-acts"><button class="btn" data-streclaim${dis ? " disabled" : ""}>${btnLbl}</button></span>`;
  return `<div class="pref st-pref"><span class="t">${tr("VM disk space")}</span><span class="d num">${d}</span>${ctl}</div>`;
}

function storagePruneRow(moving) {
  const stoppedN = ui.containers.filter((c) => c.State !== "running").length;
  const danglingImgs = ui.images.filter((i) => !(i.RepoTags || []).some((t) => t && t !== "<none>:<none>" && !t.startsWith("sha256:")));
  const danglingSize = danglingImgs.reduce((a, i) => a + (i.Size || 0), 0);
  const hasCache = !!ui.builderVolume;
  const hasUnused = stoppedN > 0 || danglingImgs.length > 0 || hasCache;
  let d = "";
  if (ui.stPruning) {
    d = tr("Cleaning up stopped containers, untagged images, and build cache…");
  } else if (hasUnused) {
    const parts = [];
    if (stoppedN > 0) parts.push(trn(stoppedN, "{n} stopped container", "{n} stopped containers"));
    if (danglingImgs.length > 0) {
      const cnt = trn(danglingImgs.length, "{n} untagged image", "{n} untagged images");
      parts.push(danglingSize > 0 ? tr("{count} ({size})", { count: cnt, size: size(danglingSize) }) : cnt);
    }
    if (hasCache) parts.push(tr("build cache"));
    d = `${parts.join(" · ")}.`;
  } else if (ui.stPruned && ui.stPruned.freed > 0) {
    d = tr("No stopped containers, untagged images or build cache · {freed}.", {
      freed: `<span style="color:var(--moss)">${tr("Freed {size}", { size: size(ui.stPruned.freed) })}</span>`,
    });
  } else {
    d = tr("No stopped containers, untagged images or build cache.");
  }
  const ctl = ui.stPruning
    ? `<span class="st-acts"><span class="hbusy"><i class="hspin"></i>${tr("Cleaning up…")}</span></span>`
    : `<span class="st-acts"><button class="btn" data-stprune${moving || !hasUnused ? " disabled" : ""}>${tr("Clean up…")}</button></span>`;
  return `<div class="pref st-pref"><span class="t">${tr("Unused Docker data")}</span><span class="d num">${d}</span>${ctl}</div>`;
}

function storagePane() {
  const s = ui.storage;
  if (!s) return `<div class="pane"><h3>${tr("Storage")}</h3><p class="muted">${tr("Loading…")}</p></div>`;
  if (s.error && !s.path) return `<div class="pane"><h3>${tr("Storage")}</h3><p class="muted">${tr("Start Kiri to change its storage location. ({error})", { error: esc(s.error) })}</p></div>`;
  const moving = s.state === "moving", unavail = s.state === "unavailable", locked = moving || !!s.env;
  const stats = [s.used != null ? tr("{size} used", { size: size(s.used) }) : "", s.free != null ? tr("{size} free", { size: size(s.free) }) : "", s.fs ? esc(s.fs) : ""].filter(Boolean).join(" · ");
  const badge = !s.custom && !s.env ? `<span class="st-badge">${tr("Default")}</span>` : "";
  const m = s.moving;
  const pct = m && m.total > 0 ? Math.min(100, Math.round((m.done / m.total) * 100)) : null;
  const progressBox = moving && m ? `<div class="st-box" role="status">
    <div class="st-hd">${rspin("sm plain")}<span>${stPhaseText(m.phase)}</span></div>
    <p>${tr("Moving Kiri's data to {path}.", { path: `<span class="mono st-path">${esc(m.to || "")}</span>` })}</p>
    ${pct != null ? `<div class="st-bar"><span style="width:${pct}%"></span></div><p class="num">${size(m.done)} / ${size(m.total)} (${pct}%)</p>` : ""}
    <p>${tr("Running containers pause while Kiri copies its data and start again once it's done.")}</p>
  </div>` : "";
  const errText = ui.stErr || (!moving && s.error ? s.error : "");
  const errBox = errText ? `<div class="st-box err" role="alert">
    <div class="st-hd"><svg class="i" viewBox="0 0 256 256" aria-hidden="true"><path d="${PH.warning}"/></svg><span>${tr("Couldn't change storage location")}</span></div>
    <p>${esc(errText)}</p>
    ${ui.stErr ? `<div class="st-row"><button class="btn sm" data-sterrclose>${tr("Dismiss")}</button></div>` : ""}
  </div>` : "";
  const oldRow = s.old && s.state === "ok" ? `<div class="pref st-pref">
    <span class="t">${tr("Old data")}</span>
    <span class="d">${tr("Previous data is still in {path}. Remove it once everything works in the new location.", { path: `<span class="mono st-path">${esc(s.old)}</span>` })}</span>
    <span class="st-acts"><button class="btn" data-strmold>${tr("Remove old data")}</button></span>
  </div>` : "";
  return `<div class="pane"><h3>${tr("Storage")}</h3>
    ${unavail ? storageUnavailableBox(s, false) : ""}
    <div class="pref st-pref">
      <span class="t st-t"><span>${tr("Storage location")}</span>${badge}</span>
      <span class="d"><span class="mono st-path">${esc(s.path || "")}</span>${stats ? `<span class="st-meta">${stats}</span>` : ""}</span>
      <span class="st-acts">
        <button class="btn" data-stpick${locked ? " disabled" : ""}>${tr("Change…")}</button>
        ${s.custom ? `<button class="btn" data-streset${locked ? " disabled" : ""}>${tr("Reset to default")}</button>` : ""}
      </span>
    </div>
    ${s.env ? `<p class="muted">${tr("{var} sets Kiri's storage location, so it can't be changed here.", { var: `<span class="mono">KIRI_DATA_DIR</span>` })}</p>` : ""}
    ${progressBox}
    ${errBox}
    ${oldRow}
    ${!unavail ? storageDiskRow(s, moving) : ""}
    ${!unavail ? storagePruneRow(moving) : ""}
    <p class="muted">${tr("Images, containers, and volumes live in this folder. External drives must use a native filesystem (APFS on macOS, ext4/xfs/btrfs on Linux, NTFS on Windows); FAT and exFAT drives aren't supported.")}</p>
  </div>`;
}

function storageConfirm(c) {
  $("st-dlg")?.remove();
  const s = ui.storage || {};
  const unavail = s.state === "unavailable";
  const hasData = !unavail && ((s.used || 0) > 0 || ui.containers.length > 0 || ui.images.length > 0 || ui.volumes.length > 0);
  const showMode = !c.reset && hasData;
  const title = c.reset ? tr("Reset storage location to default?") : tr("Change storage location?");
  const meta = !unavail && c.free != null ? `<p>${tr("Destination: {path} ({free} free).", { path: `<span class="mono st-path">${esc(c.path)}</span>`, free: size(c.free) })}</p>`
    : `<p>${tr("Destination: {path}.", { path: `<span class="mono st-path">${esc(c.path)}</span>` })}</p>`;
  const warn = c.replaces ? `<p>${tr("Existing Kiri data in this folder will be replaced.")}</p>` : "";
  const modeHtml = showMode ? `<div class="st-opts" role="radiogroup" aria-label="${tr("Migration mode")}">
    <label class="st-opt"><input type="radio" name="st-mode" value="move" checked><b>${tr("Move existing images, containers, and volumes")}</b><small>${tr("Stops running containers, copies your data, and starts them again.")}</small></label>
    <label class="st-opt"><input type="radio" name="st-mode" value="fresh"><b>${tr("Start fresh")}</b><small>${tr("Starts empty in the new folder. Your old folder stays until you remove it.")}</small></label>
  </div>` : `<p>${unavail ? tr("Kiri will switch to this folder and restart the engine.") : tr("Running containers will stop while Kiri moves your data and start again once it's done.")}</p>`;
  const scrim = document.createElement("div");
  scrim.className = "scrim"; scrim.id = "st-dlg";
  scrim.innerHTML = `<div class="dialog alert" role="dialog" aria-modal="true" aria-labelledby="st-h">${alertIco(c.replaces ? "warn" : "info")}<h3 id="st-h">${title}</h3>
    ${meta}${warn}${modeHtml}
    <div class="row-end"><span></span><span><button class="btn" data-stcancel>${tr("Cancel")}</button> <button class="btn primary" data-stgo>${c.reset ? tr("Reset to default") : tr("Move data")}</button></span></div></div>`;
  document.body.append(scrim);
  const goBtn = scrim.querySelector("[data-stgo]");
  const close = () => { scrim.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (ev) => { if (ev.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  scrim.querySelectorAll('input[name="st-mode"]').forEach((r) => r.addEventListener("change", () => {
    goBtn.textContent = r.value === "fresh" && r.checked ? tr("Start fresh") : tr("Move data");
  }));
  scrim.addEventListener("click", (ev) => {
    if (ev.target === scrim || ev.target.closest("[data-stcancel]")) return close();
    if (ev.target.closest("[data-stgo]")) {
      const fresh = scrim.querySelector('input[name="st-mode"]:checked')?.value === "fresh";
      ui.stErr = "";
      startRestartOverlay("storage", c.reset ? tr("Kiri will switch to this folder and restart the engine.") : tr("Moving Kiri's data to {path}.", { path: `<span class="mono st-path">${esc(c.path)}</span>` }), tr("Stopping containers…"));
      if (c.reset) send("storagereset");
      else send("storagemove", { path: c.path, value: { fresh } });
      close();
    }
  });
  goBtn.focus();
}

function renderSettings() {
  const tab = (id, icon, label) => `<button data-stab="${id}" aria-current="${prefs.tab === id}"><svg class="i" viewBox="0 0 256 256"><path d="${PH[icon]}"/></svg>${label}</button>`;
  const appearancePane = () => {
    const opts = (list, current, system) => {
      const memo = optsMemo[system];
      if (memo?.list !== list || memo.current !== current) optsMemo[system] = { list, current, html: [system, ...list].map((f) =>
        `<option value="${esc(f)}"${f === current ? " selected" : ""}>${f !== system ? esc(f) : f === "System" ? tr("System|font") : tr("System Mono|font")}</option>`).join("") };
      return optsMemo[system].html;
    };
    /* A tiny window in each theme's colours, for the Theme choice. */
    const mini = (dark) => {
      const c = dark ? { bg: "#0F1419", side: "#121920", line: "#2A313A", bar: "#66707C", text: "#98A1AC" } : { bg: "#FFFFFF", side: "#EDF0F5", line: "#DDE3EB", bar: "#8A929C", text: "#5E6773" };
      const accent = (ACCENTS.find(([id]) => id === prefs.accent) || ACCENTS[0])[2];
      const rows = [0, 1, 2, 3].map((i) => `<rect x="46" y="${22 + i * 11}" width="${[40, 32, 44, 30][i]}" height="3" rx="1.5" fill="${i === 1 ? accent : c.text}"/><rect x="${96}" y="${22 + i * 11}" width="${[18, 24, 14, 20][i]}" height="3" rx="1.5" fill="${["#3FB68B", "#3FB68B", "#FFC23D", "#3FB68B"][i]}"/>`).join("");
      return `<svg viewBox="0 0 132 74" aria-hidden="true"><rect x=".5" y=".5" width="131" height="73" rx="6" fill="${c.bg}" stroke="${c.line}"/>
        <path d="M6.5 .5h32v73h-32a6 6 0 0 1-6-6v-61a6 6 0 0 1 6-6z" fill="${c.side}"/>${[0, 1, 2].map((i) => `<circle cx="${7 + i * 5}" cy="7" r="1.6" fill="${c.bar}"/>`).join("")}
        ${[0, 1, 2, 3].map((i) => `<rect x="7" y="${18 + i * 9}" width="${[22, 18, 24, 16][i]}" height="3" rx="1.5" fill="${i === 0 ? accent : c.bar}"/>`).join("")}
        <rect x="44" y="30.5" width="84" height="9" rx="2" fill="${accent}" fill-opacity=".14"/>${rows}<rect x="106" y="62" width="20" height="6" rx="2" fill="${accent}"/></svg>`;
    };
    const inUse = darkNow();
    const sysName = LANGS.find(([id]) => id === resolveLang("system"))?.[1] || "English";
    const startAtLogin = prefs.startAtLogin ?? !LINUX;
    const stopOnQuit = prefs.stopOnQuit === true;
    return `<div class="pane"><h3>${tr("Appearance")}</h3>
    <div class="pref"><span class="t" id="pref-lang-t">${tr("Language")}</span><span class="d">${tr("Follow {os} (now {lang}), or always use one language.", { os: OS, lang: sysName })}</span>
      ${langButton(sysName)}
      <select id="pref-lang" class="lsrc" aria-label="${tr("Language")}" aria-hidden="true" tabindex="-1" inert>${[["system", `${tr("System")} (${sysName})`], ...LANGS].map(([v, l]) => `<option value="${v}"${(prefs.lang || "system") === v ? " selected" : ""}${v === "system" ? "" : ` lang="${v}"`}>${l}</option>`).join("")}</select></div>
    <div class="pref"><span class="t">${tr("Theme")}</span><span class="d">${tr("Follow {os}, or always use the dark or light theme.", { os: OS })}</span>
      <div class="seg" role="group" aria-label="${tr("Theme")}">${[["system", tr("System")], ["dark", tr("Dark")], ["light", tr("Light")]].map(([v, l]) => `<button data-theme-pick="${v}" aria-pressed="${prefs.theme === v}">${l}</button>`).join("")}</div></div>
    <div class="themes">${[[false, tr("Light")], [true, tr("Dark")]].map(([dark, l]) => `<button class="tcard" data-theme-pick="${dark ? "dark" : "light"}" aria-pressed="${inUse === dark}">${mini(dark)}<span>${l}${inUse === dark ? ` <em>${tr("In use")}</em>` : ""}</span></button>`).join("")}</div>
    <div class="pref"><span class="t">${tr("Accent")}</span><span class="d">${tr("Selection, focus rings and primary buttons.")}</span>
      <div class="swatches" role="radiogroup" aria-label="${tr("Accent")}">${ACCENTS.map(([id, l, hex]) => `<button role="radio" aria-checked="${prefs.accent === id}" aria-label="${tr(l)}" title="${tr(l)}" data-accent="${id}" style="--sw:${hex}"></button>`).join("")}</div></div>
    <div class="pref"><span class="t">${tr("Interface font")}</span><span class="d">${tr("Tables, the sidebar and headings.")}</span>
      <select id="pref-font" data-ssfont aria-label="${tr("Interface font")}">${opts(fontLists.families, prefs.font, "System")}</select></div>
    <div class="pref"><span class="t">${tr("Monospace font")}</span><span class="d">${tr("IDs, commands and code.")}</span>
      <select id="pref-mono" data-ssfont aria-label="${tr("Monospace font")}">${opts(fontLists.mono, prefs.mono, "System Mono")}</select></div>
    <div class="pref"><span class="t">${tr("Text size")}</span><span class="d">${tr("Everything in the window.")}</span>
      <div class="seg" role="group" aria-label="${tr("Text size")}">${SIZES.map((z) => `<button data-scale="${z}" aria-pressed="${Math.abs((prefs.scale || 1) - z) < 0.01}">${Math.round(z * 100)}%</button>`).join("")}</div></div>
    <div class="pref"><span class="t">${tr("Log text")}</span><span class="d">${tr("Container, Kubernetes and diagnostics logs.")}</span>
      <div class="seg" role="group" aria-label="${tr("Log text")}">${LOG_SIZES.map(([px, l]) => `<button data-logsize="${px}" aria-pressed="${prefs.logSize === px}">${tr(l)}</button>`).join("")}</div></div>
    <div class="pref"><span class="t">${tr("Closing the window")}</span><span class="d">${prefs.closeButton === "close"
      ? tr("Close: the memory the window uses is freed. It takes a moment to open again, and open terminals end.")
      : tr("Hide: the window stays ready and opens again at once.")}</span>
      <div class="seg" role="group" aria-label="${tr("Closing the window")}"><button data-closebtn="hide" aria-pressed="${prefs.closeButton !== "close"}">${tr("Hide")}</button><button data-closebtn="close" aria-pressed="${prefs.closeButton === "close"}">${tr("Close")}</button></div></div>
    <div class="preview"><div class="p-title">web · nginx:alpine</div><div>Up 3 minutes · 26.3 MB · localhost:8080 → 80</div><div class="p-mono">ef9a6e2b45c2  docker run -p 8080:80 nginx</div></div>
    <div class="pref"><span class="t">${tr("Start Kiri at sign-in")}</span><span class="d">${tr("Start Kiri in the background when you sign in.")}</span>
      <div class="seg" role="group" aria-label="${tr("Start Kiri at sign-in")}"><button data-startlogin="0" aria-pressed="${!startAtLogin}">${tr("Off")}</button><button data-startlogin="1" aria-pressed="${startAtLogin}">${tr("On")}</button></div></div>
    <div class="pref"><span class="t">${tr("Stop the engine when Kiri quits")}</span><span class="d">${tr("Quitting Kiri stops running containers and the engine. Opening Kiri starts it again.")}</span>
      <div class="seg" role="group" aria-label="${tr("Stop the engine when Kiri quits")}"><button data-stopquit="0" aria-pressed="${!stopOnQuit}">${tr("Off")}</button><button data-stopquit="1" aria-pressed="${stopOnQuit}">${tr("On")}</button></div></div>
    ${ui.shellPath && ui.shellPath.supported !== false ? `<div class="pref"><span class="t">${tr("Command-line tools in shell")}</span><span class="d">${tr("Add {bin} to {zshrc} and {zprofile} so {docker}, {kubectl} and {kiri} work in new terminals.", { bin: '<span class="mono">~/.kiri/bin</span>', zshrc: '<span class="mono">.zshrc</span>', zprofile: '<span class="mono">.zprofile</span>', docker: '<span class="mono">docker</span>', kubectl: '<span class="mono">kubectl</span>', kiri: '<span class="mono">kiri</span>' })}</span>
      <div class="seg" role="group" aria-label="${tr("Command-line tools in shell")}"><button data-shellpath="0" aria-pressed="${!ui.shellPath.enabled}"${ui.shellPathBusy ? " disabled" : ""}>${tr("Off")}</button><button data-shellpath="1" aria-pressed="${!!ui.shellPath.enabled}"${ui.shellPathBusy ? " disabled" : ""}>${tr("On")}</button></div></div>` : ""}
  </div>`;
  };
  const domainsPane = () => {
    const portsPref = routerPortsPref();
    // On Linux: kiri.localhost only, for now; nothing to switch.
    return LINUX ? `<div class="pane"><h3>${tr("Domains")}</h3>
    <div class="pref"><span class="t">${tr("Local names")}</span><span class="d">${tr("Running containers answer at <span class=mono>&lt;name&gt;.kiri.localhost</span>, which needs no setup.")}</span></div>
    ${portsPref}
    <p class="muted">${tr("Compose services answer at {addr}.", { addr: `<span class="mono">&lt;service&gt;.&lt;project&gt;.kiri.localhost</span>` })} ${tr("{local} names and HTTPS aren't on Linux yet.", { local: `<span class="mono">.kiri.local</span>` })}</p>
  </div>`
  // On Windows: a DNS rule instead of /etc/resolver, and no HTTPS.
  : WIN ? `<div class="pane"><h3>${tr("Domains")}</h3>
    <div class="pref"><span class="t">${tr("Local names")}</span><span class="d">${ui.domainsOn
      ? tr("On: running containers answer at <span class=mono>&lt;name&gt;.kiri.local</span>.")
      : tr("Off: containers answer at <span class=mono>&lt;name&gt;.kiri.localhost</span>, which needs no setup.")}</span>
      <div class="seg" role="group" aria-label="${tr("Local names")}"><button data-domains="0" aria-pressed="${!ui.domainsOn}">kiri.localhost</button><button data-domains="1" aria-pressed="${!!ui.domainsOn}">kiri.local</button></div></div>
    ${portsPref}
    <p class="muted">${tr("Compose services answer at {addr}.", { addr: `<span class="mono">&lt;service&gt;.&lt;project&gt;.${ui.suffix}</span>` })} ${tr("Changing this asks Windows for an administrator's approval, since it adds or removes a DNS rule for {local}.", { local: `<span class="mono">.kiri.local</span>` })}</p>
  </div>` : `<div class="pane"><h3>${tr("Domains")}</h3>
    <div class="pref"><span class="t">${tr("Local names")}</span><span class="d">${ui.domainsOn
      ? tr("On: running containers answer at <span class=mono>&lt;name&gt;.kiri.local</span>.")
      : tr("Off: containers answer at <span class=mono>&lt;name&gt;.kiri.localhost</span>, which needs no setup.")}</span>
      <div class="seg" role="group" aria-label="${tr("Local names")}"><button data-domains="0" aria-pressed="${!ui.domainsOn}">kiri.localhost</button><button data-domains="1" aria-pressed="${!!ui.domainsOn}">kiri.local</button></div></div>
    <div class="pref"><span class="t">HTTPS</span><span class="d">${ui.https
      ? tr("On: containers open at <span class=mono>https://</span> with Kiri's own certificate, which only vouches for <span class=mono>.kiri.local</span> and <span class=mono>.kiri.localhost</span> names.")
      : tr("Trust Kiri's certificate so {url} works. macOS asks for your password. The certificate can only vouch for Kiri's own names.", { url: `<span class=mono>https://myapp.${ui.suffix}</span>` })}</span>
      <div class="seg" role="group" aria-label="HTTPS"><button data-https="0" aria-pressed="${!ui.https}">${tr("Off")}</button><button data-https="1" aria-pressed="${!!ui.https}">${tr("On")}</button></div></div>
    ${portsPref}
    <p class="muted">${tr("Compose services answer at {addr}.", { addr: `<span class="mono">&lt;service&gt;.&lt;project&gt;.${ui.suffix}</span>` })} ${tr("Changing this needs admin rights (an administrator password), since it adds or removes {path}.", { path: `<span class="mono">/etc/resolver/kiri.local</span>` })}</p>
  </div>`;
  };
  const aboutPane = () => {
    const a = about;
    const mib = (b) => (b ? `${(b / 1073741824).toFixed(1)} GB` : "—");
    const canUninstall = a?.can_uninstall ?? (!WIN && !LINUX);
    return `<div class="pane about"><div class="about-head">
      <svg viewBox="0 0 64 64" aria-hidden="true"><g transform="translate(6 0) skewX(-10)"><clipPath id="lid2"><rect x="22" y="12" width="34" height="40" rx="10"/></clipPath>
        <rect x="22" y="12" width="34" height="40" rx="10" fill="#E0B420"/><g clip-path="url(#lid2)"><rect x="10" y="0" width="60" height="21.5" fill="#F2CF5B"/></g>
        <g fill="#0F1419"><ellipse cx="41.5" cy="29" rx="3.1" ry="3.6"/><ellipse cx="50.5" cy="29" rx="3.1" ry="3.6"/></g></g>
        <g fill="currentColor" opacity=".55"><rect x="5" y="21.5" width="13" height="5" rx="2.5"/><rect x="1" y="32" width="15" height="5" rx="2.5"/><rect x="7" y="42.5" width="7" height="5" rx="2.5"/></g></svg>
      <div><div class="n">Kiri <span class="devband">DEV</span></div><div class="muted">${tr("A small, fast container runtime.")}</div></div></div>
    ${aboutUpdate(a?.app)}
    <dl>
      <dt>${tr("Engine")}</dt><dd>${a?.running ? `Kiri ${esc(a.engine)} · Docker API ${esc(a.api)}` : tr("Not running")}</dd>
      <dt>${tr(VM)}</dt><dd>${a?.running ? `${a.awake ? tr("Running") : tr("Asleep")} · ${tr("kernel {version}", { version: esc(a.kernel) })}` : "—"}</dd>
      <dt>${tr("CPUs")}</dt><dd>${esc(a?.cpus ?? "—")}</dd>
      <dt>${tr("Memory")}</dt><dd>${a?.running ? tr("up to {size}", { size: mib(a.memory) }) : "—"}</dd>
      <dt>${tr("Website")}</dt><dd><a data-open-site="https://runkiri.com">runkiri.com</a></dd>
      <dt>${tr("Made by")}</dt><dd><a data-open-site="https://canestack.com">Canestack Labs</a></dd>
      <dt>${tr("Community")}</dt><dd><a data-open-site="https://discord.gg/K5A8wuqcC"><svg class="soc-i" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M20.317 4.37a19.79 19.79 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.74 19.74 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.11 13.11 0 0 1-1.872-.892.077.077 0 0 1-.008-.128c.126-.094.252-.192.372-.291a.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.099.246.198.373.292a.077.077 0 0 1-.006.127 12.3 12.3 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.84 19.84 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.06.06 0 0 0-.031-.028ZM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418Zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418Z"/></svg>Discord</a> <span class="muted">·</span> <a data-open-site="https://x.com/runkiri"><svg class="soc-i" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>@runkiri</a></dd>
    </dl>
    <p class="muted">${tr("The name comes from the Igbo word ntakịrị, “small”.")}</p>
    ${canUninstall ? `<div class="pref"><span class="t">${tr("Uninstall Kiri")}</span>
      <span class="d">${tr("Stops the engine, removes Kiri's background service, CLI links and shell profile entries, and restores your previous Docker context ({cmd}).", { cmd: '<span class="mono">kiri setup --uninstall</span>' })}</span>
      <span class="pact"><button class="btn danger" data-uninstall>${tr("Uninstall Kiri…")}</button></span></div>` : ""}</div>`;
  };
  const body = prefs.tab === "diagnostics" ? diagPane() : prefs.tab === "about" ? aboutPane() : prefs.tab === "domains" ? domainsPane() : prefs.tab === "resources" ? `<div class="panes">${enginePane()}${resourcesPane()}${wslPane()}</div>` : prefs.tab === "storage" ? storagePane() : prefs.tab === "network" ? networkPane() : prefs.tab === "builds" ? buildsPane() : prefs.tab === "registries" ? `<div class="panes">${loginsOn() ? registriesPane() : ""}${regListPane("insecure")}${regListPane("mirrors")}</div>` : prefs.tab === "kubernetes" ? kubernetesPane() : prefs.tab === "import" ? importPane() : appearancePane();
  const html = `<div class="settings"><div class="tabs">${tab("appearance", "textaa", tr("Appearance"))}${tab("resources", "stack", tr("Resources"))}${tab("storage", "harddrive", tr("Storage"))}${tab("network", "globe", tr("Network"))}${tab("builds", "hammer", tr("Builds"))}${tab("registries", "lock", tr("Registries"))}${tab("kubernetes", "pods", "Kubernetes")}${tab("import", "stack", tr("Import"))}${tab("domains", "network", tr("Domains"))}${tab("diagnostics", "bug", tr("Diagnostics"))}${tab("about", "info", tr("About"))}</div>
    <div class="settings-body">${body}</div></div>`;
  // The container lists arrive every few seconds; rebuilding an unchanged page
  // closes an open menu. The font menus list names in the interface font: an
  // option in its own font made WebKit load every installed font (438 here)
  // the first time Appearance showed, freezing the window for about 3 s. The
  // preview below them shows the chosen fonts.
  if (html === settingsShown.html && settingsShown.el?.isConnected) return;
  const c = $("content"), sameTab = settingsShown.el?.isConnected && settingsShown.tab === prefs.tab;
  const tscroll = c.querySelector(".settings .tabs")?.scrollTop || 0;
  const bscroll = sameTab ? (c.querySelector(".settings-body")?.scrollTop || 0) : 0;
  const kept = signinKeep(c);
  c.innerHTML = html;
  signinPut(c, kept);
  if (tscroll) c.querySelector(".settings .tabs").scrollTop = tscroll;
  if (bscroll) c.querySelector(".settings-body").scrollTop = bscroll;
  settingsShown.html = html; settingsShown.el = c.firstElementChild; settingsShown.tab = prefs.tab;
  diagDrawn();
  for (const k of ["http", "https", "no_proxy"]) $(`px-${k}`)?.addEventListener("input", (ev) => { ui.pxDraft[k] = ev.target.value; });
  for (const k of ["insecure", "mirrors"]) {
    $(`reg-${k}`)?.addEventListener("input", (ev) => { ui.regAdd[k] = ev.target.value; });
    $(`reg-${k}`)?.addEventListener("keydown", (ev) => { if (ev.key === "Enter") { ev.preventDefault(); regListAdd(k); } });
  }
  for (const k of ["http", "https"]) $(`rp-${k}`)?.addEventListener("input", (ev) => {
    ui.rpDraft[k] = ev.target.value;
    const save = document.querySelector("#content [data-saverp]");
    if (save) save.disabled = !rpChanged();
  });
  $("reg-server")?.addEventListener("input", (ev) => { ui.reg.server = ev.target.value; regHintShow(); });
  document.querySelectorAll("#content [data-imp]").forEach((cb) => cb.addEventListener("change", (ev) => {
    pickChange(ev.target);
    const go = document.querySelector("#content [data-impgo]"), n = importCount();
    if (go) { go.disabled = !n; go.textContent = n ? trn(n, "Import {n} item", "Import {n} items") : tr("Import"); }
  }));
  for (const id of ["res-cpus", "res-mem", "res-disk", "res-swap"]) $(id)?.addEventListener("input", (ev) => {
    const v = +ev.target.value;
    ui.resDraft[{ "res-cpus": "cpus", "res-mem": "memory_mib", "res-disk": "disk_gb", "res-swap": "swap_mib" }[id]] = v;
    ev.target.style.setProperty("--fill", rangeFill(v, +ev.target.min, +ev.target.max));
    $(`${id}-v`).textContent = id === "res-cpus" ? cpuText(v) : id === "res-mem" ? gb(v) : id === "res-swap" ? swapText(v) : diskGb(v);
    $("res-save").disabled = !resChanged();
  });
  $("pref-font")?.addEventListener("change", (ev) => setPref("font", ev.target.value));
  $("pref-lang")?.addEventListener("change", (ev) => setPref("lang", ev.target.value));
  $("pref-lang-btn")?.addEventListener("click", (ev) => langPop(ev.currentTarget));
  $("pref-lang-btn")?.addEventListener("keydown", (ev) => { if ((ev.key === "ArrowDown" || ev.key === "ArrowUp") && !ev.metaKey && !ev.ctrlKey && !langPopState.close) { ev.preventDefault(); langPop(ev.currentTarget); } });
  // A list left open over a page that's gone (another view) closes; over the page drawn again, it stays.
  if (langPopState.close) $("pref-lang-btn")?.setAttribute("aria-expanded", "true");
  $("pref-mono")?.addEventListener("change", (ev) => setPref("mono", ev.target.value));
  $("bld-cache")?.addEventListener("input", (ev) => {
    const v = +ev.target.value;
    ui.bsetDraft = { ...(ui.bsetDraft || {}), cache_gb: v };
    ev.target.style.setProperty("--fill", rangeFill(v, +ev.target.min, +ev.target.max));
    $("bld-cache-v").textContent = diskGb(v);
  });
  $("bld-cache")?.addEventListener("change", (ev) => {
    const v = +ev.target.value;
    ui.bsetDraft = { ...(ui.bsetDraft || {}), cache_gb: v };
    if (ui.bset) ui.bset = { ...ui.bset, cache_gb: v };
    send("setbuildersettings", { value: { cache_gb: v, idle_secs: ui.bsetDraft?.idle_secs ?? ui.bset?.idle_secs ?? 300 } });
  });
  $("k8s-ver")?.addEventListener("change", (ev) => {
    const v = ev.target.value, c = k8s.config || {};
    if (v !== (c.version || "")) k8sDo("set", { lan: !!c.lan, tls_san: c.tls_san || [], version: v || "default" });
  });
}
function renderBuilds() {
  const b = ui.bl, c = $("content");
  if (b.items === null) {
    c.innerHTML = `<div class="empty"><div>${BL_ICON("hammer", "art")}<h3>${tr("Reading build history…")}</h3>${oomWait() || `<p>${tr("BuildKit starts if it's asleep.")}</p>`}</div></div>`;
    return;
  }
  if (!b.items.length) {
    if (b.error) { c.innerHTML = `<div class="empty"><div>${BL_ICON("hammer", "art")}<h3>${tr("Couldn't read the build history")}</h3><p>${esc(b.error)}</p></div></div>`; return; }
    return renderEmpty("builds");
  }
  if (!kept("builds").length) return renderEmpty("builds");
  const items = listed("builds");
  const scroll = c.querySelector(".bl-list")?.scrollTop || 0, dscroll = c.querySelector(".bl-detail")?.scrollTop || 0;
  c.innerHTML = `<div class="bl">
    <div class="bl-list" role="listbox" aria-label="${tr("Builds")}">${items.length ? items.map((x) => {
      const k = blKind(x.status);
      return `<button class="bl-item" role="option" data-bl="${esc(x.id)}" aria-selected="${b.sel?.id === x.id}">
        <span class="bl-st ${k}" title="${tr(blWord[k])}">${k === "run" ? '<i class="spin"></i>' : BL_ICON(k === "ok" ? "checkcircle" : k === "fail" ? "xcircle" : "minus")}</span>
        <span class="bl-txt"><b>${esc(x.name || x.id)}</b><small>${blDur(blSpan(x.started, x.completed))}${x.started ? ` · ${ago(Date.parse(x.started) / 1000)}` : ""}</small></span></button>`;
    }).join("") : `<p class="bl-none">${tr("No build matches.")}</p>`}</div>
    <div class="bl-detail">${buildDetail()}</div></div>`;
  c.querySelector(".bl-list").scrollTop = scroll;
  c.querySelector(".bl-detail").scrollTop = dscroll;
}

function buildDetail() {
  const b = ui.bl, s = b.sel, d = b.d;
  if (!s) return "";
  // A build stopped with Ctrl-C ends as an Error whose message says it was canceled.
  const k = d?.error && /\bcancel/i.test(d.error.message || "") ? "off" : blKind(d?.status || s.status);
  const head = `<div class="bl-head"><h2>${esc(s.name || s.id)}</h2><span class="bl-pill ${k}">${tr(blWord[k])}</span>
    <span class="bl-acts">${b.confirm === s.id ? `<span class="muted">${tr("Remove this build from the history?")}</span>${btn(tr("Cancel"), 'data-blrm="no"')}${btn(tr("Remove"), 'data-blrm="yes"', "danger")}` : btn(tr("Remove"), 'data-blrm="ask"')}</span></div>`;
  if (!d) return `${head}<div class="bl-loading muted">${tr("Loading the steps…")}</div>`;
  const warns = d.warnings || [];
  const meta = `<div class="bl-meta">
    <span title="${tr("Duration")}">${BL_ICON("clock")}${blDur(blSpan(d.started, d.completed)) || "—"}</span>
    ${d.started ? `<span title="${tr("Started")}">${BL_ICON("calendar")}${esc(new Date(d.started).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }))}</span>` : ""}
    <span title="${tr("Steps")}">${BL_ICON("steps")}${d.done ?? "?"}/${d.total ?? "?"}${d.cached ? ` (${tr("{n} cached", { n: d.cached })})` : ""}</span>
    ${warns.length ? `<span class="warn" title="${tr("Warnings")}">${BL_ICON("warning")}${warns.length}</span>` : ""}
  </div>
  <div class="bl-sub mono">${d.context ? `<span title="${tr("Build context")}">${esc(d.context)}</span>` : ""}<span title="${tr("Build record")}"><span class="sel"># ${esc(d.id)}</span>${copyBtn(d.id, tr("build ID"))}</span></div>`;
  const err = d.error?.message ? `<div class="bl-err${k === "off" ? " off" : ""}"><b>${BL_ICON("xcircle")}${esc(k === "off" ? tr("The build was canceled") : d.error.step || tr("The build failed"))}</b><p>${esc(d.error.message)}</p>${d.error.source ? `<pre>${esc(d.error.source.trim())}</pre>` : ""}</div>` : "";
  const warnList = warns.length ? `<div class="bl-warns">${warns.map((w) => `<div>${BL_ICON("warning")}<span>${esc(w.text)}${w.line ? ` <span class="muted">(${tr("line {n}", { n: w.line })})</span>` : ""}${w.detail ? `<small>${esc(w.detail)}</small>` : ""}</span>${/^https:\/\/docs\.docker\.com\//.test(w.url || "") ? `<button class="linkish" data-open-site="${esc(w.url)}">${tr("Docs")}</button>` : ""}</div>`).join("")}</div>` : "";
  let steps = (d.steps || []).filter((x) => b.internal || !blInternal(x.name));
  if (b.steps === "ran") steps = steps.filter((x) => !x.cached && x.started);
  if (b.steps === "cached") steps = steps.filter((x) => x.cached);
  if (b.steps === "failed") steps = steps.filter((x) => x.error);
  const max = Math.max(1, ...steps.filter((x) => !x.cached).map((x) => blSpan(x.started, x.completed) || 0));
  const openAll = steps.length > 0 && steps.every((x) => b.open.has(x.name));
  const bar = `<div class="bl-bar">
    <select data-blsteps aria-label="${tr("Which steps")}">${[["all", tr("All steps")], ["ran", tr("Ran")], ["cached", tr("Cached")], ["failed", tr("Failed")]].map(([v, l]) => `<option value="${v}"${b.steps === v ? " selected" : ""}>${l}</option>`).join("")}</select>
    <label class="bl-check"><input type="checkbox" data-blinternal${b.internal ? " checked" : ""}> ${tr("Internal steps")}</label>
    <button class="btn sm bl-all" data-blall>${BL_ICON(openAll ? "collapse" : "expand")}${openAll ? tr("Collapse all") : tr("Expand all")}</button></div>`;
  const rows = steps.map((x) => {
    const ms = blSpan(x.started, x.completed), open = b.open.has(x.name), has = x.log || x.error;
    const st = x.error ? "fail" : x.cached ? "cached" : !x.started ? "skip" : !x.completed ? "run" : "ok";
    const ic = st === "run" ? '<i class="spin"></i>' : BL_ICON(st === "ok" ? "checkcircle" : st === "fail" ? "xcircle" : st === "cached" ? "lightning" : "minus");
    const m = (x.name || "").match(/^(\[[^\]]*\])\s*(.*)$/s);
    // An image pinned by digest reads as alpine:latest@sha256:be2656061b53…; the step's tooltip has it all.
    const short = (t) => t.replace(/@sha256:([0-9a-f]{12})[0-9a-f]{52}/g, "@sha256:$1…");
    const right = st === "cached" ? `<span class="bl-time muted">${tr("cached")}</span>` : st === "skip" ? `<span class="bl-time muted">${tr("skipped")}</span>`
      : `<span class="bl-time"><span>${blDur(ms)}</span><span class="track"><i style="width:${Math.max(2, Math.round(((ms || 0) / max) * 100))}%"></i></span></span>`;
    return `<div class="bl-step ${st}${open ? " open" : ""}">
      <button class="bl-row" data-blstep="${esc(x.name)}"${has ? "" : " disabled"} aria-expanded="${open}"><span class="bl-st ${st}">${ic}</span>
        <span class="bl-name mono" title="${esc(x.name)}">${m ? `<span class="muted">${esc(m[1])}</span> ${esc(short(m[2]))}` : esc(short(x.name || ""))}</span>${right}</button>
      ${open && has ? `<pre class="console bl-log">${esc(((x.log || "") + (x.error ? `\n${x.error}` : "")).trim())}</pre>` : ""}</div>`;
  }).join("");
  const tab = ["layers", "security"].includes(b.tab) ? b.tab : "steps";
  const tabs = `<div class="bl-tabs" role="tablist">
    <button role="tab" data-bltab="steps" aria-selected="${tab === "steps"}">${tr("Steps")}</button>
    <button role="tab" data-bltab="layers" aria-selected="${tab === "layers"}">${tr("Layers")}</button>
    <button role="tab" data-bltab="security" aria-selected="${tab === "security"}">${tr("Security")}</button>
  </div>`;
  const pane = tab === "security" ? blSecurity() : tab === "layers" ? blLayers()
    : `${bar}<div class="bl-steps">${rows || `<p class="bl-none">${tr("No steps here.")}</p>`}</div>`;
  return `${head}${meta}${err}${warnList}${tabs}${pane}`;
}

// Layers: the image the build made, per platform, read from the manifest and
// config BuildKit keeps with the build. Biggest first is one click away.
function blLayers() {
  const L = ui.bl.layers;
  if (L && !L.error && !L.images?.length) return `<p class="bl-none">${tr("This build made no image: it failed before exporting, or its output was the cache only.")}</p>`;
  return layersView(L, ui.bl.plat, { own: tr("Added by this build"), base: tr("From the base image") });
}

// An image's layers, newest work first, then what came from its base; used by a
// build's Layers tab and by an image's own page.
function layersView(L, plat, words) {
  if (!L) return `<div class="bl-loading muted">${tr("Reading the image…")}</div>`;
  if (L.error) return `<p class="bl-none">${esc(L.error)}</p>`;
  const im = L.images.find((i) => i.platform === plat) || L.images[0];
  const real = im.layers.filter((l) => !l.empty), base = real.filter((l) => l.base), own = real.filter((l) => !l.base);
  const sum = (a) => a.reduce((t, l) => t + (l.size || 0), 0);
  const big = Math.max(...real.map((l) => l.size || 0), 1);
  const plats = L.images.length > 1 ? `<span class="bl-plats">${L.images.map((i) => `<button data-blplat="${esc(i.platform)}" aria-pressed="${i === im}">${esc(i.platform)}</button>`).join("")}</span>` : `<span class="muted">${esc(im.platform)}</span>`;
  const mat = (L.materials || []).map((m) => (m.URI || "").match(/^pkg:docker\/([^?]+)/)?.[1]).filter(Boolean);
  const row = (l, i) => {
    const pct = Math.round(((l.size || 0) / big) * 100);
    return `<div class="bl-layer${l.empty ? " cfgline" : ""}${l.base ? " base" : ""}" title="${esc(l.digest || tr("no layer: this line only changes the image's settings"))}">
      <span class="bl-ln muted">${i + 1}</span><span class="bl-by mono">${esc(l.by || tr("(no description)"))}</span>
      ${l.empty ? `<span class="bl-lsz muted">${tr("settings")}</span>` : `<span class="bl-lsz"><span>${size(l.size)}</span><span class="track"><i style="width:${Math.max(2, pct)}%"></i></span></span>`}</div>`;
  };
  const group = (title, note, rows) => rows.length ? `<div class="bl-lgroup"><div class="bl-lhead"><b>${title}</b><span class="muted">${note}</span></div>${rows.join("")}</div>` : "";
  const lines = im.layers.map((l, i) => ({ l, i }));
  const c = im.config || {};
  const run = [...(c.entrypoint || []), ...(c.cmd || [])];
  const kv = (k, v) => v ? `<div><span class="muted">${k}</span><span class="mono">${v}</span></div>` : "";
  const env = (c.env || []).filter((e) => !/^PATH=/.test(e));
  const labels = Object.entries(c.labels || {});
  return `<div class="bl-lsum">
      <span>${rlm()}<b>${size(im.size)}</b> <span class="muted">${tr("compressed")}</span></span>
      <span>${rlm()}<b>${real.length}</b> <span class="muted">${tr("layers")}</span></span>
      <span>${rlm()}<b>${size(sum(own))}</b> <span class="muted">${words.own.toLowerCase()}</span></span>
      ${mat.length ? `<span class="muted" title="${tr("Base image")}">FROM <span class="mono">${esc(mat.join(", "))}</span></span>` : ""}
      <span class="bl-lplat">${plats}</span>
    </div>
    ${group(words.own, `${trn(own.length, "{n} layer", "{n} layers")} · ${size(sum(own))}`, lines.filter(({ l }) => !l.base).map(({ l, i }) => row(l, i)))}
    ${group(words.base, `${trn(base.length, "{n} layer", "{n} layers")} · ${size(sum(base))}`, lines.filter(({ l }) => l.base).map(({ l, i }) => row(l, i)))}
    <div class="bl-lgroup bl-cfg"><div class="bl-lhead"><b>${tr("How it runs")}</b><span class="muted">${tr("the image's settings")}</span></div>
      ${kv(tr("Runs"), esc(run.join(" ")))}${kv(tr("Working dir"), esc(c.workdir || ""))}${kv(tr("User"), esc(c.user || "root"))}
      ${kv(tr("Ports"), esc((c.ports || []).join(", ")))}${kv(tr("Volumes"), esc((c.volumes || []).join(", ")))}
      ${kv(tr("Health check"), esc((c.healthcheck || []).join(" ")))}${kv(tr("Stop signal"), esc(c.stopsignal || ""))}
      ${kv(tr("Environment"), env.map(esc).join("<br>"))}${kv(tr("Labels"), labels.map(([k, v]) => `${esc(k)}=${esc(v)}`).join("<br>"))}
    </div>`;
}

// Security: the image a build made, scanned with Grype once it's in Kiri.
function blSecurity() {
  const L = ui.bl.layers;
  if (!L) return `<div class="bl-loading muted">${tr("Reading the image…")}</div>`;
  if (L.error) return `<p class="bl-none">${esc(L.error)}</p>`;
  if (!L.images?.length) return `<p class="bl-none">${tr("This build made no image to scan: it failed before exporting, or its output was the cache only.")}</p>`;
  const im = L.images.find((i) => i.platform === ui.bl.plat) || L.images[0];
  const img = ui.images.find((i) => i.Id === im.config_digest);
  if (!img) return `<p class="bl-none">${tr("This build's image isn't in Kiri, so there's nothing here to scan. It was pushed or exported elsewhere, or removed since. Build it with <code>--load</code> to scan it here.")}</p>`;
  return scanView(img, { own: tr("this build") });
}

/* Scanning: Grype, run on the Mac against Kiri's store. One image's scan,
   keyed by its ID; the same view for a build and for an image's page. */
const SEVS = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];
const sevKey = (s) => (SEVS.includes(s) ? s : "Unknown").toLowerCase();
const SCAN_PHASE = { scanner: "Downloading Grype, the scanner (about 30 MB, once)", database: "Updating the vulnerability database (about 200 MB the first time)", scanning: "Scanning the image's packages" };
/* i18n */ void [tr("Critical"), tr("High"), tr("Medium"), tr("Low"), tr("Negligible"), tr("Unknown"), tr("Downloading Grype, the scanner (about 30 MB, once)"), tr("Updating the vulnerability database (about 200 MB the first time)"), tr("Scanning the image's packages"), tr("Completed"), tr("Failed"), tr("Building"), tr("Canceled")];
// Grype's mascot, for the "Powered by" line (from Anchore's Grype README).
const GRYPE_MARK = "data:image/png;base64,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";
const poweredBy = () => `<button class="sc-by" data-open-grype title="${tr("Grype, the open-source scanner from Anchore")}">${tr("Powered by")} <img src="${GRYPE_MARK}" alt=""><b>Grype</b><span class="muted">· Anchore</span></button>`;
const sevCounts = (c) => SEVS.filter((x) => c[x]).map((x) => `<span class="sc-sev ${sevKey(x)}">${c[x]} ${tr(x)}</span>`).join("") || `<span class="muted">${tr("None found")}</span>`;
const when = (t) => new Date(t * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

// An image's scans: the history first, one scan open over it with a close.
function scanView(img, words) {
  const id = img.Id;
  let st = ui.scans.get(id);
  if (!st) { st = { history: null }; ui.scans.set(id, st); send("scanhistory", { name: id }); }
  const label = img.RepoTags?.[0] || short(id);
  const err = st.error ? `<p class="sc-err">${esc(st.error)}</p>` : "";
  if (st.running) {
    const pct = st.phase === "scanner" ? st.pct : null;
    return `<div class="sc-run"><div class="sc-runline"><span class="sc-spin" aria-hidden="true"></span><b>${SCAN_PHASE[st.phase] ? tr(SCAN_PHASE[st.phase]) : tr("Starting the scan")}</b><span class="spacer"></span>${poweredBy()}</div>
      ${pct != null ? `<div class="pprog"><div class="pbar"><span style="width:${pct}%"></span></div><span class="num">${pct}%</span></div>` : `<div class="stripe"></div>`}
      <p class="muted">${tr("Kiri runs Grype here on your Mac against the image in Kiri's store. The image isn't uploaded anywhere.")}</p></div>`;
  }
  if (st.open != null) {
    if (st.result?.scanned !== st.open) return `<div class="bl-loading muted">${tr("Opening the scan…")}</div>`;
    return scanResult(img, st.result, words, err);
  }
  if (!st.history) return st.histErr ? `<p class="sc-err">${esc(st.histErr)}</p>` : `<div class="bl-loading muted">${tr("Reading the scans…")}</div>`;
  if (!st.history.length) return `<form class="sc-intro" data-scanform="${esc(id)}">
      <div class="sc-introtop">${BL_ICON("shieldcheck")}<b>${tr("Scan {image} for known vulnerabilities", { image: esc(label) })}</b></div>
      <p class="muted">${tr("Kiri finds every package in the image (OS packages, language libraries and binaries) and checks each against a vulnerability database. No scans yet: run the first one.")}</p>
      ${scannerOptions(scannerFresh(id))}
      ${err}<div class="sc-go"><button type="submit" class="btn primary">${tr("Start scan")}</button></div></form>`;
  const rows = st.history.map((h, n) => `<tr class="sc-hrow" data-scanat="${h.scanned}" data-scanimg="${esc(id)}">
      <td><b>${when(h.scanned)}</b><div class="muted">${ago(h.scanned)}${n === 0 ? ` · ${tr("latest")}` : ""}</div></td>
      <td><div class="sc-counts">${sevCounts(h.counts || {})}</div></td>
      <td class="r num">${h.vulns}</td><td class="r num">${h.fixable}</td><td class="r num">${h.packages}</td>
      <td class="muted">${h.db ? new Date(h.db).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : ""}</td>
    </tr>`).join("");
  return `<div class="sc">
    <div class="sc-head"><b>${tr("Scans")}</b><span class="muted">${tr("{n} of this image, newest first", { n: st.history.length })}</span><span class="spacer"></span>${poweredBy()}${btn(tr("Scan image"), `data-scan="${esc(id)}"`, "primary")}</div>
    ${err}
    <div class="sc-table"><table>
      <thead><tr><th>${tr("Scanned")}</th><th>${tr("Found")}</th><th class="r">${tr("Vulnerabilities")}</th><th class="r">${tr("With a fix")}</th><th class="r">${tr("Packages")}</th><th>${tr("Database")}</th></tr></thead>
      <tbody>${rows}</tbody></table></div>
  </div>`;
}

// The scanners to pick from, in the first-scan card and the Scan image dialog.
const scannerOptions = (fresh) => `<fieldset class="sc-opts"><legend class="muted">${tr("Scan with")}</legend>
    <label class="sc-opt"><input type="radio" name="scanner" value="grype" checked>
      <img src="${GRYPE_MARK}" alt="">
      <span>${rlm()}<b>Grype</b> <span class="muted">· ${tr("Anchore, open source")}</span><br>
      <span class="muted">${tr("Runs here on your Mac against Kiri's copy of the image; nothing is uploaded.")}${fresh ? ` ${tr("The first scan downloads Grype and its database, about 230 MB (3 GB unpacked).")}` : ""}</span></span></label>
  </fieldset>`;
const scannerFresh = (id) => !ui.scans.get(id)?.history?.length && ![...ui.scans.values()].some((x) => x.history?.length);

// Scan image: pick the scanner first. Grype is the one there is, and it runs here.
function startScan(id) {
  const x = ui.scans.get(id) || {};
  ui.scans.set(id, { ...x, running: true, phase: "", error: null });
  send("scan", { name: id });
  rerenderScan();
}
function chooseScanner(id) {
  const img = ui.images.find((i) => i.Id === id);
  const label = img?.RepoTags?.[0] || short(id);
  const fresh = scannerFresh(id);
  const scrim = document.createElement("div");
  scrim.className = "scrim";
  scrim.innerHTML = `<form class="dialog sc-pick" role="dialog" aria-modal="true" aria-labelledby="sc-pick-title">
      <h3 id="sc-pick-title">${tr("Scan {image}", { image: esc(label) })}</h3>
      ${scannerOptions(fresh)}
      <div class="row-end"><span></span><span><button type="button" class="btn" data-close>${tr("Cancel")}</button> <button type="submit" class="btn primary">${tr("Start scan")}</button></span></div>
    </form>`;
  document.body.append(scrim);
  const close = () => { scrim.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (ev) => { if (ev.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  scrim.addEventListener("click", (ev) => { if (ev.target === scrim || ev.target.closest("[data-close]")) close(); });
  scrim.querySelector("form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    if (new FormData(ev.target).get("scanner") === "grype") { close(); startScan(id); }
  });
  scrim.querySelector("[type=submit]").focus();
}

// One scan's findings, with a close back to the history.
function scanResult(img, r, words, err) {
  const id = img.Id, label = img.RepoTags?.[0] || short(id);
  const f = ui.scanf;
  const counts = Object.fromEntries(SEVS.map((x) => [x, 0]));
  for (const v of r.vulns) counts[SEVS.includes(v.severity) ? v.severity : "Unknown"]++;
  const fixable = r.vulns.filter((v) => v.fixed?.length).length;
  const own = r.vulns.filter((v) => v.base === false).length;
  const shown = r.vulns.filter((v) => (!f.sev || v.severity === f.sev) && (!f.fix || v.fixed?.length) && (!f.own || v.base === false));
  const chips = SEVS.filter((x) => counts[x] || x === "Critical" || x === "High").map((x) =>
    `<button class="sc-chip ${sevKey(x)}" data-scansev="${x}" aria-pressed="${f.sev === x}"><b>${counts[x]}</b> ${tr(x)}</button>`).join("");
  const db = r.db ? new Date(r.db).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "";
  const rows = shown.map((v) => `<tr>
      <td><span class="sc-sev ${sevKey(v.severity)}">${esc(tr(v.severity))}</span></td>
      <td class="mono">${v.url ? `<button class="sc-link" data-advisory="${esc(v.url)}" title="${esc(v.url)}">${esc(v.id)}</button>` : esc(v.id)}</td>
      <td><span class="mono">${esc(v.package)}</span> <span class="muted mono">${esc(v.version)}</span><div class="muted sc-kind">${esc(v.kind || "")}</div></td>
      <td class="mono">${v.fixed?.length ? esc(v.fixed.join(", ")) : `<span class="muted">${tr("No fix yet")}</span>`}</td>
      <td class="sc-where" title="${esc(v.by || "")}">${v.base == null ? `<span class="muted">—</span>` : v.base ? `<span class="muted">${tr("Base image")}</span>` : `<span>${esc(words.own[0].toUpperCase() + words.own.slice(1))}</span>`}${v.by ? `<div class="muted mono">${esc(v.by)}</div>` : ""}</td>
    </tr>`).join("");
  return `<div class="sc">
    <div class="sc-head">
      <b>${tr("Scan of {when}", { when: when(r.scanned) })}</b>
      <span class="spacer"></span>
      ${btn(tr("Save SBOM"), `data-sbom="${esc(id)}" data-sbomat="${r.scanned}" data-sbomname="${esc(label)}" title="${tr("The {n} packages as CycloneDX JSON, saved to Downloads", { n: r.packages })}"`)}
      ${btn(tr("Scan again"), `data-scan="${esc(id)}"`)}
      <button class="sc-close" data-scanclose="${esc(id)}" title="${tr("Close this scan")}" aria-label="${tr("Close this scan")}">×</button>
    </div>
    <div class="sc-chips">${chips}</div>
    <div class="sc-meta muted">${r.vulns.length ? `${trn(r.vulns.length, "{n} vulnerability in {packages} packages", "{n} vulnerabilities in {packages} packages", { packages: r.packages })} · ${tr("{n} with a fix", { n: fixable })} · ${tr("{n} from {what}", { n: own, what: esc(words.own) })}` : tr("No known vulnerabilities in {n} packages", { n: r.packages })} · ${ago(r.scanned)}${db ? ` · ${tr("database from {date}", { date: db })}` : ""} · Grype ${esc(r.grype)}</div>
    ${err}
    ${r.vulns.length ? `<div class="sc-filters">
      <label><input type="checkbox" data-scanfix ${f.fix ? "checked" : ""}> ${tr("Has a fix")}</label>
      <label><input type="checkbox" data-scanown ${f.own ? "checked" : ""}> ${tr("Only from {what}", { what: esc(words.own) })}</label>
      ${f.sev || f.fix || f.own ? `<span class="muted">${tr("{n} shown", { n: shown.length })}</span><button class="sc-link" data-scanclear>${tr("Clear")}</button>` : ""}
    </div>
    <div class="sc-table"><table>
      <thead><tr><th>${tr("Severity")}</th><th>${tr("Vulnerability")}</th><th>${tr("Package")}</th><th>${tr("Fixed in")}</th><th>${tr("Layer")}</th></tr></thead>
      <tbody>${rows || `<tr><td colspan="5" class="muted">${tr("None match these filters.")}</td></tr>`}</tbody>
    </table></div>` : ""}
  </div>`;
}
function rerenderScan() {
  if (ui.view === "builds") renderBuilds();
  else if (ui.view === "images" && ui.imgd) render();
}

// The first-scan card's own Start scan.
document.addEventListener("submit", (ev) => {
  const f = ev.target.closest("[data-scanform]");
  if (!f) return;
  ev.preventDefault();
  if (new FormData(f).get("scanner") === "grype") startScan(f.dataset.scanform);
});

document.addEventListener("click", (ev) => {
  const t = (q) => ev.target.closest(q), b = ui.bl;
  let el;
  if ((el = t("[data-bl]"))) { const x = b.items.find((i) => i.id === el.dataset.bl); if (x && x.id !== b.sel?.id) { pickBuild(x); renderBuilds(); } }
  else if ((el = t("[data-bltab]"))) {
    b.tab = el.dataset.bltab;
    if ((b.tab === "layers" || b.tab === "security") && b.sel && b.layers?.id !== b.sel.id) send("buildlayers", { name: b.sel.builder, id: b.sel.id });
    renderBuilds();
  }
  else if ((el = t("[data-blplat]"))) { b.plat = el.dataset.blplat; renderBuilds(); }
  else if ((el = t("[data-blstep]"))) { const n = el.dataset.blstep; b.open.has(n) ? b.open.delete(n) : b.open.add(n); renderBuilds(); }
  else if (t("[data-blall]")) {
    const steps = (b.d?.steps || []).filter((x) => (b.internal || !blInternal(x.name)) && (x.log || x.error));
    const all = steps.every((x) => b.open.has(x.name));
    b.open = all ? new Set() : new Set(steps.map((x) => x.name)); renderBuilds();
  }
  else if ((el = t("[data-blrm]"))) {
    const a = el.dataset.blrm;
    if (a === "ask") b.confirm = b.sel?.id;
    else if (a === "no") b.confirm = null;
    else if (b.sel) { send("rmbuild", { name: b.sel.builder, id: b.sel.id }); b.items = b.items.filter((x) => x.id !== b.sel.id); b.sel = null; b.d = null; b.confirm = null; if (b.items[0]) pickBuild(b.items[0]); }
    render();
  }
});
document.addEventListener("change", (ev) => {
  if (ev.target.matches("[data-blsteps]")) { ui.bl.steps = ev.target.value; renderBuilds(); }
  else if (ev.target.matches("[data-blinternal]")) { ui.bl.internal = ev.target.checked; renderBuilds(); }
});
// Back to the window (it doesn't tick while hidden): ask at once rather than at the next 15 s.
document.addEventListener("visibilitychange", () => { if (!document.hidden && ui.view === "builds" && ui.vm !== "stopped") send("builds"); });
const DG_PART = { ui: "Window", daemon: "Engine", cli: "CLI" };
const DG_WHO = { ui: "The window", daemon: "The engine", cli: "A kiri command" };
/* i18n */ void [tr("Window"), tr("Engine"), tr("CLI"), tr("The window"), tr("The engine"), tr("A kiri command")];
const dgIcon = (name) => `<svg viewBox="0 0 256 256" aria-hidden="true"><path d="${PH[name]}"/></svg>`;
// Today 14:02, Yesterday 22:14, 26 Oct 09:41: when a crash or an error was.
const dgDate = (iso) => new Date(String(iso).replace(/(\.\d{3})\d+/, "$1"));
function dgWhen(iso, sentence) {
  const d = dgDate(iso), day = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const hm = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  const days = Math.round((day(new Date()) - day(d)) / 86400000);
  if (days === 0) return sentence ? tr("today at {time}", { time: hm }) : tr("Today {time}", { time: hm });
  if (days === 1) return sentence ? tr("yesterday at {time}", { time: hm }) : tr("Yesterday {time}", { time: hm });
  const date = d.toLocaleDateString([], { day: "numeric", month: "short" });
  return sentence ? tr("on {date} at {time}", { date, time: hm }) : `${date} ${hm}`;
}
const dgTime = (iso) => { const d = dgDate(iso); return isNaN(d) ? iso : `${d.toLocaleTimeString([], { hour12: false })}.${String(d.getMilliseconds()).padStart(3, "0")}`; };
// The search, marked in a piece of a line.
function dgMark(text) {
  if (!dg.find) return esc(text);
  const lower = text.toLowerCase(), q = dg.find.toLowerCase();
  let out = "", at = 0, i;
  while ((i = lower.indexOf(q, at)) >= 0) { out += `${esc(text.slice(at, i))}<mark>${esc(text.slice(i, i + q.length))}</mark>`; at = i + q.length; }
  return out + esc(text.slice(at));
}
const dgFields = (l) => Object.entries(l.fields || {}).map(([k, v]) => ` ${k}=${typeof v === "string" ? (/\s/.test(v) || !v ? JSON.stringify(v) : v) : JSON.stringify(v)}`);
const dgText = (l) => `${l.msg || ""}${dgFields(l).join("")}`;
function dgRow(l, key = "") {
  const lv = ["error", "warn", "info", "debug"].includes(l.level) ? l.level : "info";
  return `<div class="dg-row ${lv}${lv === "error" ? " hit" : ""}"${key ? ` data-key="${esc(key)}"` : ""}><span class="t">${esc(dgTime(l.time))}</span><span class="lv">${lv.toUpperCase()}</span><span class="p">${(DG_PART[l.part] && tr(DG_PART[l.part])) || esc(l.part || "")}</span><span class="m">${dgMark(l.msg || "")}${dgFields(l).map((f) => `<span class="k">${dgMark(f)}</span>`).join("")}</span></div>`;
}
// A line as text, for Copy: local time, level, part, message and fields.
const dgPlain = (l) => `${dgTime(l.time)} ${(l.level || "").toUpperCase().padEnd(5)} ${(DG_PART[l.part] || l.part || "").padEnd(6)} ${dgText(l)}`;

/* Warn means warnings and errors, Info everything but debug: each level and worse. */
function dgVisible() {
  return (dg.lines || []).filter((l) => (dg.level !== "error" || l.level === "error") && (dg.level !== "info" || l.level !== "debug")
    && (!dg.find || dgText(l).toLowerCase().includes(dg.find.toLowerCase())));
}
function dgFetch() {
  send("diaglogs", { name: dg.part, id: dg.op, value: { errors: dg.level === "warn" || dg.level === "error", n: 500 } });
}
// Settings → Diagnostics opened: its crashes and log, then the log again every 2 s while it follows.
function diagOpen() { dg.lines = null; dg.shown = ""; send("diagcrashes"); dgFetch(); }
setInterval(() => { if (ui.view === "settings" && prefs.tab === "diagnostics" && dg.follow && !document.hidden) dgFetch(); }, 2000);

function drawDiagLog() {
  const el = $("dg-log");
  if (!el) return;
  const rows = dgVisible();
  const key = `${rows.length}|${rows.at(-1)?.time}|${rows[0]?.time}|${dg.find}`;
  $("dg-count").textContent = dg.lines ? trn(rows.length, "{n} line", "{n} lines") : "";
  if (key === dg.shown && el.childElementCount) return;
  const sel = getSelection();
  if (dg.shown && sel && !sel.isCollapsed && (el.contains(sel.anchorNode) || el.contains(sel.focusNode))) return;
  dg.shown = key;
  const top = el.scrollTop, seen = new Map();
  const html = !dg.lines ? `<div class="dg-empty">${tr("Reading the log…")}</div>` : rows.length ? rows.map((l) => {
    const base = `${l.time}|${l.level}|${l.part}|${l.msg || ""}`, n = (seen.get(base) || 0) + 1;
    seen.set(base, n);
    return dgRow(l, `${base}#${n}`);
  }).join("") : `<div class="dg-empty">${dg.find || dg.level || dg.part || dg.op ? tr("No lines match.") : tr("Nothing logged yet.")}</div>`;
  morph(el, html);
  el.scrollTop = dg.follow ? el.scrollHeight : top;
}

function diagPane() {
  const levels = [["", tr("All levels")], ["error", tr("Errors")], ["warn", tr("Warnings and errors")], ["info", tr("Info and up")]];
  const crash = (c) => {
    const busy = dg.sending.has(c.name) || c.sending, open = dg.open.has(c.name);
    return `<div class="dg-crash" data-crashrow="${esc(c.name)}" aria-expanded="${open}">
      <button class="car" aria-label="${open ? tr("Hide the crash report") : tr("Show the crash report")}">${dgIcon("caret")}</button>
      <span class="when">${esc(dgWhen(c.time))}</span><span><span class="dg-part">${(DG_PART[c.part] && tr(DG_PART[c.part])) || esc(c.part)}</span></span>
      <span class="first" title="${esc(c.location ? `${c.message}\n${c.location}` : c.message || "")}">${esc(c.message || tr("(no message)"))}</span>
      <span class="st">${c.sent ? `<span class="pill sent">${tr("Sent")}</span>${c.id ? `<span class="mono">${esc(c.id)}</span>${copyBtn(c.id, tr("report ID"))}` : ""}`
        : busy ? `<span class="pill">${tr("Sending…")}</span>` : `<span class="pill">${tr("Not sent")}</span>${btn(tr("Send"), `data-crashsend="${esc(c.name)}"`)}`}</span>
    </div>${open ? `<pre class="dg-stack">${esc(c.text || "")}</pre>` : ""}`;
  };
  const crashes = dg.crashes == null ? `<div class="none">${tr("Looking for crash reports…")}</div>` : dg.crashes.length ? dg.crashes.map(crash).join("") : `<div class="none">${tr("No crashes. Kiri keeps a report here if one of its parts ever stops unexpectedly.")}</div>`;
  return `<div class="pane diag"><h3>${tr("Diagnostics")}</h3>
    <div class="pref"><span class="t">${tr("Send crash reports automatically")}</span>
      <span class="d">${tr("When part of Kiri crashes, the stack trace and the last 200 log lines before it go to Kiri Cloud, with Kiri's and the system's versions, the computer's model and a random ID for this install. Never your Kiri Cloud account, and nothing from inside your containers. Your home folder, image and container names, tokens and passwords are taken out.")}</span>
      <div class="seg" role="group" aria-label="${tr("Send crash reports automatically")}"><button data-dgauto="0" aria-pressed="${prefs.crashReports !== true}">${tr("Off")}</button><button data-dgauto="1" aria-pressed="${prefs.crashReports === true}">${tr("On")}</button></div></div>
    <div class="pref"><span class="t">${tr("Diagnostics report")}</span>
      <span class="d">${tr("Recent logs, crash reports and versions in one redacted file, for when something goes wrong.")}</span>
      <div class="dg-acts"><button class="btn sm" data-dgreport="save">${tr("Create report…")}</button><button class="btn sm" data-dgreport="send">${dgIcon("send")}${tr("Send to Kiri")}</button></div>
      ${dg.sent ? `<div class="dg-result">${dgIcon("checkcircle")}<span>${tr("Sent. Quote {id} if you write to us.", { id: `<span class="mono">${esc(dg.sent)}</span>` })}</span>${copyBtn(dg.sent, tr("report ID"))}</div>` : ""}</div>
    <h4 class="ksub">${tr("Recent crashes")}</h4>
    <div class="dg-crashes">${crashes}</div>
    <h4 class="ksub">${tr("Logs")}</h4>
    <div class="dg-logs">
      <div class="logbar">
        <div class="seg" role="group" aria-label="${tr("Part")}">${[["", tr("All")], ["ui", tr("Window")], ["daemon", tr("Engine")], ["cli", tr("CLI")]].map(([v, l]) => `<button data-dgpart="${v}" aria-pressed="${dg.part === v}">${l}</button>`).join("")}</div>
        <select id="dg-level" aria-label="${tr("Level")}">${levels.map(([v, l]) => `<option value="${v}"${dg.level === v ? " selected" : ""}>${l}</option>`).join("")}</select>
        <input class="field" id="dg-find" placeholder="${tr("Find in logs")}" spellcheck="false" autocomplete="off">
        ${dg.op ? `<span class="dg-chip">${tr("Action {op}", { op: `<span class="mono">${esc(dg.op)}</span>` })}<button data-dgop aria-label="${tr("Show all actions")}">${UPD_ICON.x}</button></span>` : ""}
        <span style="flex:1"></span>
        <label class="toggle"><input type="checkbox" id="dg-follow"${dg.follow ? " checked" : ""}> ${tr("Follow")}</label>
      </div>
      <div class="dg-log" id="dg-log" role="log" aria-label="${tr("Kiri's log")}"></div>
      <div class="dg-logfoot"><span class="dg-live${dg.follow ? "" : " off"}"><i></i>${dg.follow ? tr("Live|stream") : tr("Paused")}</span><span>·</span><span class="num" id="dg-count"></span>
        <span>${tr("· the newest 500 · up to 15 MB a part is kept")}</span>
        <span style="flex:1"></span><button class="btn sm" data-dgfolder>${dgIcon("folder")}${tr("Open logs folder")}</button></div>
    </div>
  </div>`;
}
// After the pane is drawn: the search keeps its text and focus across redraws.
function diagDrawn() {
  const f = $("dg-find");
  if (!f || f.dataset.bound) return;
  f.dataset.bound = "1"; f.value = dg.find;
  f.addEventListener("input", () => { dg.find = f.value; drawDiagLog(); });
  $("dg-level").addEventListener("change", (ev) => { dg.level = ev.target.value; dg.lines = null; drawDiagLog(); dgFetch(); });
  $("dg-follow").addEventListener("change", (ev) => { dg.follow = ev.target.checked; render(); if (dg.follow) dgFetch(); });
  dg.shown = ""; drawDiagLog();
}
function diagClick(t) {
  let el;
  if ((el = t("[data-dgpart]"))) { dg.part = el.dataset.dgpart; dg.lines = null; render(); dgFetch(); }
  else if ((el = t("[data-dgauto]"))) setPref("crashReports", el.dataset.dgauto === "1");
  else if ((el = t("[data-crashsend]"))) { dg.sending.add(el.dataset.crashsend); send("diagsendcrash", { name: el.dataset.crashsend }); render(); }
  else if (t("[data-dgop]")) { dg.op = ""; dg.lines = null; render(); dgFetch(); }
  else if ((el = t("[data-dgreport]"))) reportDialog(el.dataset.dgreport);
  else if (t("[data-dgfolder]")) send("diagfolder");
  else if ((el = t("[data-crashrow]")) && !t(".st button, .copy")) { const n = el.dataset.crashrow; dg.open.has(n) ? dg.open.delete(n) : dg.open.add(n); render(); }
  else return false;
  return true;
}
// Opens Settings → Diagnostics, on one action's lines or with a crash open.
function showDiag(op, crash) {
  prefs.tab = "diagnostics";
  if (op) { dg.op = op; dg.follow = false; dg.find = ""; dg.level = ""; dg.part = ""; }
  if (crash) dg.open.add(crash);
  show("settings");
  requestAnimationFrame(() => (op ? $("dg-log") : document.querySelector(".dg-crashes"))?.scrollIntoView({ block: "nearest" }));
}

/* Create report… (saved to the Desktop, shown in Finder) and Send to Kiri:
   what goes in first, the container list only when ticked. */
function reportDialog(mode) {
  rp = { mode, state: "", containers: false, id: "", error: "", close: () => close() };
  const scrim = document.createElement("div");
  scrim.className = "scrim"; scrim.id = "rp";
  document.body.append(scrim);
  drawReport();
  const close = () => { scrim.remove(); rp = null; document.removeEventListener("keydown", onKey); };
  const onKey = (ev) => { if (ev.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  scrim.addEventListener("change", (ev) => { if (ev.target.dataset.rpopt != null) rp.containers = ev.target.checked; });
  scrim.addEventListener("click", (ev) => {
    if (ev.target === scrim || ev.target.closest("[data-close]")) return close();
    if (ev.target.closest("[data-rpcopy]")) { send("copy", { name: rp.id }); copiedBtn(ev.target.closest("button")); }
    if (ev.target.closest("[data-rpgo]")) { rp.state = "busy"; rp.error = ""; send(rp.mode === "send" ? "diagsend" : "diagreport", { value: { containers: rp.containers } }); drawReport(); }
  });
  scrim.querySelector("[data-rpgo]")?.focus();
}
function drawReport() {
  const scrim = $("rp");
  if (!scrim || !rp) return;
  const send_ = rp.mode === "send", done = rp.state === "sent";
  const item = (t, d) => `<div class="rp-item">${dgIcon("check")}<span class="t">${t}</span><span class="d">${d}</span></div>`;
  scrim.innerHTML = `<div class="dialog rp-dialog" role="dialog" aria-modal="true" aria-labelledby="rp-t">
    <h3 id="rp-t">${send_ ? tr("Send a report to Kiri") : tr("Create a diagnostics report")}</h3>
    <p>${send_ ? tr("We get the file below, redacted, and you get an ID to quote when you write to us. If you're signed in to Kiri Cloud, it says it's from you, so we can reply.") : WIN || LINUX ? tr("One text file, redacted, saved to your Desktop. Read it before you share it.") : tr("One text file, redacted, saved to your Desktop and shown in Finder. Read it before you share it.")}</p>
    <div class="rp-list">${item(tr("Kiri's logs"), tr("The last 300 lines from the window, the engine and kiri commands, and the engine's own output"))}
      ${item(tr("Crash reports"), WIN || LINUX ? tr("The 5 newest crash reports for Kiri") : tr("The 5 newest, and macOS's own crash reports for Kiri from the last 30 days"))}
      ${item(WIN ? tr("Kiri and this PC") : LINUX ? tr("Kiri and this computer") : tr("Kiri and this Mac"), WIN || LINUX ? tr("Versions, {os}, whether the engine runs, how many containers and images", { os: OS }) : tr("Versions, macOS, whether the engine runs, how many containers and images"))}
      <label class="rp-item opt"><input type="checkbox" data-rpopt${rp.containers ? " checked" : ""}${rp.state ? " disabled" : ""}><span class="t">${tr("Container list")}</span><span class="d">${tr("Names, images and status. Not their files, logs or environment.")}</span></label></div>
    <div class="rp-red">${dgIcon("shieldcheck")}<span>${tr("Your home folder's path, tokens, passwords and other secrets are blanked before anything is written.")}</span></div>
    ${done ? `<div class="rp-id"><span class="lab">${tr("Report ID")}</span><span class="val">${esc(rp.id)}</span><button class="btn sm" data-rpcopy>${dgIcon("copy")}${tr("Copy")}</button></div>` : ""}
    ${rp.error ? `<p class="err">${send_ ? tr("Couldn't send it: {error}", { error: esc(rp.error) }) : tr("Couldn't save it: {error}", { error: esc(rp.error) })}</p>` : ""}
    <div class="row-end"><span></span><span>${done ? `<button class="btn primary" data-close>${tr("Done")}</button>`
      : `<button class="btn" data-close>${tr("Cancel")}</button> <button class="btn primary" data-rpgo${rp.state === "busy" ? " disabled" : ""}>${rp.state === "busy" ? `${rspin("sm plain")}${send_ ? tr("Sending…") : tr("Saving…")}` : rp.error ? tr("Try again") : send_ ? tr("Send") : tr("Save to Desktop")}</button>`}</span></div></div>`;
}

/* The card after a crash, in the update card's place (an update offer goes
   first). `lastcrash` says which crash; Send report sends that file. */
function crashCard() {
  const c = ui.crash;
  if (!c || c.hidden) return "";
  const who = DG_WHO[c.part] ? tr(DG_WHO[c.part]) : tr("Part of Kiri"), when = dgWhen(c.time, true);
  const title = c.part === "cli" ? tr("A kiri command crashed") : tr("Kiri quit unexpectedly last time");
  const more = c.count > 1 ? tr(" That's {count} crashes since Kiri last opened.", { count: c.count }) : "";
  const head = (ic, h, sub) => `<div class="updcard" role="dialog" aria-label="${esc(h)}">
    <div class="head"><div class="ic ${ic}">${dgIcon(ic === "ok" ? "checkcircle" : "warning")}</div><div class="txt"><h4>${esc(h)}</h4><div class="sub">${sub}</div></div>
    <button class="close" data-crashcard="close" aria-label="${tr("Close")}">${UPD_ICON.x}</button></div>`;
  if (c.id || c.state === "sent") return `${head("ok", tr("Report sent"), tr("Quote {id} if you write to us about this crash.", { id: `<span class="mono">${esc(c.id)}</span>` }))}
    <div class="row">${btn(`${dgIcon("copy")}${tr("Copy ID")}`, 'data-crashcard="copy"')}<button class="lnk" data-crashcard="view">${tr("Details")}</button></div></div>`;
  if (c.sent || (c.crashReports && c.state !== "error")) return `${head("calm", title, tr("{who} stopped {when}.{more} Crash reports are sent automatically, so this one goes to Kiri too.", { who, when: esc(when), more }))}
    <div class="row"><button class="lnk" data-crashcard="view">${tr("Details")}</button></div></div>`;
  return `${head("calm", title, tr("{who} stopped {when}.{more} A report helps us fix it: the stack trace and the last 200 log lines before it, with your home folder and tokens blanked.", { who, when: esc(when), more }))}
    ${c.error ? `<div class="err">${tr("Couldn't send it: {error}", { error: esc(c.error) })}</div>` : ""}
    <label class="opt"><input type="checkbox" data-crashcard="auto"${c.always ? " checked" : ""}> ${tr("Always send crash reports")}</label>
    <div class="row">${btn(c.state === "busy" ? tr("Sending…") : c.error ? tr("Try again") : tr("Send report"), `data-crashcard="send"${c.state === "busy" ? " disabled" : ""}`, "primary")}${btn(tr("Not now"), 'data-crashcard="close"')}<button class="lnk" data-crashcard="view">${tr("Details")}</button></div></div>`;
}
function crashCardAction(a, el) {
  const c = ui.crash;
  if (!c) return;
  if (a === "close") c.hidden = true;
  else if (a === "send") { if (c.always) setPref("crashReports", true); Object.assign(c, { state: "busy", error: "" }); send("diagsendcrash", { name: c.name }); }
  else if (a === "copy") { send("copy", { name: c.id }); copiedBtn(el); }
  else if (a === "view") { c.hidden = true; showDiag("", c.name); }
  renderUpdate();
}

/* An error's Details: the lines its action logged, in the window and the engine. */
function detailsDialog(text, op) {
  const cut = text.indexOf(": ");
  dt = { op, title: cut > 0 ? text.slice(0, cut) : tr("Something went wrong"), why: cut > 0 ? text.slice(cut + 2) : text, lines: null, state: "", id: "", error: "" };
  const scrim = document.createElement("div");
  scrim.className = "scrim"; scrim.id = "dt";
  document.body.append(scrim);
  drawDetails();
  send("diaglogs", { name: "", id: op, value: { errors: false, n: 200 } });
  const close = () => { scrim.remove(); dt = null; document.removeEventListener("keydown", onKey); };
  const onKey = (ev) => { if (ev.key === "Escape") close(); };
  document.addEventListener("keydown", onKey);
  scrim.addEventListener("click", (ev) => {
    if (ev.target === scrim) return close();
    const b = ev.target.closest("[data-dt]");
    if (!b) return;
    const a = b.dataset.dt;
    if (a === "close") close();
    else if (a === "copy") { send("copy", { name: [text, ...(dt.lines || []).map(dgPlain)].join("\n") }); copiedBtn(b); }
    else if (a === "copyid") { send("copy", { name: dt.id }); copiedBtn(b); }
    else if (a === "send") { Object.assign(dt, { state: "busy", error: "" }); send("diagsend", { value: { containers: false } }); drawDetails(); }
    else if (a === "diag") { close(); showDiag(op); }
  });
  scrim.querySelector('[data-dt="close"].primary')?.focus();
}
function drawDetails() {
  const scrim = $("dt");
  if (!scrim || !dt) return;
  const n = dt.lines?.length ?? 0;
  let parts = [...new Set((dt.lines || []).map((l) => (DG_PART[l.part] && tr(DG_PART[l.part])) || l.part))].join(tr(" and "));
  // Lowercase in a sentence, but German nouns keep their capital.
  if (LANG !== "de") parts = parts.toLowerCase();
  scrim.innerHTML = `<div class="dialog dt-dialog" role="dialog" aria-modal="true" aria-labelledby="dt-t">
    <div class="dt-head"><span class="ic">${dgIcon("xcircle")}</span><h3 id="dt-t">${esc(dt.title)}</h3><p>${esc(dt.why[0].toUpperCase() + dt.why.slice(1))}</p>
      <button class="close" data-dt="close" aria-label="${tr("Close")}">${UPD_ICON.x}</button></div>
    <div class="dt-meta">${dt.lines?.[0] ? `<span>${esc(dgWhen(dt.lines[0].time))}</span>` : ""}<span>${tr("Action {op}", { op: `<span class="mono">${esc(dt.op)}</span>` })}</span>
      <span>${dt.lines ? (n ? trn(n, "{n} log line from the {parts}", "{n} log lines from the {parts}", { parts }) : trn(n, "{n} log line", "{n} log lines")) : tr("Reading the log…")}</span></div>
    <div class="dt-body"><div class="dg-log" role="log" aria-label="${tr("Log lines for this action")}">${!dt.lines ? `<div class="dg-empty">${tr("Reading the log…")}</div>` : n ? dt.lines.map(dgRow).join("") : `<div class="dg-empty">${tr("This action left no log lines.")}</div>`}</div></div>
    <div class="dt-foot"><button class="lnk" data-dt="diag">${tr("Show in Diagnostics")}</button>
      ${dt.error ? `<span class="err">${tr("Couldn't send it: {error}", { error: esc(dt.error) })}</span>` : ""}
      ${dt.state === "sent" ? `<span class="ok">${dgIcon("checkcircle")}${tr("Sent as {id}", { id: `<span class="mono">${esc(dt.id)}</span>` })}</span>${btn(`${dgIcon("copy")}${tr("Copy ID")}`, 'data-dt="copyid"')}`
        : `${btn(`${dgIcon("copy")}${tr("Copy")}`, 'data-dt="copy"')}${btn(`${dgIcon("send")}${dt.state === "busy" ? tr("Sending…") : tr("Send report")}`, `data-dt="send"${dt.state === "busy" ? " disabled" : ""}`)}`}
      ${btn(tr("Close"), 'data-dt="close"', "primary")}</div>
  </div>`;
}

/* The diagnostics events. */
function diagEvent(e) {
  switch (e.type) {
    case "diaglogs":
      if (dt && e.op === dt.op && !e.part) { dt.lines = e.lines || []; drawDetails(); }
      if (dg.copyOp && e.op === dg.copyOp) { send("copy", { name: [dg.copyText, ...(e.lines || []).map(dgPlain)].join("\n") }); dg.copyOp = ""; }
      if (e.part === dg.part && e.op === dg.op) { dg.lines = e.lines || []; drawDiagLog(); }
      break;
    case "diagcrashes":
      dg.crashes = e.crashes || [];
      for (const c of dg.crashes) if (c.sent) dg.sending.delete(c.name);
      if (ui.view === "settings") render();
      break;
    case "diagsendcrash":
      dg.sending.delete(e.name);
      if (ui.crash?.name === e.name) { Object.assign(ui.crash, e.id ? { state: "sent", id: e.id, hidden: false } : { state: "error", error: e.error }); renderUpdate(); }
      else if (e.error) toast("error", tr("Couldn't send the crash report: {error}", { error: e.error }));
      send("diagcrashes");
      break;
    case "diagsend":
      if (e.id) dg.sent = e.id;
      if (rp?.mode === "send") { Object.assign(rp, e.id ? { state: "sent", id: e.id } : { state: "", error: e.error }); drawReport(); }
      if (dt?.state === "busy") { Object.assign(dt, e.id ? { state: "sent", id: e.id } : { state: "", error: e.error }); drawDetails(); }
      if (ui.view === "settings") render();
      break;
    case "diagreport":
      if (rp?.mode === "save") { if (e.path) rp.close(); else { Object.assign(rp, { state: "", error: e.error }); drawReport(); } }
      if (e.path) toast("ok", tr("Saved the report to {path}", { path: e.path })); else if (!rp) toast("error", tr("Couldn't save the report: {error}", { error: e.error }));
      break;
    case "lastcrash": ui.crash = { ...e, state: "", always: false }; renderUpdate(); break;
  }
}

Object.assign(window, { buildAsk, builderPref, renderSettings, renderStorageUnavailable, storageConfirm, renderBuilds, layersView, scanView, chooseScanner, rerenderScan, diagOpen, diagPane, diagDrawn, diagClick, crashCard, crashCardAction, detailsDialog, drawDetails, drawReport, reportDialog, drawDiagLog, diagEvent });
})();
