// Settings -> Network: Docker socket ownership (#577) and plain `docker` CLI
// binding (#369). Run with scripts/ui-test.py.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const click = (sel) => { const el = document.querySelector(sel); if (!el) throw new Error("no " + sel); el.click(); return el; };

const reset = () => {
  sent.length = 0;
  document.querySelectorAll(".scrim").forEach((x) => x.remove());
  kiri.on({ type: "importsources", sources: [] });
  kiri.on({ type: "status", version: "0.1.4", dev: false, share: true, app: "Kiri", ours: "kiri", context: "kiri", pinned: null });
  kiri.on({ type: "dockersock", path: WIN ? "\\\\.\\pipe\\docker_engine" : "/var/run/docker.sock", owner: "kiri", engine: null, target: null, hint: WIN ? "DOCKER_HOST=npipe:////./pipe/kiri" : "DOCKER_HOST=unix:///Users/me/.kiri/run/docker.sock", take: false });
  sent.length = 0;
};

prefs.tab = "network";
show("settings");

t("Settings -> Network asks for dockersock on open, tab click and window focus", () => {
  reset();
  show("containers");
  sent.length = 0;
  show("settings");
  eq(sent.some((x) => x.type === "dockersock"), true, "show settings");
  sent.length = 0;
  click('[data-stab="about"]');
  click('[data-stab="network"]');
  eq(sent.some((x) => x.type === "dockersock"), true, "tab click");
  sent.length = 0;
  window.dispatchEvent(new Event("focus"));
  eq(sent.some((x) => x.type === "dockersock"), true, "window focus");
});

t("Docker socket and CLI rows render above loading or stopped engine error", () => {
  reset();
  ui.proxy = null;
  render();
  eq(document.querySelectorAll("#content .pref").length >= 2, true, "rows visible while loading");
  ui.proxy = { error: "Kiri is not running" };
  render();
  const txt = document.getElementById("content").textContent;
  eq(txt.includes("Docker socket"), true, "socket row while stopped");
  eq(txt.includes("docker command"), true, "cli row while stopped");
  eq(txt.includes("Kiri is not running"), true, "proxy error still shown");
});

t("Another engine owning the socket shows its name, DOCKER_HOST hint and copy button", () => {
  reset();
  ui.proxy = { error: "Kiri is not running" };
  const hint = WIN ? "DOCKER_HOST=npipe:////./pipe/kiri" : "DOCKER_HOST=unix:///Users/me/.kiri/run/docker.sock";
  kiri.on({
    type: "dockersock",
    path: WIN ? "\\\\.\\pipe\\docker_engine" : "/var/run/docker.sock",
    owner: "other",
    engine: WIN ? "Docker Desktop" : "OrbStack",
    target: WIN ? "Docker Desktop.exe" : "/Users/me/.orbstack/run/docker.sock",
    hint,
    take: false,
  });
  const c = document.getElementById("content");
  const txt = c.textContent;
  eq(txt.includes(WIN ? "Docker Desktop" : "OrbStack"), true, "engine shown");
  eq(txt.includes(hint), true, "hint shown");
  eq(!!c.querySelector("[data-takesock]"), false, "never offers to take another engine's socket");
  sent.length = 0;
  click("#content [data-copy]");
  eq(sent.find((x) => x.type === "copy")?.name, hint, "copy hint");
  // Unknown owner (no engine name or target) never renders "null" or "undefined".
  kiri.on({ type: "dockersock", path: "/var/run/docker.sock", owner: "other", engine: null, target: null, hint, take: false });
  const t2 = document.getElementById("content").textContent;
  eq(t2.includes("null") || t2.includes("undefined"), false, "no raw null");
});

t("Free socket shows Use Kiri when take is true and Free badge when take is false", () => {
  reset();
  ui.proxy = { error: "stopped" };
  const path = "/var/run/docker.sock";
  const hint = "DOCKER_HOST=unix:///Users/me/.kiri/run/docker.sock";
  kiri.on({ type: "dockersock", path, owner: "free", engine: null, target: null, hint, take: true });
  sent.length = 0;
  click("#content [data-takesock]");
  eq(sent.some((x) => x.type === "takesocket"), true, "takesocket sent");
  eq(document.querySelector("#content [data-takesock]").disabled, true, "disabled while taking");
  // Cancel or update re-enables on fresh dockersock event.
  kiri.on({ type: "dockersock", path, owner: "free", engine: null, target: null, hint, take: true });
  eq(document.querySelector("#content [data-takesock]").disabled, false, "re-enabled after event");
  kiri.on({ type: "dockersock", path, owner: "free", engine: null, target: null, hint, take: false });
  eq(!!document.querySelector("#content [data-takesock]"), false, "no take button when take is false");
  eq(document.getElementById("content").textContent.includes("Free"), true, "Free badge");
});

t("Another docker context (desktop-linux) reports honestly and switches from Settings", () => {
  reset();
  ui.proxy = { error: "stopped" };
  kiri.on({ type: "status", version: "0.1.4", dev: false, share: true, app: "Kiri", ours: "kiri", context: "desktop-linux", pinned: null });
  show("containers");
  eq(document.querySelector("#statusbar").textContent.includes("docker → Docker Desktop"), true, "status bar says Docker Desktop");
  eq(!!document.querySelector("#impstrip [data-ctxswitch]"), true, "strip offers switch");
  prefs.tab = "network";
  show("settings");
  eq(document.getElementById("content").textContent.includes("The docker command uses Docker Desktop."), true, "Settings shows Docker Desktop");
  sent.length = 0;
  click("#content [data-usekiri]");
  eq(sent.find((x) => x.type === "usecontext")?.name, "kiri", "switches to kiri");
  kiri.on({ type: "status", version: "0.1.4", dev: false, share: true, app: "Kiri", ours: "kiri", context: "kiri", pinned: null });
  kiri.on({ type: "usedcontext", name: "kiri", error: null });
  eq(!!document.querySelector("#content [data-usekiri]"), false, "switch button gone once on kiri");
  eq(document.querySelector("#statusbar").textContent.includes("docker → Kiri"), true, "status bar updated to Kiri");
});

t("Pinned DOCKER_HOST or DOCKER_CONTEXT never offers a context switch", () => {
  reset();
  ui.proxy = { error: "stopped" };
  kiri.on({ type: "status", version: "0.1.4", dev: false, share: true, app: "Kiri", ours: "kiri", context: "default", pinned: "DOCKER_HOST" });
  show("containers");
  eq(document.querySelector("#statusbar").textContent.includes("docker → DOCKER_HOST"), true, "status bar names DOCKER_HOST");
  eq(!!document.querySelector("#impstrip [data-ctxswitch]"), false, "strip does not offer pointless switch");
  click("#statusbar [data-ctxswitch]");
  eq(document.querySelector("#ctx-dlg")?.textContent.includes("DOCKER_HOST"), true, "dialog explains DOCKER_HOST");
  eq(!!document.querySelector("#ctx-dlg [data-ctxgo]"), false, "dialog has no switch button when pinned");
  click("#ctx-dlg [data-close]");
  prefs.tab = "network";
  show("settings");
  eq(!!document.querySelector("#content [data-usekiri]"), false, "Settings hides switch when pinned");
  eq(document.getElementById("content").textContent.includes("DOCKER_HOST"), true, "Settings names DOCKER_HOST");
});

report(R);
