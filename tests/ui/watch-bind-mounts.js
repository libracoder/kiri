// Settings → Resources → WSL integration: Windows C:\ bind-mount file events
// (watchBindMounts, #487) Off|On toggle, setpref round-trip, and omission on
// non-Windows when neither WSL nor watchBindMounts state is present.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${m}: got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`); };

const baseRes = {
  type: "resources", cpus: 8, memory_mib: 16384, running_cpus: 8, running_memory_mib: 16384,
  awake: true, max_cpus: 16, max_memory_mib: 32768, overridden: false,
};

prefs.tab = "resources";
show("settings");

t("Bind-mount watcher toggle hidden on non-Windows without WSL or watchBindMounts state", () => {
  delete prefs.watchBindMounts;
  kiri.on({ ...baseRes });
  eq(!!document.querySelector("[data-watchbinds]"), false, "no watchbinds toggle");
});

t("Bind-mount watcher toggle renders from Windows prefs even when no other WSL distros exist", () => {
  sent.length = 0;
  kiri.on({ type: "prefs", prefs: { watchBindMounts: false } });
  kiri.on({ ...baseRes, wsl_distros: [] });
  const tabs = document.querySelector(".settings .tabs").getBoundingClientRect();
  const offBtn = document.querySelector('[data-watchbinds="0"]');
  const onBtn = document.querySelector('[data-watchbinds="1"]');
  if (!offBtn || !onBtn) throw new Error("missing watchbinds Off|On buttons");
  if (offBtn.getBoundingClientRect().left < tabs.right) throw new Error("watchbinds sits under tabs");
  eq(offBtn.getAttribute("aria-pressed"), "true", "Off initially pressed");
  eq(onBtn.getAttribute("aria-pressed"), "false", "On initially unpressed");
  const wsl = [...document.querySelectorAll(".settings .pane")].find((p) => p.querySelector("h3")?.textContent.trim() === "WSL integration");
  eq(wsl?.textContent.includes("C:\\"), true, "mentions C:\\");
  eq(wsl?.textContent.includes("No other WSL distros installed."), true, "empty distro note kept");
});

t("Clicking Off|On sends setpref('watchBindMounts', true/false), ignores no-ops, and reconciles prefs", () => {
  sent.length = 0;
  // Clicking already-active Off sends nothing.
  document.querySelector('[data-watchbinds="0"]').click();
  eq(sent.length, 0, "no duplicate send on active Off");

  // Turn On.
  document.querySelector('[data-watchbinds="1"]').click();
  const onMsg = sent.find((m) => m.cmd === "setpref" && m.name === "watchBindMounts");
  if (!onMsg) throw new Error("missing setpref(watchBindMounts) on enable: " + JSON.stringify(sent));
  eq(onMsg.value, true, "enabled value");
  eq(prefs.watchBindMounts, true, "prefs updated to true");
  eq(document.querySelector('[data-watchbinds="1"]').getAttribute("aria-pressed"), "true", "On pressed");
  eq(document.querySelector('[data-watchbinds="0"]').getAttribute("aria-pressed"), "false", "Off unpressed");

  // Turn Off.
  sent.length = 0;
  document.querySelector('[data-watchbinds="0"]').click();
  const offMsg = sent.find((m) => m.cmd === "setpref" && m.name === "watchBindMounts");
  if (!offMsg) throw new Error("missing setpref(watchBindMounts) on disable: " + JSON.stringify(sent));
  eq(offMsg.value, false, "disabled value");
  eq(prefs.watchBindMounts, false, "prefs updated to false");
  eq(document.querySelector('[data-watchbinds="0"]').getAttribute("aria-pressed"), "true", "Off pressed again");

  // Host round-trip prefs event reconciles toggle state alongside WSL distros.
  kiri.on({ ...baseRes, wsl_distros: [{ name: "Ubuntu", on: true }] });
  kiri.on({ type: "prefs", prefs: { watchBindMounts: true } });
  eq(document.querySelector('[data-watchbinds="1"]').getAttribute("aria-pressed"), "true", "reconciled On from host prefs");
  eq(document.querySelector('[data-wsldistro="Ubuntu"][data-wslon="1"]').getAttribute("aria-pressed"), "true", "distro row intact");
});

report(R);
