// Settings → Builds: "Build with Forge", the switch for what
// `kiri build` uses (the engine's setting, as `kiri builder use` sets it).
// Off by default; On sends {native: true}, Off {native: false}, at once.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const last = (cmd) => sent.filter((m) => m.type === cmd).at(-1);
const pref = () => [...document.querySelectorAll(".settings .pref")].find((p) => p.querySelector("[data-nb]"));
const pressed = (v) => pref().querySelector(`[data-nb="${v}"]`).getAttribute("aria-pressed") === "true";

t("Settings → Builds asks for it", () => {
  show("settings");
  document.querySelector('[data-stab="builds"]').click();
  if (!last("nativebuild") || last("nativebuild").value !== undefined) throw new Error("didn't ask for the state: " + JSON.stringify(last("nativebuild")));
  kiri.on({ type: "buildwith", with: "docker", ask: false, engine: null, taken: false, ready: true });
});
t("before the engine answers it can't be switched", () => {
  if (!pref()) throw new Error("no switch");
  if (!pref().querySelector('[data-nb="1"]').disabled) throw new Error("On is clickable before the state is known");
});
t("off by default, with its label and one line under it", () => {
  kiri.on({ type: "nativebuild", native: false, cache_limit: 21474836480, idle_secs: 300, state: "none" });
  const p = pref();
  if (p.querySelector(".t").textContent !== "Build with Forge") throw new Error("label: " + p.querySelector(".t").textContent);
  const d = p.querySelector(".d").textContent;
  if (!/^kiri build makes images with Forge, Kiri's own build engine/.test(d) || !/BuildKit stays available/.test(d)) throw new Error("line: " + d);
  if (!pressed(0) || pressed(1)) throw new Error("not Off");
  if (p.querySelector('[data-nb="1"]').disabled) throw new Error("disabled");
  if (p.querySelector(".seg")?.getAttribute("aria-label") !== "Build with Forge") throw new Error("the switch has no name");
});
t("On sends native: true and shows it at once", () => {
  const n = sent.length;
  pref().querySelector('[data-nb="1"]').click();
  if (sent.length !== n + 1 || last("nativebuild").value !== true) throw new Error("sent " + JSON.stringify(sent.slice(n)));
  if (!pressed(1) || pressed(0)) throw new Error("not On");
  kiri.on({ type: "nativebuild", native: true });
  if (!pressed(1)) throw new Error("not On after the answer");
});
t("pressing On again sends nothing", () => {
  const n = sent.length;
  pref().querySelector('[data-nb="1"]').click();
  if (sent.length !== n) throw new Error("sent " + JSON.stringify(sent.slice(n)));
});
t("Off sends native: false", () => {
  pref().querySelector('[data-nb="0"]').click();
  if (last("nativebuild").value !== false) throw new Error("sent " + JSON.stringify(last("nativebuild")));
  if (!pressed(0)) throw new Error("not Off");
});
t("no engine: shown, not switchable", () => {
  kiri.on({ type: "nativebuild", error: "Kiri isn't running" });
  if (!pref().querySelector('[data-nb="0"]').disabled) throw new Error("clickable");
  const n = sent.length;
  pref().querySelector('[data-nb="1"]').click();
  if (sent.length !== n) throw new Error("sent " + JSON.stringify(sent.slice(n)));
});
report(R);
