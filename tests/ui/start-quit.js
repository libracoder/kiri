// parity: macos windows linux
// #368, #703: Settings → Appearance offers "Start Kiri at sign-in" and "Stop
// the engine when Kiri quits" on macOS, Windows and Linux, with per-system
// defaults before prefs arrive, setpref messages on click, and host updates.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const seen = (el) => !!el && !el.closest("[hidden]") && getComputedStyle(el).display !== "none";
const pressed = (attr, v) => document.querySelector(`#content [${attr}="${v}"]`)?.getAttribute("aria-pressed");
const state = () => ({
  loginOff: pressed("data-startlogin", "0"),
  loginOn: pressed("data-startlogin", "1"),
  quitOff: pressed("data-stopquit", "0"),
  quitOn: pressed("data-stopquit", "1"),
});

prefs.tab = "appearance";
delete prefs.startAtLogin;
delete prefs.stopOnQuit;
show("settings");

const items = [];
for (const [attr, name] of [["data-startlogin", "startAtLogin"], ["data-stopquit", "stopOnQuit"]]) {
  for (const v of ["0", "1"]) {
    if (seen(document.querySelector(`#content [${attr}="${v}"]`))) items.push(`appearance ${name} ${v}`);
  }
}

t("defaults match the system before prefs arrive", () => {
  const defaultLogin = window.KIRI_OS !== "linux";
  eq(state(), {
    loginOff: String(!defaultLogin),
    loginOn: String(defaultLogin),
    quitOff: "true",
    quitOn: "false",
  }, "defaults");
  const text = document.querySelector("#content .settings")?.textContent || "";
  if (!text.includes("Start Kiri at sign-in")) throw new Error("missing Start Kiri at sign-in label");
  if (!text.includes("Stop the engine when Kiri quits")) throw new Error("missing Stop the engine when Kiri quits label");
});

t("toggling Start Kiri at sign-in updates aria-pressed and sends setpref", () => {
  sent.length = 0;
  document.querySelector('#content [data-startlogin="0"]').click();
  eq([state().loginOff, state().loginOn], ["true", "false"], "startAtLogin off");
  document.querySelector('#content [data-startlogin="1"]').click();
  eq([state().loginOff, state().loginOn], ["false", "true"], "startAtLogin on");
  eq(
    sent.filter((x) => x.type === "setpref" && x.name === "startAtLogin").map((x) => x.value),
    [false, true],
    "startAtLogin setpref",
  );
});

t("host prefs event updates or reverts both toggles", () => {
  kiri.on({ type: "prefs", prefs: { tab: "appearance", startAtLogin: false, stopOnQuit: true } });
  eq(state(), { loginOff: "true", loginOn: "false", quitOff: "false", quitOn: "true" }, "host prefs applied");
});

t("toggling Stop the engine when Kiri quits updates aria-pressed and sends setpref", () => {
  sent.length = 0;
  document.querySelector('#content [data-stopquit="0"]').click();
  eq([state().quitOff, state().quitOn], ["true", "false"], "stopOnQuit off");
  document.querySelector('#content [data-stopquit="1"]').click();
  eq([state().quitOff, state().quitOn], ["false", "true"], "stopOnQuit on");
  eq(
    sent.filter((x) => x.type === "setpref" && x.name === "stopOnQuit").map((x) => x.value),
    [false, true],
    "stopOnQuit setpref",
  );
});

report([...R, ...items.map((x) => "ITEM " + x)]);
