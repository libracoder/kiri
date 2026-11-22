// Settings → Resources has a switch for starting Kiri when the person signs
// in (issue 703). The shared page shows it on every system; the host sends the
// real state and applies a change, sending the state back afterwards.
kiri.on({ type: "prefs", prefs: {} });
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const asw = (v) => document.querySelector('#content [data-autostart="' + v + '"]');
const pressed = (v) => asw(v)?.getAttribute("aria-pressed");

prefs.tab = "resources";
show("settings");

t("Settings → Resources offers the start-at-login switch", () => {
  eq([!!btn(0), !!btn(1)], [true, true], "Off and On buttons");
  eq([pressed(0), pressed(1)], ["true", "false"], "initial state");
});

t("the host's state moves the switch", () => {
  kiri.on({ type: "autostart", on: true });
  eq([pressed(0), pressed(1)], ["false", "true"], "on");
});

t("clicking On asks the host to turn it on", () => {
  kiri.on({ type: "autostart", on: false });
  asw(1).click();
  eq(sent.at(-1)?.type, "autostart", "command");
  eq(sent.at(-1)?.value, true, "value");
  eq([pressed(0), pressed(1)], ["false", "true"], "optimistic state");
});

t("the host can put the switch back after a failed change", () => {
  kiri.on({ type: "autostart", on: false });
  eq([pressed(0), pressed(1)], ["true", "false"], "reverted");
});

t("clicking Off asks the host to turn it off", () => {
  kiri.on({ type: "autostart", on: true });
  asw(0).click();
  eq(sent.at(-1)?.type, "autostart", "command");
  eq(sent.at(-1)?.value, false, "value");
});

report(R);
