// parity: macos windows linux
// Settings → Registry mirrors: the Docker Hub pull-through mirrors. Adding,
// removing and saving send setmirrors; an answer from the daemon replaces
// the page; a daemon that can't be reached says to start Kiri.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const mirrors = (list) => ({ type: "mirrors", mirrors: list, applies_to: "docker.io" });
const pane = () => document.querySelector("#content .settings");
const open = () => { prefs.tab = "mirrors"; show("settings"); };
const put = (id, v) => { const el = document.getElementById(id); el.value = v; el.dispatchEvent(new Event("input", { bubbles: true })); };
const save = () => document.querySelector("#content [data-savemirrors]");
const sentList = () => { const m = sent.find((x) => x.type === "setmirrors"); return m ? m.value.mirrors : null; };
const items = [];

kiri.on(mirrors([]));
open();
if (document.querySelector('#content [data-stab="mirrors"]')) items.push("settings tab Registry mirrors");
if (document.getElementById("mirror-url")) items.push("mirrors address field");
if (document.querySelector("#content [data-mirroradd]")) items.push("mirrors add button");

t("with no mirrors it says Docker Hub itself is used", () => {
  if (!pane().textContent.includes("No mirrors yet")) throw new Error(pane().textContent);
  if (!save().disabled) throw new Error("save enabled with nothing changed");
});
t("opening Settings asks for the mirrors", () => {
  sent.length = 0;
  ui.mirrors = null;
  show("settings");
  if (!sent.some((m) => m.type === "mirrors")) throw new Error("sent " + sent.map((m) => m.type).join(","));
  kiri.on(mirrors([]));
});
t("adding an address shows it, and Save sends the whole list", () => {
  put("mirror-url", "https://mirror.example.com");
  document.querySelector("#content [data-mirroradd]").click();
  if (!pane().textContent.includes("mirror.example.com")) throw new Error("no row");
  sent.length = 0;
  save().click();
  if (JSON.stringify(sentList()) !== JSON.stringify(["https://mirror.example.com"])) throw new Error("sent " + JSON.stringify(sent));
});
t("the daemon's answer resets the page to the saved list", () => {
  kiri.on(mirrors(["https://mirror.example.com", "https://mirror.example.net"]));
  open();
  if (!pane().textContent.includes("mirror.example.net")) throw new Error("no second mirror");
  if (!save().disabled) throw new Error("save enabled");
});
t("removing a mirror takes it out of the list Save sends", () => {
  const rows = document.querySelectorAll("#content [data-mirrordel]");
  if (rows.length !== 2) throw new Error("rows " + rows.length);
  rows[0].click();
  sent.length = 0;
  save().click();
  if (JSON.stringify(sentList()) !== JSON.stringify(["https://mirror.example.net"])) throw new Error("sent " + JSON.stringify(sent));
});
t("with no daemon the page says to start Kiri", () => {
  kiri.on({ type: "mirrors", error: "connection refused" });
  open();
  if (document.getElementById("mirror-url")) throw new Error("field shown");
  if (!pane().textContent.includes("Start Kiri")) throw new Error("no hint");
});
report([...R, ...items.map((x) => "ITEM " + x)]);
