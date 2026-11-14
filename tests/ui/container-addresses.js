// parity: macos windows linux
// Settings → Network → Container addresses: the pool new networks take their
// subnets from, on every system. The line under it checks it as it's typed:
// red for a range Kiri can't use, amber when it overlaps one of this
// computer's networks, green with the room it has. Back to the default is a
// link; Save sends the pool with the proxy settings, and a red one can't be saved.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const proxyEvent = (pool = "172.16.0.0/12", bridge = "172.17.0.0/16") => ({ type: "proxy",
  settings: { mode: "system", http: "", https: "", no_proxy: "", containers: false },
  effective: { http: null, https: null, no_proxy: [], pac: false },
  pool: { pool, default: "172.16.0.0/12", bridge, host: [{ name: "VPN (utun4)", net: "172.20.0.0/16" }, { name: "Wi-Fi (en0)", net: "192.168.1.0/24" }] } });
const network = () => { prefs.tab = "network"; show("settings"); };
const field = () => document.getElementById("px-pool");
const hint = () => document.getElementById("pool-hint");
const save = () => document.querySelector("#content [data-savepx]");
const put = (v) => { const f = field(); f.value = v; f.dispatchEvent(new Event("input", { bubbles: true })); };
const items = [];

kiri.on(proxyEvent());
network();
for (const r of document.querySelectorAll("#content .pref .t")) items.push(`network row ${r.textContent.trim()}`);
if (field()) items.push("network container addresses field");

t("the row shows the pool in a mono field after Pass to containers", () => {
  const rows = [...document.querySelectorAll("#content .pref .t")].map((r) => r.textContent.trim());
  eq(rows.slice(-2), ["Pass to containers", "Container addresses"], "rows");
  eq(field().value, "172.16.0.0/12", "value");
  if (!/The pool Kiri takes each network's addresses from/.test(document.querySelector("#content .pane").textContent)) throw new Error("no description");
  if (!/VPNs need no other setting/.test(document.querySelector("#content .res-foot").textContent)) throw new Error("footer: " + document.querySelector("#content .res-foot").textContent);
});
t("the default that overlaps a VPN is amber and names it, with no reset link", () => {
  eq(hint().className, "pool-hint warn", "class");
  if (!hint().textContent.includes("Clashes with VPN (utun4), 172.20.0.0/16: containers on a network there can't reach it.")) throw new Error(hint().textContent);
  if (hint().querySelector("[data-poolreset]")) throw new Error("reset link on the default");
  if (save().disabled) throw new Error("Save blocked on amber");
});
t("a free range is green, with the room it has and a reset link", () => {
  put("10.200.0.0/16");
  eq(hint().className, "pool-hint ok", "class");
  if (!hint().textContent.includes("No clash with this computer's networks. Room for 256 networks of /24.")) throw new Error(hint().textContent);
  if (!hint().textContent.includes("Networks you have keep their addresses.")) throw new Error("no note on existing networks");
  if (!hint().textContent.includes("The default network moves into it when Kiri next starts.")) throw new Error("no note on the default bridge");
  if (!hint().querySelector("[data-poolreset]")) throw new Error("no reset link");
  put("10.0.0.0/8");
  if (!hint().textContent.includes("Room for 256 networks of /16.")) throw new Error(hint().textContent);
  put("192.168.5.0/24");
  if (!hint().textContent.includes("Room for 1 network of /24.")) throw new Error(hint().textContent);
});
t("a range over Wi-Fi is amber", () => {
  put("192.168.0.0/16");
  eq(hint().className, "pool-hint warn", "class");
  if (!hint().textContent.includes("Clashes with Wi-Fi (en0), 192.168.1.0/24")) throw new Error(hint().textContent);
});
t("a range Kiri can't use is red and blocks Save", () => {
  for (const bad of ["10.200.0.0", "10.200.0.0/25", "10.0.0.0/7", "300.1.0.0/16", "nonsense"]) {
    put(bad);
    eq(hint().className, "pool-hint err", bad);
    if (!hint().textContent.includes("Write it like 10.200.0.0/16 (from /8 to /24)")) throw new Error(bad + ": " + hint().textContent);
    if (!field().classList.contains("bad")) throw new Error(bad + ": field not marked");
    if (!save().disabled) throw new Error(bad + ": Save enabled");
  }
  put("8.8.0.0/16");
  eq(hint().className, "pool-hint err", "public range");
  if (!hint().textContent.includes("Use a private range (inside 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16).")) throw new Error(hint().textContent);
  sent.length = 0;
  save().click();
  document.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  eq(sent.filter((m) => m.type === "setproxy").length, 0, "setproxy sent");
});
t("Back to the default puts it back", () => {
  put("10.200.0.0/16");
  hint().querySelector("[data-poolreset]").click();
  eq(field().value, "172.16.0.0/12", "value");
  eq(ui.pxDraft.pool, "172.16.0.0/12", "draft");
  eq(hint().className, "pool-hint warn", "class");
  if (hint().querySelector("[data-poolreset]")) throw new Error("reset link still there");
});
t("Save sends the pool with the proxy settings", () => {
  put("10.200.0.0/16");
  if (save().disabled) throw new Error("Save blocked");
  sent.length = 0;
  save().click();
  const m = sent.find((x) => x.type === "setproxy");
  if (!m) throw new Error("sent " + JSON.stringify(sent));
  eq([m.value.pool, m.value.mode], ["10.200.0.0/16", "system"], "value");
});
t("once saved and the bridge has moved, no notes and the reset link stays", () => {
  kiri.on(proxyEvent("10.200.0.0/16", "10.200.0.0/24"));
  network();
  eq(field().value, "10.200.0.0/16", "value");
  eq(hint().className, "pool-hint ok", "class");
  if (/keep their addresses|next starts/.test(hint().textContent)) throw new Error(hint().textContent);
  if (!hint().querySelector("[data-poolreset]")) throw new Error("no reset link");
});
t("an engine without the setting shows no row", () => {
  const e = proxyEvent(); delete e.pool;
  kiri.on(e);
  network();
  if (field()) throw new Error("row shown");
  sent.length = 0;
  save().click();
  const m = sent.find((x) => x.type === "setproxy");
  if (!m || "pool" in m.value) throw new Error("sent " + JSON.stringify(sent));
});
report([...R, ...items.map((x) => "ITEM " + x)]);
