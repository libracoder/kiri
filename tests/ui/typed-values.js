// parity: macos windows linux
// Values that are always a number or a fixed word (Docker Hub's stars, the share account's sizes, a container's ID,
// published and Kubernetes ports, USB state, bus and device) still never reach the HTML as markup when an answer, a
// cache or a host sends text in their place: the helpers coerce to numbers, the rest goes through esc(). What a
// normal value shows is unchanged.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const EVIL = '"><img src=x onerror="window.pwned=(window.pwned||0)+1"><b id=evil>';
const clean = (where) => {
  eq(document.querySelector("#evil, img[src=x], [onerror]"), null, `${where}: markup from a value got in`);
  eq(window.pwned, undefined, `${where}: a handler ran`);
};
t("stars and sizes show as before for numbers", () => {
  eq([stars(20900), stars(1500), stars(195), stars(0), stars(undefined)], ["21k ★", "1.5k ★", "195 ★", "0 ★", "0 ★"], "stars");
  eq([size(0), size(999), size(1500), size(1.9e9)], ["0 B", "999 B", "1.5 KB", "1.9 GB"], "size");
});
t("stars and sizes are numbers whatever came", () => {
  eq(stars(EVIL), "0 ★", "stars of text");
  eq(stars("2000"), "2.0k ★", "stars of a number in text");
  eq(size(EVIL), "0 B", "size of text");
  eq(size({ toString: () => EVIL }), "0 B", "size of an object");
});
ui.vm = "running";
kiri.on({ type: "status", version: "0.1.4", dev: true, share: true, app: "Kiri", ours: "kiri", context: "kiri" });
const now = Math.floor(Date.now() / 1000);
kiri.on({ type: "lists", containers: [
  { Id: "abc123" + EVIL, Names: ["/web"], Image: "nginx", State: "running", Status: "Up", Created: now - 60, Labels: {},
    Ports: [{ IP: "0.0.0.0", PrivatePort: EVIL, PublicPort: 8080, Type: "tcp" }, { IP: "0.0.0.0", PrivatePort: 443, PublicPort: "9<b id=evil>", Type: "tcp" }] },
  { Id: "def456", Names: ["/db"], Image: "postgres", State: "running", Status: "Up", Created: now - 60, Labels: {}, Ports: [{ IP: "0.0.0.0", PrivatePort: 5432, PublicPort: 5432, Type: "tcp" }] },
], images: [], volumes: [], networks: [] });
show("containers");
t("a container's ID and ports in the list", () => {
  clean("containers");
  const row = document.querySelector('#content tr[data-key="def456"]');
  eq(row.querySelector('[data-c="stop"]').dataset.id, "def456", "a plain ID as before");
  eq([...row.querySelectorAll("a.port")].map((a) => [a.textContent, a.dataset.open]), [["5432→5432", "http://localhost:5432"]], "a plain port as before");
  const odd = [...document.querySelectorAll("#content tr.row")].find((r) => r.dataset.key !== "def456");
  eq(odd.querySelector('[data-c="stop"]').dataset.id, "abc123" + EVIL, "the odd ID is the same text, escaped");
});
t("a container's page and ⋯ menu", () => {
  document.querySelector('#content tr[data-key="def456"] [data-more]').click();
  eq([...document.querySelectorAll('.menu [data-c="pause"]')].map((b) => b.dataset.id), ["def456"], "menu");
  document.body.click();
  const odd = [...document.querySelectorAll("#content tr.row")].find((r) => r.dataset.key !== "def456");
  odd.querySelector("[data-more]").click();
  clean("⋯ menu");
  document.body.click();
  openDetail(odd.dataset.key);
  clean("container page");
});
kiri.on({ type: "usb", can: "attach", devices: [
  { key: "u1", name: "Odd", id: "1:2", speed: "full", state: EVIL, bus: EVIL, dev: "3<b id=evil>", path: "" },
  { key: "u2", name: "Plain", id: "10c4:ea60", speed: "full", state: "host", bus: "1", dev: "4", path: "" },
] });
show("usb");
t("USB state, bus and device", () => {
  clean("usb list");
  document.querySelector('[data-usbmore="u1"]').click();
  clean("usb details");
  document.querySelector('[data-usbmore="u2"]').click();
  eq(document.querySelector("#content").textContent.includes("Bus 1 · Device 4"), true, "a plain location as before");
});
kiri.on({ type: "k8s", state: "running", ready: true, context: "kiri", pods: [],
  services: [
    { ns: "default", name: "odd", type: "LoadBalancer", clusterIP: "10.43.0.9", ports: [{ port: EVIL, targetPort: 80, protocol: "TCP", nodePort: EVIL }], selector: {}, ingress: [], created: "2026-10-28T00:00:00Z" },
    { ns: "default", name: "web", type: "LoadBalancer", clusterIP: "10.43.0.5", ports: [{ port: 8080, targetPort: 80, protocol: "TCP" }], selector: {}, ingress: [], created: "2026-10-28T00:00:00Z" },
  ] });
show("services");
t("Kubernetes service ports", () => {
  clean("services");
  eq([...document.querySelectorAll("#content a.port")].map((a) => [a.textContent, a.dataset.open]).find(([, u]) => u === "http://localhost:8080"), ["8080→80", "http://localhost:8080"], "a plain port as before");
});
kiri.on({ type: "shareusage", login: "octo", used: EVIL, cap: 5e9, tunnels: 3, rate: EVIL });
show("share");
t("the share account's sizes", () => clean("share"));
report(R);
