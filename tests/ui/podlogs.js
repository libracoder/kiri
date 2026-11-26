// parity: macos windows linux
// Pod logs share the numbered log console component with Container logs.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };

kiri.on({
  type: "lists",
  containers: [{ Id: "k8snode000001", Names: ["/kiri-k8s"], Image: "rancher/k3s:v1.31.4-k3s1", State: "running", Status: "Up 2m", Created: 1700000000, Ports: [], Labels: {} }],
  images: [], volumes: [], networks: [],
});
kiri.on({
  type: "k8s",
  state: "running",
  ready: true,
  context: "kiri",
  port: 6443,
  pods: [{
    ns: "default",
    name: "api-7d4b9",
    phase: "Running",
    ready: "1/1",
    restarts: 1,
    node: "kiri-k8s",
    created: "2026-11-25T10:00:00Z",
    containers: [{ name: "api", image: "app:1", state: "running", ready: true, restarts: 1 }],
  }],
  services: [],
});

show("pods");
openPod("default/api-7d4b9", "logs");
const key = "default/api-7d4b9/api";
kiri.on({
  type: "k8slogs",
  key,
  parts: [
    { t: "2026-11-25T10:00:01Z INFO boot ready\r\n2026-11-25T10:00:02Z WARN slow query\n", e: false },
    { t: "2026-11-25T10:00:03Z ERROR connection dropped\n", e: true },
  ],
});

t("pod logs render in .console.numbered with line numbers, level classes, and count", () => {
  const klog = document.querySelector("#dbody .console.numbered");
  if (!klog) throw new Error("missing .console.numbered on pod logs");
  const rows = [...klog.children];
  eq(rows.map((r) => r.dataset.n), ["1", "2", "3"], "line numbers");
  eq([rows[1].className, rows[2].className], ["lvl-warn", "lvl-error"], "level classes");
  eq(document.querySelector("#klog-count")?.textContent, tr("{all} lines", { all: "3" }), "line count");
});

t("selecting pod logs omits line numbers", () => {
  const klog = document.querySelector("#dbody .console.numbered");
  getSelection().selectAllChildren(klog);
  eq(
    getSelection().toString().trim().split("\n"),
    ["2026-11-25T10:00:01Z INFO boot ready", "2026-11-25T10:00:02Z WARN slow query", "2026-11-25T10:00:03Z ERROR connection dropped"],
    "copied lines",
  );
  getSelection().removeAllRanges();
});

t("filtering and clearing pod logs share uniform behavior and reset numbering", () => {
  const klog = document.querySelector("#dbody .console.numbered");
  const filter = document.querySelector("#klog-filter");
  filter.value = "warn";
  filter.dispatchEvent(new Event("input", { bubbles: true }));
  const visible = [...klog.children].filter((r) => !r.classList.contains("hide"));
  eq(visible.map((r) => r.dataset.n), ["2"], "filtered visible line");
  filter.value = "";
  filter.dispatchEvent(new Event("input", { bubbles: true }));

  document.querySelector("[data-klogclear]").click();
  eq(klog.childElementCount, 0, "cleared");
  kiri.on({ type: "k8slogs", key, parts: [{ t: "restarted line\n", e: false }] });
  eq(klog.firstElementChild?.dataset.n, "1", "restarted line number");
});

report(R);
