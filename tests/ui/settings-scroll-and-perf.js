// Settings keeps its left tab rail static while the pane body scrolls, preserves
// body scroll across live redraws on the same tab, resets on tab switch, and
// keeps UI responsiveness helpers (log counts, diag selection, floating tips)
// accurate without idle requestAnimationFrame loops.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };

show("settings");
document.querySelector('[data-stab="appearance"]').click();

t("Settings left tab rail stays static while the body scrolls", () => {
  const tabs = document.querySelector(".settings .tabs");
  const body = document.querySelector(".settings-body");
  const heading = body?.querySelector(".pane h3");
  if (!tabs || !body || !heading) throw new Error("missing .settings .tabs or .settings-body");
  const tabsTop0 = tabs.getBoundingClientRect().top;
  const headTop0 = heading.getBoundingClientRect().top;
  body.scrollTop = 180;
  if (body.scrollTop < 80) throw new Error(`Appearance body did not scroll (scrollTop=${body.scrollTop}, scrollHeight=${body.scrollHeight}, clientHeight=${body.clientHeight})`);
  const tabsTop1 = tabs.getBoundingClientRect().top;
  const headTop1 = heading.getBoundingClientRect().top;
  if (Math.abs(tabsTop1 - tabsTop0) > 0.5) throw new Error(`tabs moved from ${tabsTop0} to ${tabsTop1}`);
  if (headTop1 >= headTop0 - 40) throw new Error(`pane heading did not scroll (${headTop0} -> ${headTop1})`);
});

t("Settings preserves body scroll on live redraws and resets on tab switch", () => {
  const body0 = document.querySelector(".settings-body");
  body0.scrollTop = 140;
  const kept = body0.scrollTop;
  // Trigger a live update on the same tab (Appearance).
  kiri.on({ type: "shellpath", supported: true, enabled: true });
  const body1 = document.querySelector(".settings-body");
  if (Math.abs(body1.scrollTop - kept) > 1) throw new Error(`same-tab redraw lost scroll (${kept} -> ${body1.scrollTop})`);
  // Switching tabs resets body scroll to 0.
  document.querySelector('[data-stab="kubernetes"]').click();
  const body2 = document.querySelector(".settings-body");
  if (body2.scrollTop !== 0) throw new Error(`tab switch kept old scrollTop=${body2.scrollTop}`);
});

t("Settings RTL places static tabs on inline-start and body beside them", () => {
  document.documentElement.dir = "rtl";
  try {
    render();
    const tabs = document.querySelector(".settings .tabs").getBoundingClientRect();
    const pane = document.querySelector(".settings .pane").getBoundingClientRect();
    if (pane.right > tabs.left + 1) throw new Error(`RTL pane (${pane.left}..${pane.right}) overlaps tabs (${tabs.left}..${tabs.right})`);
  } finally {
    document.documentElement.dir = "ltr";
    render();
  }
});

t("Log console O(1) visible count stays exact across filters and LOG_MAX trims", () => {
  const el = makeLogConsole();
  const countHost = document.createElement("span");
  countHost.id = "perf-log-count";
  document.body.append(countHost);
  try {
    let n = 0;
    const partial = { false: "", true: "" };
    const state = { logFilter: "match", logLevel: "", follow: false };
    const lines = Array.from({ length: LOG_MAX + 25 }, (_, i) => (i % 5 === 0 ? `INFO match-${i}` : `INFO other-${i}`)).join("\n") + "\n";
    appendLogParts(el, "perf-log-count", state, partial, () => ++n, [{ e: false, t: lines }]);
    const domVisible = [...el.children].filter((x) => !x.classList.contains("hide")).length;
    if (el.childElementCount !== LOG_MAX) throw new Error(`expected ${LOG_MAX} children, got ${el.childElementCount}`);
    if (el._shown !== domVisible) throw new Error(`_shown=${el._shown} !== domVisible=${domVisible}`);
    state.logFilter = "";
    state.logLevel = "error";
    applyLogFilter(el, "perf-log-count", state);
    if (el._shown !== 0) throw new Error(`expected 0 error lines, got ${el._shown}`);
    clearLogConsole(el, "perf-log-count", state, partial, () => { n = 0; });
    if (el._shown !== 0 || el.childElementCount !== 0) throw new Error("clearLogConsole did not reset _shown");
  } finally {
    countHost.remove();
  }
});

t("Diagnostics log preserves active text selection across background polls and morphs unchanged rows", () => {
  show("settings");
  document.querySelector('[data-stab="diagnostics"]').click();
  kiri.on({
    type: "diaglogs",
    part: "",
    op: "",
    lines: [
      { time: "2026-11-26T07:00:01.000Z", level: "info", part: "daemon", msg: "first line" },
      { time: "2026-11-26T07:00:02.000Z", level: "warn", part: "ui", msg: "second line" },
    ],
  });
  const log = document.getElementById("dg-log");
  const firstRow = log.firstElementChild;
  if (!firstRow || log.childElementCount !== 2) throw new Error(`expected 2 initial diagnostics rows, got ${log.childElementCount}`);
  const range = document.createRange();
  range.selectNodeContents(firstRow);
  const sel = getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
  // While text is selected inside #dg-log, a background poll updates count without wiping selection.
  kiri.on({
    type: "diaglogs",
    part: "",
    op: "",
    lines: [
      { time: "2026-11-26T07:00:01.000Z", level: "info", part: "daemon", msg: "first line" },
      { time: "2026-11-26T07:00:02.000Z", level: "warn", part: "ui", msg: "second line" },
      { time: "2026-11-26T07:00:03.000Z", level: "error", part: "daemon", msg: "third line" },
    ],
  });
  if (log.childElementCount !== 2 || !firstRow.isConnected || sel.isCollapsed) {
    sel.removeAllRanges();
    throw new Error("selection or DOM rows were wiped during active selection");
  }
  sel.removeAllRanges();
  drawDiagLog();
  if (log.childElementCount !== 3) throw new Error(`expected 3 rows after selection cleared, got ${log.childElementCount}`);
  if (log.firstElementChild !== firstRow) throw new Error("unchanged first row was destroyed instead of morphed");
});

t("Idle floating popovers do not spin requestAnimationFrame continuously", () => {
  const nowS = Date.now() / 1000;
  kiri.on({ type: "lists", containers: [], images: [{ Id: "sha256:" + "1".repeat(64), RepoTags: ["postgres:17"], Size: 1e8, Created: nowS }], volumes: [], networks: [] });
  show("images");
  let rafCalls = 0;
  const origRaf = window.requestAnimationFrame;
  window.requestAnimationFrame = (cb) => { rafCalls++; return origRaf(cb); };
  try {
    document.querySelector('[data-run="postgres:17"]').click();
    if (!document.querySelector(".need")) throw new Error("need popover did not open");
    rafCalls = 0;
    needPlace();
    if (rafCalls !== 0) throw new Error(`needPlace scheduled ${rafCalls} recursive rAF calls`);
    needClose();
  } finally {
    window.requestAnimationFrame = origRaf;
  }
});

report(R);
