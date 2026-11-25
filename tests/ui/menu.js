// Right-click: never opens the browser's menu (Search with Google, Look Up,
// Translate, Reload…); Kiri draws its own app menu (#app-ctx) with only editing
// actions (Copy on selected text, Cut / Copy / Paste / Select All in fields).
kiri.on({ type: "status", version: "0.1.4", dev: true, app: "Kiri Dev", ours: "kiri-dev", context: "kiri-dev" });
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const menu = (el) => { const ev = new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: 120, clientY: 120 }); el.dispatchEvent(ev); return !ev.defaultPrevented; };
const ctxLabels = () => [...$("app-ctx").querySelectorAll("[data-ctx]")].map((b) => [b.dataset.ctx, b.disabled]);

t("no browser or app menu on unselected UI", () => {
  getSelection().removeAllRanges();
  show("images");
  eq(menu($("content")), false, "browser menu prevented");
  eq($("app-ctx").hidden, true, "app menu stays hidden");
});

t("selected log text opens Kiri's Copy-only menu (no browser Search with Google)", () => {
  sent.length = 0;
  const p = document.createElement("p");
  p.textContent = "2026-11-20 10:14:34.716 UTC starting: time";
  p.style.userSelect = p.style.webkitUserSelect = "text";
  document.body.append(p);
  getSelection().selectAllChildren(p);
  eq(menu(p), false, "browser menu prevented");
  eq($("app-ctx").hidden, false, "app menu shown");
  eq(ctxLabels(), [["copy", false]], "only Copy shown");
  eq($("app-ctx").textContent.includes("Google"), false, "never mentions Google");
  $("app-ctx").querySelector('[data-ctx="copy"]').click();
  eq($("app-ctx").hidden, true, "menu closes on click");
  eq(sent.at(-1), { type: "term", cmd: "term", name: "copy", value: "2026-11-20 10:14:34.716 UTC starting: time" }, "copied through native bridge");
  getSelection().removeAllRanges();
  p.remove();
});

t("a text field gets Kiri's Cut, Copy, Paste and Select All menu", () => {
  sent.length = 0;
  const i = document.createElement("input");
  i.value = "hello world";
  document.body.append(i);
  i.focus();
  i.setSelectionRange(0, 5);
  eq(menu(i), false, "browser menu prevented");
  eq($("app-ctx").hidden, false, "app menu shown");
  eq(ctxLabels(), [["cut", false], ["copy", false], ["paste", false], ["selectall", false]], "field actions");
  $("app-ctx").querySelector('[data-ctx="cut"]').click();
  eq(i.value, " world", "Cut removes selection");
  eq(sent.at(-1), { type: "term", cmd: "term", name: "copy", value: "hello" }, "Cut copies selection");
  menu(i);
  $("app-ctx").querySelector('[data-ctx="paste"]').click();
  eq(sent.at(-1), { type: "term", cmd: "term", name: "paste", id: "__field" }, "Paste asks native clipboard");
  kiri.on({ type: "term", ev: "paste", id: "__field", text: "kiri\nlogs" });
  eq(i.value, "kiri logs world", "Paste inserts sanitized single-line text");
  i.remove();
});

t("number and email inputs support Cut, Copy and Paste without setRangeText InvalidStateError", () => {
  sent.length = 0;
  const n = document.createElement("input");
  n.type = "number";
  n.value = "8080";
  document.body.append(n);
  eq(menu(n), false, "browser menu prevented on number input");
  $("app-ctx").querySelector('[data-ctx="cut"]').click();
  eq(n.value, "", "Cut clears number input safely");
  eq(sent.at(-1), { type: "term", cmd: "term", name: "copy", value: "8080" }, "Cut copied number value");
  menu(n);
  $("app-ctx").querySelector('[data-ctx="paste"]').click();
  kiri.on({ type: "term", ev: "paste", id: "__field", text: "9090" });
  eq(n.value, "9090", "Paste updates number input safely");
  n.remove();
});

report(R);
