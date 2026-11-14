// A container's log can be selected and copied, without the line numbers.
kiri.on({ type: "status", version: "0.1.4", dev: true, app: "Kiri Dev", ours: "kiri-dev", context: "kiri-dev" });
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
show("containers"); openDetail("a1"); setTab("logs"); render();
kiri.on({ type: "logs", id: "a1", parts: [{ e: false, t: "[INFO] Started worker-1\n" }, { e: true, t: "ERROR: engine failed\n" }] });
t("selecting the log copies its lines, without the numbers", () => {
  const log = document.querySelector(".console.numbered");
  getSelection().selectAllChildren(log);
  eq(getSelection().toString().trim().split("\n"), ["[INFO] Started worker-1", "ERROR: engine failed"], "copied");
});
t("the copy key sends the selected log to the clipboard", () => {
  const log = document.querySelector(".console.numbered");
  getSelection().selectAllChildren(log);
  sent.length = 0;
  log.dispatchEvent(new KeyboardEvent("keydown", { key: "c", metaKey: true, bubbles: true }));
  const copies = sent.filter((m) => m.cmd === "term" && m.name === "copy");
  eq(copies.length, 1, "copies sent");
  eq(copies[0].value.trim().split("\n"), ["[INFO] Started worker-1", "ERROR: engine failed"], "text");
});
t("the copy key leaves text fields and an empty selection alone", () => {
  sent.length = 0;
  getSelection().removeAllRanges();
  document.body.dispatchEvent(new KeyboardEvent("keydown", { key: "c", metaKey: true, bubbles: true }));
  const field = document.querySelector("input");
  getSelection().selectAllChildren(document.querySelector(".console.numbered"));
  field.dispatchEvent(new KeyboardEvent("keydown", { key: "c", metaKey: true, bubbles: true }));
  eq(sent.filter((m) => m.cmd === "term" && m.name === "copy").length, 0, "copies sent");
});
report(R);
