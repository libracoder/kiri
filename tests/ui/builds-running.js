// A running build's steps are asked again on each 2 s tick, but one ask at a
// time: each reads the build's log for a moment, and asking every tick left a
// log reader running per ask (#923).
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const at = new Date(Date.now() - 60e3).toISOString();
const running = { builder: "kiri", id: "b1", name: "api", status: "Running", started: at, completed: null, steps: 9, done: 3, cached: 1 };
const asks = () => sent.filter((s) => s.type === "build" && s.id === "b1").length;
show("builds");
kiri.on({ type: "builds", builds: [running] });
t("picking the running build asks for its steps", () => eq(asks(), 1, "asks"));
t("ticks while that ask is out ask nothing more", () => {
  kiri.on({ type: "builds", builds: [running] });
  kiri.on({ type: "builds", builds: [running] });
  eq(asks(), 1, "asks");
});
t("once the steps come, the next tick asks again", () => {
  kiri.on({ type: "build", builder: "kiri", id: "b1", name: "api", status: "Running", started: at, steps: [], warnings: [] });
  kiri.on({ type: "builds", builds: [running] });
  eq(asks(), 2, "asks");
});
t("an error answer counts as the answer", () => {
  kiri.on({ type: "build", builder: "kiri", id: "b1", error: { message: "boom" }, steps: [], failed: true });
  kiri.on({ type: "builds", builds: [running] });
  eq(asks(), 3, "asks");
});
t("the build finishing is asked about at once, ask or no ask", () => {
  kiri.on({ type: "builds", builds: [{ ...running, status: "Completed", completed: new Date().toISOString() }] });
  eq(asks(), 4, "asks");
});
report(R);
