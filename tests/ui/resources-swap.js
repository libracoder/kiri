// Settings -> Resources: the VM's swap slider on macOS (#326): its range and
// labels, the save, the restart notice, and no slider where the host has
// its own swap (no swap_mib).
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, what) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`); };
const res = (extra) => kiri.on({
  type: "resources",
  cpus: 4,
  memory_mib: 8192,
  running_cpus: 4,
  running_memory_mib: 8192,
  awake: true,
  max_cpus: 12,
  max_memory_mib: 32768,
  overridden: false,
  ...extra,
});
const slide = (v) => {
  const s = document.getElementById("res-swap");
  s.value = String(v);
  s.dispatchEvent(new Event("input", { bubbles: true }));
};
const saved = () => {
  const before = sent.length;
  document.getElementById("res-save").click();
  const msg = sent.slice(before).find((m) => m.cmd === "setresources");
  if (!msg) throw new Error("setresources not sent");
  return msg.value;
};

res({ swap_mib: 1024, running_swap_mib: 1024, max_swap_mib: 16384 });
prefs.tab = "resources";
show("settings");

t("The swap slider shows the VM's swap, from none to the most", () => {
  const s = document.getElementById("res-swap");
  if (!s) throw new Error("missing #res-swap");
  eq([s.min, s.max, s.step, s.value], ["0", "16384", "512", "1024"], "min, max, step, value");
  eq(document.getElementById("res-swap-v").textContent, "1 GB", "label");
  eq(document.getElementById("res-save").disabled, true, "nothing to save yet");
  if (document.getElementById("res-restart")) throw new Error("no restart while the VM has what is saved");
});

t("Half gigabytes and none read as such", () => {
  slide(1536);
  eq(document.getElementById("res-swap-v").textContent, "1.5 GB", "1536 MiB");
  slide(0);
  eq(document.getElementById("res-swap-v").textContent, "Off", "0");
});

t("Moving it enables Save and sends swap_mib with the rest", () => {
  slide(4096);
  eq(document.getElementById("res-save").disabled, false, "save enabled");
  eq(saved(), { cpus: 4, memory_mib: 8192, swap_mib: 4096 }, "setresources payload");
});

t("A saved swap the VM doesn't have yet offers the restart", () => {
  res({ swap_mib: 4096, running_swap_mib: 1024, max_swap_mib: 16384 });
  if (!document.getElementById("res-restart")) throw new Error("missing Restart VM button");
});

t("Without swap_mib (Linux, Windows) there is no slider, and Save sends none", () => {
  res({});
  if (document.getElementById("res-swap")) throw new Error("res-swap should not render without swap_mib");
  const cpus = document.getElementById("res-cpus");
  cpus.value = "6";
  cpus.dispatchEvent(new Event("input", { bubbles: true }));
  eq(saved(), { cpus: 6, memory_mib: 8192 }, "payload without swap_mib");
});

report(R);
