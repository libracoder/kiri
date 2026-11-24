// Settings -> Resources: Disk image size slider on macOS (bounds, save
// round-trip, pending restart notice) and clean omission when absent.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, what) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`); };

kiri.on({
  type: "resources",
  cpus: 4,
  memory_mib: 8192,
  disk_gb: 128,
  running_cpus: 4,
  running_memory_mib: 8192,
  running_disk_gb: 128,
  awake: true,
  max_cpus: 12,
  max_memory_mib: 32768,
  min_disk_gb: 128,
  max_disk_gb: 1024,
  overridden: false,
});
prefs.tab = "resources";
show("settings");

t("Disk slider renders beside tabs with current size as min (no shrink)", () => {
  const tabs = document.querySelector(".settings .tabs").getBoundingClientRect();
  const slider = document.getElementById("res-disk");
  if (!slider) throw new Error("missing #res-disk");
  const r = slider.getBoundingClientRect();
  if (r.left < tabs.right) throw new Error(`res-disk starts at ${Math.round(r.left)}, under the tabs`);
  eq(slider.min, "128", "min");
  eq(slider.max, "1024", "max");
  eq(slider.value, "128", "value");
  eq(document.getElementById("res-disk-v").textContent, "128 GB", "label");
  eq(document.getElementById("res-save").disabled, true, "save initially disabled");
  if (document.getElementById("res-restart")) throw new Error("no restart button when running matches saved");
});

t("Raising disk slider enables Save and posts disk_gb in setresources", () => {
  const slider = document.getElementById("res-disk");
  slider.value = "256";
  slider.dispatchEvent(new Event("input", { bubbles: true }));
  eq(document.getElementById("res-disk-v").textContent, "256 GB", "updated label");
  eq(document.getElementById("res-save").disabled, false, "save enabled");
  const before = sent.length;
  document.getElementById("res-save").click();
  const msg = sent.slice(before).find((m) => m.cmd === "setresources");
  if (!msg) throw new Error("setresources not sent");
  eq(msg.value, { cpus: 4, memory_mib: 8192, disk_gb: 256 }, "setresources payload");
});

t("Pending disk growth while awake offers Restart VM to apply", () => {
  kiri.on({
    type: "resources",
    cpus: 4,
    memory_mib: 8192,
    disk_gb: 256,
    running_cpus: 4,
    running_memory_mib: 8192,
    running_disk_gb: 128,
    awake: true,
    max_cpus: 12,
    max_memory_mib: 32768,
    min_disk_gb: 128,
    max_disk_gb: 1024,
    overridden: true,
  });
  if (!document.getElementById("res-restart")) throw new Error("missing Restart VM button");
  const text = document.querySelector(".settings").textContent;
  if (!text.includes("KIRI_DISK_GB")) throw new Error("overridden notice should mention KIRI_DISK_GB");
  if (!text.includes("128 GB")) throw new Error("running footer should show current running disk size");
});

t("When disk_gb is absent (Linux/Windows), disk slider is hidden and Save omits disk_gb", () => {
  kiri.on({
    type: "resources",
    cpus: 4,
    memory_mib: 8192,
    running_cpus: 4,
    running_memory_mib: 8192,
    awake: false,
    max_cpus: 12,
    max_memory_mib: 32768,
    overridden: false,
  });
  if (document.getElementById("res-disk")) throw new Error("res-disk should not render without disk_gb");
  const cpuSlider = document.getElementById("res-cpus");
  cpuSlider.value = "6";
  cpuSlider.dispatchEvent(new Event("input", { bubbles: true }));
  const before = sent.length;
  document.getElementById("res-save").click();
  const msg = sent.slice(before).find((m) => m.cmd === "setresources");
  eq(msg.value, { cpus: 6, memory_mib: 8192 }, "payload without disk_gb");
});

report(R);
