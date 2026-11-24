// Settings → Storage: custom storage location, native picker command, move vs
// start fresh confirmation, progress, old-data cleanup, and unavailable drive banner.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const last = (cmd) => sent.filter((m) => m.type === cmd).at(-1);

t("Settings → Storage tab asks for storage status and renders default location", () => {
  show("settings");
  const tab = document.querySelector('[data-stab="storage"]');
  if (!tab) throw new Error("missing Storage tab");
  tab.click();
  if (!last("storage")) throw new Error("didn't request storage status");
  kiri.on({
    type: "storage",
    path: "/Users/me/Library/Application Support/Kiri",
    default: "/Users/me/Library/Application Support/Kiri",
    custom: false,
    env: false,
    state: "ok",
    used: 4_200_000_000,
    free: 120_000_000_000,
    fs: "apfs",
    moving: null,
    error: null,
    old: null,
  });
  const pane = document.querySelector(".settings .pane");
  if (!pane.textContent.includes("/Users/me/Library/Application Support/Kiri")) throw new Error("missing path");
  if (!pane.querySelector(".st-badge")?.textContent.includes("Default")) throw new Error("missing Default badge");
  if (pane.querySelector("[data-streset]")) throw new Error("Reset to default shouldn't show on default path");
  if (!pane.querySelector("[data-stpick]")) throw new Error("missing Change… button");
});

t("Change… sends storagepick, validation error renders cleanly", () => {
  document.querySelector("[data-stpick]").click();
  if (!last("storagepick")) throw new Error("didn't send storagepick");
  kiri.on({ type: "storagecheck", path: "/Volumes/FAT/kiri", error: "/Volumes/FAT/kiri is on a exFAT drive, which can't hold Kiri's data" });
  const err = document.querySelector(".st-box.err");
  if (!err || !err.textContent.includes("exFAT")) throw new Error("missing validation error");
  err.querySelector("[data-sterrclose]").click();
  if (document.querySelector(".st-box.err")) throw new Error("error didn't dismiss");
});

t("valid storagecheck opens confirmation dialog with move and start fresh modes", () => {
  kiri.on({ type: "storagecheck", path: "/Volumes/SSD/kiri", needed: 5_000_000_000, free: 400_000_000_000, replaces: false, reset: false });
  const dlg = document.getElementById("st-dlg");
  if (!dlg) throw new Error("confirm dialog didn't open");
  if (!dlg.textContent.includes("/Volumes/SSD/kiri")) throw new Error("missing target path");
  const moveOpt = dlg.querySelector('input[name="st-mode"][value="move"]');
  const freshOpt = dlg.querySelector('input[name="st-mode"][value="fresh"]');
  if (!moveOpt?.checked || !freshOpt) throw new Error("missing move/fresh options");
  freshOpt.checked = true;
  freshOpt.dispatchEvent(new Event("change"));
  if (!dlg.querySelector("[data-stgo]").textContent.includes("Start fresh")) throw new Error("primary button didn't update for Start fresh");
  dlg.querySelector("[data-stgo]").click();
  if (document.getElementById("st-dlg")) throw new Error("dialog didn't close");
  const req = last("storagemove");
  if (!req || req.path !== "/Volumes/SSD/kiri" || req.value?.fresh !== true) throw new Error("bad storagemove: " + JSON.stringify(req));
});

t("default move mode sends fresh: false", () => {
  kiri.on({ type: "storagecheck", path: "/Volumes/SSD/kiri", needed: 5_000_000_000, free: 400_000_000_000, replaces: true, reset: false });
  const dlg = document.getElementById("st-dlg");
  if (!dlg.textContent.includes("Existing Kiri data in this folder will be replaced")) throw new Error("missing replaces warning");
  dlg.querySelector("[data-stgo]").click();
  const req = last("storagemove");
  if (!req || req.path !== "/Volumes/SSD/kiri" || req.value?.fresh !== false) throw new Error("bad storagemove: " + JSON.stringify(req));
});

t("moving state shows progress bar and disables action buttons", () => {
  kiri.on({
    type: "storage",
    path: "/Users/me/Library/Application Support/Kiri",
    default: "/Users/me/Library/Application Support/Kiri",
    custom: false,
    env: false,
    state: "moving",
    used: null,
    free: 120_000_000_000,
    fs: "apfs",
    moving: { to: "/Volumes/SSD/kiri", phase: "copying", done: 2_100_000_000, total: 4_200_000_000 },
    error: null,
    old: null,
  });
  const pane = document.querySelector(".settings .pane");
  if (!pane.textContent.includes("Copying data…") || !pane.textContent.includes("50%")) throw new Error("missing copying progress");
  if (!pane.querySelector("[data-stpick]").disabled) throw new Error("Change… should be disabled while moving");
});

t("custom location shows Reset to default and Old data cleanup", () => {
  kiri.on({
    type: "storage",
    path: "/Volumes/SSD/kiri",
    default: "/Users/me/Library/Application Support/Kiri",
    custom: true,
    env: false,
    state: "ok",
    used: 4_200_000_000,
    free: 400_000_000_000,
    fs: "apfs",
    moving: null,
    error: null,
    old: "/Users/me/Library/Application Support/Kiri",
  });
  const pane = document.querySelector(".settings .pane");
  if (pane.querySelector(".st-badge")) throw new Error("Default badge shouldn't show on custom path");
  if (!pane.querySelector("[data-streset]")) throw new Error("missing Reset to default");
  if (!pane.querySelector("[data-strmold]")) throw new Error("missing Remove old data");
  pane.querySelector("[data-streset]").click();
  const chk = last("storagecheck");
  if (!chk || chk.path !== "" || chk.value?.reset !== true) throw new Error("Reset should check default first: " + JSON.stringify(chk));
  pane.querySelector("[data-strmold]").click();
  const go = document.querySelector(".scrim [data-go]");
  if (!go) throw new Error("Remove old data didn't ask to confirm");
  go.click();
  if (!last("storageremoveold")) throw new Error("didn't send storageremoveold");
});

t("KIRI_DATA_DIR override disables changing storage", () => {
  kiri.on({
    type: "storage",
    path: "/custom/env/kiri",
    default: "/Users/me/Library/Application Support/Kiri",
    custom: false,
    env: true,
    state: "ok",
    used: 100_000_000,
    free: 10_000_000_000,
    fs: "apfs",
    moving: null,
    error: null,
    old: null,
  });
  const pane = document.querySelector(".settings .pane");
  if (!pane.querySelector("[data-stpick]").disabled) throw new Error("Change… must be disabled under KIRI_DATA_DIR");
  if (!pane.textContent.includes("KIRI_DATA_DIR")) throw new Error("missing KIRI_DATA_DIR note");
});

t("unavailable storage shows Retry, Change…, and Reset to default in settings and main view", () => {
  kiri.on({
    type: "storage",
    path: "/Volumes/Unplugged/kiri",
    default: "/Users/me/Library/Application Support/Kiri",
    custom: true,
    env: false,
    state: "unavailable",
    used: null,
    free: null,
    fs: null,
    moving: null,
    error: null,
    old: null,
  });
  const warn = document.querySelector(".st-box.warn");
  if (!warn || !warn.textContent.includes("/Volumes/Unplugged/kiri")) throw new Error("missing unavailable banner in settings");
  warn.querySelector("[data-stretry]").click();
  if (!last("storageretry")) throw new Error("Retry didn't send storageretry");
  warn.querySelector("[data-streset]").click();
  const confirmReset = document.querySelector(".scrim [data-go]");
  if (!confirmReset) throw new Error("Reset while unavailable didn't confirm");
  confirmReset.click();
  if (!last("storagereset")) throw new Error("didn't send storagereset");
  show("containers");
  if (!document.getElementById("content").textContent.includes("Storage location unavailable")) throw new Error("main view didn't show unavailable message");
});

report(R);
