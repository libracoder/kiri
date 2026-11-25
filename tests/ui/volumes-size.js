// Volumes view: asynchronous Size column loading, formatting, unmeasured
// fallback, cache reuse across view switches, and refresh on volume changes.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, what) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: got ${JSON.stringify(a)}, want ${JSON.stringify(b)}`); };

const vol = (name, secsAgo = 3600) => ({
  Name: name,
  Driver: "local",
  CreatedAt: new Date(Date.now() - secsAgo * 1000).toISOString(),
  Labels: {},
});
const baseVolumes = [vol("empty_vol", 7200), vol("pg_data", 3600), vol("big_cache", 1800), vol("nfs_mount", 900)];
const sendLists = (volumes) => kiri.on({ type: "lists", containers: ui.containers, images: ui.images, volumes, networks: ui.networks });
const volSizeCount = () => sent.filter((m) => m.type === "volumesizes").length;
const sizeText = (name) => {
  const row = document.querySelector(`#content tr[data-key="${name}"]`);
  if (!row) throw new Error(`missing row ${name}`);
  return row.cells[3].textContent.trim();
};

sent.length = 0;
sendLists(baseVolumes);

t("opening Volumes renders all rows immediately with … and requests volumesizes", () => {
  eq(volSizeCount(), 0, "no request before visiting Volumes");
  show("volumes");
  const heads = [...document.querySelectorAll("#content thead th")].map((th) => th.textContent.replace(/[↑↓]/g, "").trim()).filter(Boolean);
  eq(heads, ["Name", "Driver", "Size", "Created", "Actions"], "table headers");
  eq(volSizeCount(), 1, "requested volumesizes once");
  for (const v of baseVolumes) {
    const cell = document.querySelector(`#content tr[data-key="${v.Name}"]`).cells[3];
    if (!cell.classList.contains("muted") || !cell.classList.contains("num")) {
      throw new Error(`Size cell for ${v.Name} missing muted/num classes: ${cell.className}`);
    }
    eq(cell.textContent.trim(), "…", `loading indicator for ${v.Name}`);
  }
});

t("delivering volumesizes updates each row asynchronously with formatted bytes and — for -1", () => {
  kiri.on({
    type: "volumesizes",
    sizes: {
      empty_vol: 0,
      pg_data: 807_700_000,
      big_cache: 3_200_000_000,
      nfs_mount: -1,
    },
  });
  eq(ui.volSizesLoading, false, "loading cleared");
  eq(sizeText("empty_vol"), "0 B", "empty_vol");
  eq(sizeText("pg_data"), "807.7 MB", "pg_data");
  eq(sizeText("big_cache"), "3.2 GB", "big_cache");
  eq(sizeText("nfs_mount"), "—", "nfs_mount unmeasured");
});

t("Size column sorts by measured bytes", () => {
  const th = document.querySelector('#content thead th[data-sort="size"]');
  if (!th) throw new Error("missing sortable Size header");
  th.click();
  const desc = [...document.querySelectorAll("#content tbody tr")].map((r) => r.dataset.key);
  eq(desc, ["big_cache", "pg_data", "empty_vol", "nfs_mount"], "descending by size");
  document.querySelector('#content thead th[data-sort="size"]').click();
  const asc = [...document.querySelectorAll("#content tbody tr")].map((r) => r.dataset.key);
  eq(asc, ["nfs_mount", "empty_vol", "pg_data", "big_cache"], "ascending by size");
});

t("switching away and back within the cache window keeps sizes without re-requesting", () => {
  const before = volSizeCount();
  show("images");
  show("volumes");
  eq(volSizeCount(), before, "cache hit on view switch");
  eq(sizeText("empty_vol"), "0 B", "empty_vol preserved");
  eq(sizeText("pg_data"), "807.7 MB", "pg_data preserved");
  eq(sizeText("big_cache"), "3.2 GB", "big_cache preserved");
  eq(sizeText("nfs_mount"), "—", "nfs_mount preserved");
});

t("periodic lists refresh with unchanged volumes does not spam volumesizes", () => {
  const before = volSizeCount();
  sendLists(baseVolumes);
  eq(volSizeCount(), before, "unchanged volume list stays cached");
  eq(sizeText("pg_data"), "807.7 MB", "pg_data unchanged");
});

t("adding a new volume requests fresh sizes while keeping existing sizes visible", () => {
  const before = volSizeCount();
  const next = [...baseVolumes, vol("fresh_vol", 10)];
  sendLists(next);
  eq(volSizeCount(), before + 1, "new volume triggers volumesizes");
  eq(sizeText("pg_data"), "807.7 MB", "existing volume not blanked");
  eq(sizeText("big_cache"), "3.2 GB", "existing volume not blanked");
  eq(sizeText("fresh_vol"), "…", "new volume shows loading indicator");
  kiri.on({
    type: "volumesizes",
    sizes: {
      empty_vol: 0,
      pg_data: 807_700_000,
      big_cache: 3_200_000_000,
      nfs_mount: -1,
      fresh_vol: 1_500_000,
    },
  });
  eq(sizeText("fresh_vol"), "1.5 MB", "new volume size applied");
});

t("unmeasured response shows — and waking the VM re-requests sizes", () => {
  kiri.on({ type: "state", state: "asleep" });
  ui.volSizesAt = 0;
  const beforeAsleep = volSizeCount();
  show("volumes");
  eq(volSizeCount(), beforeAsleep + 1, "expired cache requests sizes");
  kiri.on({ type: "volumesizes", sizes: {} });
  eq(ui.volSizesLoading, false, "loading cleared after empty response");
  eq(sizeText("pg_data"), "—", "unmeasured while asleep");
  const beforeWake = volSizeCount();
  kiri.on({ type: "state", state: "running" });
  eq(volSizeCount(), beforeWake + 1, "VM wake triggers fresh volumesizes");
  eq(sizeText("pg_data"), "…", "shows loading while fetching after wake");
});

report(R);
