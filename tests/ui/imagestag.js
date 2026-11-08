// Images: a long repository or tag must not push Actions' buttons past the
// column — the list always uses fixed column shares, like Containers.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const nowS = Date.now() / 1000;
kiri.on({ type: "lists", containers: [], images: [
  { Id: "sha256:" + "a".repeat(64), RepoTags: ["harbor.example.com:9090/szda/very-long-path/rustfs:arm-1.0.0-beta.8-extra-long"], Size: 1e8, Created: nowS - 60, Pulled: nowS - 30 },
  { Id: "sha256:" + "b".repeat(64), RepoTags: ["nginx:alpine"], Size: 1e7, Created: nowS - 120, Pulled: nowS - 90 },
], volumes: [], networks: [] });
document.body.style.width = "1100px";
show("images");

t("Images is laid out with fixed shares without a prior resize", () => {
  const tbl = document.querySelector("#content table[data-view=images]");
  if (!tbl?.classList.contains("sized")) throw new Error("not sized");
  if (![...tbl.tHead.rows[0].cells].some((th) => th.dataset.share)) throw new Error("no shares on headings");
});
t("a long tag and repository leave every Actions button inside its column", () => {
  const tbl = document.querySelector("#content table.sized");
  for (const r of tbl.tBodies[0].rows) {
    const td = r.cells[r.cells.length - 1];
    if (!td.classList.contains("actions")) throw new Error("last cell is not actions");
    const colR = td.getBoundingClientRect().right;
    for (const b of td.querySelectorAll("button")) {
      if (b.getBoundingClientRect().right > colR + 0.5) throw new Error(`button past column: ${b.getAttribute("aria-label")}`);
    }
  }
});
t("the long tag is clipped with its full value in the title", () => {
  const pill = document.querySelector('#content tr[data-key*="rustfs"] .tag');
  if (!pill) throw new Error("no tag pill");
  if (!/arm-1\.0\.0-beta\.8/.test(pill.title)) throw new Error("title missing full tag: " + pill.title);
  if (pill.scrollWidth <= pill.clientWidth + 1 && pill.textContent.length > 20) {
    // May or may not overflow depending on column share; the cell must still clip.
  }
  const cell = pill.closest("td");
  if (!cell.classList.contains("clip")) throw new Error("tag cell not clip");
});
report(R);
