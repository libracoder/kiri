// parity: macos windows linux
// The first start's language step as one searchable list: a search field,
// then Suggested (the system's language first, the system's other languages,
// then a few common ones up to five) and every language by its English name.
// A search finds a language by its own name, its English name or its code,
// whatever the accents; Up/Down move, Enter picks; Arabic reads from the
// right; Continue and Escape both close and keep the pick.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const dlg = () => document.querySelector('[aria-labelledby="lang-title"]');
const q = () => document.getElementById("lang-q");
const list = () => dlg()?.querySelector('[role="listbox"]');
const rows = (sel = "") => [...(list()?.querySelectorAll(`${sel} [role="option"]`.trim()) || [])];
const ids = (sel) => rows(sel).map((r) => r.dataset.lang);
const groups = () => [...(list()?.querySelectorAll('[role="group"]') || [])];
const type = (s) => { q().value = s; q().dispatchEvent(new Event("input", { bubbles: true })); };
const key = (k) => q().dispatchEvent(new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
const active = () => document.getElementById(q().getAttribute("aria-activedescendant") || "-")?.dataset.lang;
const picked = () => [...new Set(rows().filter((r) => r.getAttribute("aria-selected") === "true").map((r) => r.dataset.lang))];
const saved = (name) => sent.filter((m) => m.type === "setpref" && m.name === name).at(-1)?.value;
const box = (el) => el.getBoundingClientRect();
const ITEMS = [];

// An English system that also lists German and Portuguese (Portugal).
window.KIRI_LANG.os = ["en-US", "de-DE", "pt-PT"];
setPref("lang", "system");
sent.length = 0;
kiri.on({ type: "langpick" });
ITEMS.push(...[...(dlg()?.querySelectorAll("input, [role=listbox], [role=group], button") || [])].map((e) => `language step: ${e.tagName.toLowerCase()} ${e.id || e.getAttribute("aria-labelledby") || ""}`.trim()));

t("a search field, focused, then one list", () => {
  if (!dlg()) throw new Error("no language step");
  if (!q() || document.activeElement !== q()) throw new Error("the search field doesn't have focus: " + document.activeElement?.tagName);
  if (q().placeholder !== "Search languages" || q().getAttribute("aria-label") !== "Search languages") throw new Error(`placeholder ${q().placeholder}, label ${q().getAttribute("aria-label")}`);
  if (!list() || list().getAttribute("role") !== "listbox") throw new Error("no listbox");
  if (dlg().querySelector(".choices, [role=radio]")) throw new Error("the tiles are still there");
  if (!(box(q()).bottom <= box(list()).top)) throw new Error("the search field isn't above the list");
});
t("Suggested: the system's language first, its other languages, then up to five", () => {
  const [sug, all] = groups();
  if (sug?.querySelector(".lsect")?.textContent !== "Suggested") throw new Error("first section: " + sug?.querySelector(".lsect")?.textContent);
  const got = ids(`#${sug.id}`).join(" ");
  if (got !== "en de pt-BR es fr") throw new Error("suggested: " + got);
  if (all?.querySelector(".lsect")?.textContent !== "All languages · 38") throw new Error("second section: " + all?.querySelector(".lsect")?.textContent);
});
t("All languages: every one, by its English name", () => {
  const all = groups()[1];
  const got = rows(`#${all.id}`);
  if (got.length !== 38 || new Set(got.map((r) => r.dataset.lang)).size !== 38) throw new Error(got.length + " rows");
  const names = got.map((r) => (r.querySelector(".le") || r.querySelector(".ln")).textContent);
  const sorted = [...names].sort((a, b) => a.localeCompare(b, "en"));
  if (names.join() !== sorted.join()) throw new Error("not sorted: " + names.join(", "));
  if (names[0] !== "Albanian" || got[0].dataset.lang !== "sq") throw new Error("first: " + names[0]);
});
t("a row: its own name in its language, its English name, its hello, a check on the one picked", () => {
  const de = list().querySelector('[data-lang="de"]');
  if (de.querySelector(".ln").getAttribute("lang") !== "de" || de.querySelector(".ln").textContent !== "Deutsch") throw new Error(de.outerHTML);
  if (de.querySelector(".le").textContent !== "German" || de.querySelector(".lh").textContent !== "Hallo") throw new Error(de.textContent);
  const ar = list().querySelector('[data-lang="ar"]');
  if (ar.querySelector(".ln").getAttribute("lang") !== "ar" || ar.querySelector(".ln").textContent !== "العربية" || ar.querySelector(".le").textContent !== "Arabic") throw new Error(ar.textContent);
  if (list().querySelector('[data-lang="en"] .le')) throw new Error("English shows its English name twice");
  if (picked().join() !== "en") throw new Error("picked: " + picked());
  const ck = list().querySelector('[data-lang="en"] .lck');
  if (!ck || getComputedStyle(ck).visibility !== "visible") throw new Error("no check on English");
  if (getComputedStyle(de.querySelector(".lck")).visibility === "visible") throw new Error("a check on German");
  if (!(box(de.querySelector(".lh")).left > box(de.querySelector(".ln")).right)) throw new Error("the hello isn't on the end side");
});
t("the system's language is marked Same as the system", () => {
  const marks = rows().filter((r) => r.querySelector(".sys")).map((r) => r.dataset.lang);
  if ([...new Set(marks)].join() !== "en") throw new Error("marked: " + marks);
  if (list().querySelector('[data-lang="en"] .sys').textContent !== `Same as ${OS}`) throw new Error(list().querySelector('[data-lang="en"] .sys').textContent);
});

for (const s of ["german", "deu", "de", "GERMAN", "Deutsch"]) t(`a search for "${s}" finds Deutsch, first`, () => {
  type(s);
  if (ids()[0] !== "de") throw new Error(`"${s}" found ${ids().join(" ")}`);
  if (groups().length) throw new Error("still in sections");
});
t("accents don't matter: portugues, cestina, turkce", () => {
  for (const [s, id] of [["portugues", "pt-BR"], ["cestina", "cs"], ["turkce", "tr"], ["Portugués", "pt-BR"]]) {
    type(s);
    if (ids()[0] !== id) throw new Error(`"${s}" found ${ids().join(" ")}`);
  }
});
t("a search in another script: русский, 日本", () => {
  for (const [s, id] of [["русский", "ru"], ["日本", "ja"], ["chinese", "zh-Hans"]]) {
    type(s);
    if (ids()[0] !== id) throw new Error(`"${s}" found ${ids().join(" ")}`);
  }
  type("chinese");
  if (ids().join(" ") !== "zh-Hans zh-Hant") throw new Error("chinese found " + ids().join(" "));
});
t("nothing found says so", () => {
  type("klingon");
  if (rows().length) throw new Error(rows().length + " rows");
  const none = list().querySelector(".lnone")?.textContent;
  if (none !== "No language matches. Try its English name.") throw new Error("message: " + none);
  key("Enter");
  if (saved("lang") !== undefined) throw new Error("Enter picked " + saved("lang"));
});
t("clearing the search brings the sections back", () => {
  type("");
  if (groups().length !== 2 || rows().length !== 43) throw new Error(`${groups().length} sections, ${rows().length} rows`);
});

t("Up and Down move through the rows, from the one picked", () => {
  if (active() !== "en") throw new Error("starts on " + active());
  key("ArrowDown"); key("ArrowDown");
  if (active() !== "pt-BR") throw new Error("two down is " + active());
  key("ArrowUp");
  if (active() !== "de") throw new Error("one up is " + active());
  if (!document.getElementById(q().getAttribute("aria-activedescendant")).classList.contains("act")) throw new Error("the row doesn't show it");
  if (saved("lang") !== undefined) throw new Error("moving picked " + saved("lang"));
});
t("Enter picks it: the window switches and saves it", () => {
  key("Enter");
  if (saved("lang") !== "de" || document.documentElement.lang !== "de") throw new Error(`saved ${saved("lang")}, lang ${document.documentElement.lang}`);
  if (picked().join() !== "de") throw new Error("picked: " + picked());
  if (dlg().querySelector("#lang-title").textContent !== STRINGS.de["Choose your language"]) throw new Error(dlg().querySelector("#lang-title").textContent);
  if (q().placeholder !== STRINGS.de["Search languages"] || groups()[0].querySelector(".lsect").textContent !== STRINGS.de["Suggested"]) throw new Error("the step's own words stayed English");
  if (document.activeElement !== q()) throw new Error("focus left the search field");
});
t("typing filters and Enter picks the first match", () => {
  type("fran");
  if (active() !== "fr") throw new Error("active " + active());
  key("Enter");
  if (saved("lang") !== "fr" || document.documentElement.lang !== "fr") throw new Error(`saved ${saved("lang")}, lang ${document.documentElement.lang}`);
  if (q().value !== "fran" || ids().join() !== "fr") throw new Error("the search went: " + q().value);
});
t("a click picks too, and the system's own row saves System", () => {
  type("");
  list().querySelector('[data-lang="en"]').click();
  if (saved("lang") !== "system" || document.documentElement.lang !== "en") throw new Error(`saved ${saved("lang")}, lang ${document.documentElement.lang}`);
  if (document.activeElement !== q()) throw new Error("focus left the search field");
});

t("Arabic reads from the right", () => {
  type("arabic"); key("Enter");
  const root = document.documentElement;
  if (root.lang !== "ar" || root.dir !== "rtl") throw new Error(`lang ${root.lang}, dir ${root.dir}`);
  type("");
  const de = list().querySelector('[data-lang="de"]');
  if (!(box(de.querySelector(".ln")).left > box(de.querySelector(".lh")).right)) throw new Error("German's hello isn't on the left");
  if (!(box(de.querySelector(".ln")).left - box(de.querySelector(".le")).right >= 4)) throw new Error("German's English name isn't after it, on the left, with a gap");
  const en = list().querySelector('[data-lang="en"]');
  if (!(box(en.querySelector(".ln")).left - box(en.querySelector(".sys")).right >= 4)) throw new Error("Same as the system isn't after English, on the left, with a gap");
  const icon = q().parentElement.querySelector("svg");
  if (!(box(icon).left > box(q()).left)) throw new Error("the search icon isn't on the right");
  const head = groups()[0].querySelector(".lsect");
  if (head.textContent !== STRINGS.ar["Suggested"]) throw new Error(head.textContent);
  const r = document.createRange(); r.selectNodeContents(head);
  if (!(box(head).right - r.getBoundingClientRect().right < 20)) throw new Error("Suggested isn't on the right");
  if (!(box(document.getElementById("lang-go")).left < box(dlg().querySelector(".lfoot p")).left)) throw new Error("Continue isn't on the left");
});
t("Kurdish and Persian read from the right too", () => {
  for (const s of ["kurdish", "persian"]) {
    type(s); key("Enter");
    if (document.documentElement.dir !== "rtl") throw new Error(s + ": " + document.documentElement.dir);
  }
});

type("german"); key("Enter");
dlg().querySelector("#lang-go").click();
t("Continue closes and keeps the pick", () => {
  if (dlg()) throw new Error("still open");
  if (saved("langAsked") !== true) throw new Error("langAsked " + saved("langAsked"));
  if (document.documentElement.lang !== "de" || saved("lang") !== "de") throw new Error(`lang ${document.documentElement.lang}, saved ${saved("lang")}`);
});

// Opened again with a pick far down the list: that row is in view.
setPref("lang", "lo");
kiri.on({ type: "langpick" });
t("the picked row is scrolled into view on open", () => {
  const lo = list().querySelector('[data-lang="lo"]');
  const l = box(list()), r = box(lo);
  if (lo.getAttribute("aria-selected") !== "true") throw new Error("Lao isn't picked");
  if (!(r.top >= l.top && r.bottom <= l.bottom)) throw new Error(`row ${r.top}-${r.bottom}, list ${l.top}-${l.bottom}`);
  if (active() !== "lo") throw new Error("active " + active());
});
sent.length = 0;
type("ital"); key("Enter");
document.activeElement.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
t("Escape closes as Continue does, keeping the pick", () => {
  if (dlg()) throw new Error("still open");
  if (saved("langAsked") !== true) throw new Error("langAsked " + saved("langAsked"));
  if (document.documentElement.lang !== "it" || saved("lang") !== "it") throw new Error(`lang ${document.documentElement.lang}, saved ${saved("lang")}`);
});

window.KIRI_LANG.os = ["en-US"];
setPref("lang", "system");
report([...R, ...ITEMS.map((i) => "ITEM " + i)]);
