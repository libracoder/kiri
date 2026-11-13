// The first start's language step: a tile for each language, each in its own language, the
// system's marked; a tile switches the whole window at once and is saved
// ("system" for the system's own); Continue (or Escape) saves that it was
// asked, and the welcome that arrived meanwhile waits until then.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const dlg = () => document.querySelector('[aria-labelledby="lang-title"]');
const tilesNow = () => [...(dlg()?.querySelectorAll("[data-lang]") || [])];
const pickTile = (id) => dlg()?.querySelector(`[data-lang="${id}"]`);
const welcomeOpen = () => !!document.querySelector('[aria-labelledby="welcome-title"]');
const saved = (name) => sent.filter((m) => m.type === "setpref" && m.name === name).at(-1)?.value;
const rail = () => document.querySelector("nav [data-view=containers] .lbl").textContent;

kiri.on({ type: "langpick" });
t("a langpick event opens the language step with a tile for each of the 37 languages", () => {
  if (!dlg()) throw new Error("no dialog");
  const ids = tilesNow().map((b) => b.dataset.lang).join(" ");
  if (ids !== "en id ca cs de es fr it lt hu nb pl pt-BR ro sq sl fi vi tr el bg ru uk kk ar fa ckb hi bn ta te th lo ja ko zh-Hans zh-Hant") throw new Error("tiles: " + ids);
});
t("four across, ten down", () => {
  const tops = new Set(tilesNow().map((b) => Math.round(b.getBoundingClientRect().top)));
  const lefts = new Set(tilesNow().map((b) => Math.round(b.getBoundingClientRect().left)));
  if (lefts.size !== 4 || tops.size !== 10) throw new Error(`${lefts.size} columns, ${tops.size} rows`);
});
t("each tile is in its own language, with its own Hello", () => {
  if (pickTile("de").getAttribute("lang") !== "de" || !pickTile("de").textContent.includes("Deutsch") || !pickTile("de").textContent.includes("Hallo")) throw new Error(pickTile("de").textContent);
  if (!pickTile("zh-Hans").textContent.includes("简体中文") || !pickTile("zh-Hans").textContent.includes("你好")) throw new Error(pickTile("zh-Hans").textContent);
  for (const [id, name, hello] of [["ja", "日本語", "こんにちは"], ["ko", "한국어", "안녕하세요"], ["zh-Hant", "繁體中文", "你好"], ["ru", "Русский", "Привет"], ["uk", "Українська", "Привіт"], ["hi", "हिन्दी", "नमस्ते"], ["fa", "فارسی", "سلام"], ["ckb", "کوردیی ناوەندی", "سڵاو"], ["el", "Ελληνικά", "Γεια σου"], ["kk", "Қазақша", "Сәлем"], ["te", "తెలుగు", "నమస్కారం"], ["th", "ไทย", "สวัสดี"], ["lo", "ລາວ", "ສະບາຍດີ"], ["nb", "Norsk bokmål", "Hei"], ["bn", "বাংলা", "নমস্কার"], ["ta", "தமிழ்", "வணக்கம்"], ["ar", "العربية", "مرحبًا"], ["vi", "Tiếng Việt", "Xin chào"], ["id", "Bahasa Indonesia", "Halo"]])
    if (pickTile(id).getAttribute("lang") !== id || !pickTile(id).textContent.includes(name) || !pickTile(id).textContent.includes(hello)) throw new Error(pickTile(id).textContent);
});
t("the system's language is marked and picked", () => {
  const marked = tilesNow().filter((b) => b.querySelector(".sys")).map((b) => b.dataset.lang);
  if (marked.join() !== "en") throw new Error("marked: " + marked);
  if (!pickTile("en").querySelector(".sys").textContent.includes("Same as macOS")) throw new Error(pickTile("en").querySelector(".sys").textContent);
  if (pickTile("en").getAttribute("aria-checked") !== "true" || tilesNow().filter((b) => b.getAttribute("aria-checked") === "true").length !== 1) throw new Error("not the one picked");
});

kiri.on({ type: "welcome" });
t("a welcome that arrives meanwhile waits behind it", () => {
  if (welcomeOpen()) throw new Error("the welcome opened over the language step");
  if (!dlg()) throw new Error("the language step went away");
});

pickTile("de").click();
t("a tile switches the whole window's language at once", () => {
  if (document.documentElement.lang !== "de") throw new Error("lang is " + document.documentElement.lang);
  if (rail() !== STRINGS.de["Containers"]) throw new Error("the sidebar reads " + rail());
  if (dlg().querySelector("#lang-title").textContent !== STRINGS.de["Choose your language"]) throw new Error("the dialog's title reads " + dlg().querySelector("#lang-title").textContent);
  if ($("lang-go").textContent !== STRINGS.de["Continue"]) throw new Error("Continue reads " + $("lang-go").textContent);
  if (pickTile("de").getAttribute("aria-checked") !== "true" || pickTile("en").getAttribute("aria-checked") !== "false") throw new Error("the pick didn't move");
});
t("and saves it", () => { if (saved("lang") !== "de") throw new Error("saved " + saved("lang")); });
t("the system's tile stays marked, in the new language", () => {
  if (pickTile("en").querySelector(".sys")?.textContent !== STRINGS.de["Same as {os}"].replace("{os}", "macOS")) throw new Error(pickTile("en").querySelector(".sys")?.textContent);
});

pickTile("fr").click();
t("another tile switches again", () => {
  if (document.documentElement.lang !== "fr" || rail() !== STRINGS.fr["Containers"] || saved("lang") !== "fr") throw new Error(`lang ${document.documentElement.lang}, sidebar ${rail()}, saved ${saved("lang")}`);
});

// A language the page doesn't carry: the tile is picked at once, the words
// follow when the host answers, and the step redraws in them.
hostHold = true;
pickTile("ja").click();
t("a language the page lacks: asked for, the tile picked, the window as it was until the words come", () => {
  if (!sent.some((m) => m.type === "langwords" && m.name === "ja")) throw new Error("no langwords for ja");
  if (pickTile("ja").getAttribute("aria-checked") !== "true") throw new Error("the tile isn't picked");
  if (document.documentElement.lang !== "fr" || rail() !== STRINGS.fr["Containers"]) throw new Error(`lang ${document.documentElement.lang}, sidebar ${rail()}`);
});
hostHold = false; hostFlush();
t("then the words come and the step and the window read Japanese", () => {
  if (document.documentElement.lang !== "ja" || !document.documentElement.classList.contains("cjk")) throw new Error(`lang ${document.documentElement.lang}, ${document.documentElement.className}`);
  if (rail() !== STRINGS.ja["Containers"]) throw new Error("the sidebar reads " + rail());
  if (dlg().querySelector("#lang-title").textContent !== STRINGS.ja["Choose your language"]) throw new Error(dlg().querySelector("#lang-title").textContent);
  if (pickTile("ja").getAttribute("aria-checked") !== "true" || document.activeElement !== pickTile("ja")) throw new Error("the pick or focus moved");
});

pickTile("en").click();
t("the system's own tile saves System, not English", () => {
  if (saved("lang") !== "system") throw new Error("saved " + saved("lang"));
  if (document.documentElement.lang !== "en" || rail() !== "Containers") throw new Error(`lang ${document.documentElement.lang}, sidebar ${rail()}`);
});
t("nothing says it was asked before Continue", () => { if (saved("langAsked") !== undefined) throw new Error("langAsked sent early"); });

pickTile("es").click();
$("lang-go").click();
t("Continue saves that it was asked and closes", () => {
  if (saved("langAsked") !== true) throw new Error("langAsked is " + saved("langAsked"));
  if (dlg()) throw new Error("still open");
});
t("the window stays in the language picked", () => {
  if (document.documentElement.lang !== "es" || rail() !== STRINGS.es["Containers"]) throw new Error(`lang ${document.documentElement.lang}, sidebar ${rail()}`);
});
t("then the welcome that waited shows", () => { if (!welcomeOpen()) throw new Error("no welcome"); });
document.querySelector('[aria-labelledby="welcome-title"]')?.closest(".scrim")?.remove();

// A French system: its tile is the one marked, and the step opens in French.
// Escape keeps that, as Continue does.
window.KIRI_LANG.os = ["fr-CA", "en-US"];
setPref("lang", "system");
sent.length = 0;
kiri.on({ type: "langpick" });
t("a French system's tile is the one marked, and the step reads French", () => {
  const marked = tilesNow().filter((b) => b.querySelector(".sys")).map((b) => b.dataset.lang);
  if (marked.join() !== "fr") throw new Error("marked: " + marked);
  if (pickTile("fr").getAttribute("aria-checked") !== "true") throw new Error("French isn't picked");
  if (dlg().querySelector("#lang-title").textContent !== STRINGS.fr["Choose your language"]) throw new Error(dlg().querySelector("#lang-title").textContent);
});
document.activeElement.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
t("Escape closes it as Continue does, keeping the language", () => {
  if (dlg()) throw new Error("still open");
  if (saved("langAsked") !== true) throw new Error("langAsked is " + saved("langAsked"));
  if (saved("lang") !== undefined || document.documentElement.lang !== "fr") throw new Error(`saved ${saved("lang")}, lang ${document.documentElement.lang}`);
});
window.KIRI_LANG.os = ["en-US"];
setPref("lang", "system");
report(R);
