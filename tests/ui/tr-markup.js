// parity: macos windows linux
// Translations go into the page as HTML. A translation keeps only the tags its English key has, each exactly as
// written there (attributes and all); anything else, an event handler on a kept tag, a new tag or a stray "<",
// shows as text and never runs. scripts/i18n-check.py refuses such words first; this is the page's own wall.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const CODE = KEYS.find((k) => /<code>/.test(k) && !/[{<]/.test(k.replace(/<\/?code>/g, "")));
const MONO = KEYS.find((k) => k.includes("<span class=mono>"));
const words = (lang, m) => { const p = { [lang]: KEYS.map((k) => (k in m ? m[k] : STRINGS[lang]?.[k] ?? null)) }; addWords(p); setLang(lang); };
const box = document.createElement("div");
document.body.append(box);
const asHtml = (s) => { box.innerHTML = s; return box; };
window.pwned = 0;
const HOSTILE = {
  [CODE]: CODE.replace("<code>", "<code onclick=\"pwned++\" id=evil>") + ' <img src=x onerror="pwned++"> <b style=color:red>b</b> <a href="javascript:pwned++">a</a> <img src=y onerror=pwned++ ',
  [MONO]: MONO.replace("<span class=mono>", "<span class=mono onmouseover=pwned++>"),
};
t("the keys used have the tags", () => { if (!CODE || !MONO) throw new Error(`no key: ${CODE} ${MONO}`); });
for (const lang of ["de", "ar"]) {
  words(lang, HOSTILE);
  setLang(lang);
  t(`${lang}: a kept tag with an added attribute shows as text`, () => {
    const el = asHtml(tr(CODE));
    eq(el.querySelector("#evil, [onclick], [onerror], [onmouseover], [style], [href], img, b, a"), null, "an element with markup the English lacks");
    eq(el.textContent.includes('<code onclick="pwned++" id=evil>'), true, "the text shows what was written");
    eq(el.textContent.includes("<img src=x"), true, "the img shows as text");
  });
  t(`${lang}: a stray < shows as text`, () => eq(asHtml(tr(CODE)).textContent.includes("<img src=y onerror=pwned++"), true, "stray <"));
  t(`${lang}: a tag written as in the English stays a tag`, () => {
    words(lang, { [CODE]: "Vorher <code>kiri</code> nachher" });
    eq(asHtml(tr(CODE)).querySelectorAll("code").length, 1, "code");
    words(lang, { [MONO]: MONO });
    const el = asHtml(tr(MONO, { [(MONO.match(/\{(\w+)\}/) || [])[1]]: "x" }));
    eq(el.querySelector("span.mono") !== null, true, "span class=mono");
    words(lang, HOSTILE);
    eq(asHtml(tr(MONO)).querySelector("[onmouseover]"), null, "onmouseover on span.mono");
  });
}
t("nothing ran", () => {
  for (const el of box.querySelectorAll("*")) el.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  eq(window.pwned, 0, "a handler ran");
});
setLang("en");
box.remove();
report(R);
