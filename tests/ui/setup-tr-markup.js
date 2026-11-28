// page: setup
// Windows' setup window inserts translations as HTML too: as the main window's (tr-markup.js), a translation keeps
// only the tags its English key has, exactly as written there; anything else shows as text and never runs.
(async () => {
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
window.pwned = 0;
const key = KEYS.find((k) => /<code>/.test(k)) || KEYS[0];
const evil = key.replace("<code>", "<code onclick=pwned++ id=evil>") + ' <img src=x onerror="pwned++"> <img src=y onerror=pwned++ ';
addWords({ de: KEYS.map((k) => (k === key ? evil : null)) });
pickLang("de");
const box = document.createElement("div");
document.body.append(box);
box.innerHTML = tr(key);
t("the key has a tag", () => eq(/<code>/.test(key), true, key));
t("added attributes and tags show as text", () => {
  eq(box.querySelector("#evil, [onclick], [onerror], img"), null, "an element with markup the English lacks");
  eq(box.textContent.includes("<img src=x"), true, "img as text");
  eq(box.textContent.includes("<img src=y onerror=pwned++"), true, "stray < as text");
});
await new Promise((r) => setTimeout(r, 50));
t("nothing ran", () => eq(window.pwned, 0, "a handler ran"));
box.remove();
report(R);
})();
