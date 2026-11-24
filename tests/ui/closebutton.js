// Settings → Appearance → Closing the window: Hide unless you choose Close.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const pressed = () => [...document.querySelectorAll("[data-closebtn]")].filter((b) => b.getAttribute("aria-pressed") === "true").map((b) => b.dataset.closebtn);
const words = () => document.querySelector("[data-closebtn]").closest(".pref").querySelector(".d").textContent;
prefs.tab = "appearance"; show("settings");
t("hide is the choice until another is made", () => {
  eq(pressed(), ["hide"], "pressed");
  eq(words().startsWith("Hide:"), true, "says what Hide does");
});
t("choosing Close is saved and says what it costs", () => {
  sent.length = 0; document.querySelector('[data-closebtn="close"]').click();
  eq(sent.filter((x) => x.type === "setpref").map((x) => [x.name, x.value]), [["closeButton", "close"]], "saved");
  eq(pressed(), ["close"], "pressed");
  eq(/open terminals end/.test(words()), true, "says terminals end");
});
t("and back to Hide", () => {
  sent.length = 0; document.querySelector('[data-closebtn="hide"]').click();
  eq(sent.filter((x) => x.type === "setpref").map((x) => [x.name, x.value]), [["closeButton", "hide"]], "saved");
  eq(pressed(), ["hide"], "pressed");
});
report(R);
