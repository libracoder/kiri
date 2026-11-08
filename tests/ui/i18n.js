// Settings → Appearance → Language: System / English / 简体中文.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
show("containers");
t("English is the default for tests", () => {
  if (lang() !== "en") throw new Error(lang());
  if ($("title").textContent !== "Containers") throw new Error($("title").textContent);
  if (!document.querySelector('[data-view="images"] .lbl')?.textContent.includes("Images")) throw new Error("nav");
});
t("简体中文 switches the chrome and list title", () => {
  prefs.lang = "zh";
  paintChrome();
  render();
  if (lang() !== "zh") throw new Error(lang());
  if (document.documentElement.lang !== "zh-CN") throw new Error(document.documentElement.lang);
  if ($("title").textContent !== "容器") throw new Error($("title").textContent);
  if (document.querySelector('[data-view="images"] .lbl')?.textContent !== "镜像") throw new Error("nav images");
  if (document.querySelector('[data-view="settings"] .lbl')?.textContent !== "设置") throw new Error("nav settings");
  if ($("vm-toggle").textContent !== "启动" && $("vm-toggle").textContent !== "停止") throw new Error($("vm-toggle").textContent);
});
t("Settings → Appearance exposes Language and applies it", () => {
  show("settings");
  prefs.tab = "appearance";
  settingsShown.html = "";
  render();
  const seg = document.querySelector('[data-lang-pick="zh"]');
  if (!seg) throw new Error("no language control");
  if (!/语言|Language/.test(document.querySelector(".settings .pane")?.textContent || "")) throw new Error("no language row");
  seg.click();
  if (prefs.lang !== "zh") throw new Error(prefs.lang);
  if (!sent.some((m) => m.type === "setpref" && m.name === "lang" && m.value === "zh")) throw new Error(JSON.stringify(sent.filter((m) => m.type === "setpref")));
  if (!document.querySelector('[data-stab="appearance"]')?.textContent.includes("外观")) throw new Error("tab not zh");
});
t("English restores the labels", () => {
  document.querySelector('[data-lang-pick="en"]').click();
  if (prefs.lang !== "en" || lang() !== "en") throw new Error(prefs.lang + "/" + lang());
  show("containers");
  if ($("title").textContent !== "Containers") throw new Error($("title").textContent);
});
report(R);
