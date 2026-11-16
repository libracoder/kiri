// parity: macos windows linux
// Cloudflare uses the same share actions without a Kiri Cloud login or plan.
const R = [];
const t = (name, fn) => { try { fn(); R.push("ITEM " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
kiri.on({ type: "shareaccount", provider: "cloudflare", signedIn: false, baseDomain: null });
kiri.on({ type: "shareusage", unsupported: true });
t("Cloudflare has no GitHub sign-in or Kiri Cloud plan", () => {
  show("share"); sh.open = null; renderShare();
  const text = $("content").textContent;
  eq(text.includes("Cloudflare Tunnel"), true, "provider");
  eq(text.includes("trycloudflare.com"), true, "temporary domain");
  eq(text.includes("Kiri Cloud"), false, "no Kiri Cloud claim");
  eq(text.includes("Checking your plan"), false, "no plan request");
  eq(!!document.querySelector("[data-shlogin], [data-shlogout]"), false, "no login/logout buttons");
  eq(text.includes("Cloudflare does not provide request logs in Kiri"), true, "statistics explained");
});
t("Share starts directly without opening sign-in", () => {
  for (const [id, x] of sh.items) if (x.source === "postgres") sh.items.delete(id);
  sh.starting.delete("postgres"); show("containers"); sent.length = 0;
  shShare("postgres");
  eq(sent.some(x => x.type === "share" && x.name === "postgres"), true, "share sent");
  eq(!!$("sh-signin"), false, "no sign-in dialog");
});
t("Cloudflare lists CLI shares on this computer", () => {
  sent.length = 0; shPoll();
  eq(sent.some(x => x.type === "sharetunnels"), true, "polls local shares without login");
});
t("a configured base domain is displayed safely", () => {
  kiri.on({ type: "shareaccount", provider: "cloudflare", signedIn: false, baseDomain: "apps.example.com" });
  show("share"); sh.open = null; renderShare();
  eq($("content").textContent.includes("apps.example.com"), true, "domain");
});
t("the live dialog identifies Cloudflare and stops the share", () => {
  kiri.on({ type: "share", id: 501, source: "postgres", state: "live", url: "https://postgres.example.com" });
  shCard("501");
  eq($("sh-modal").textContent.includes("Cloudflare"), true, "flow provider");
  eq($("sh-modal").textContent.includes("Kiri Cloud"), false, "no Kiri flow");
  sent.length = 0; $("sh-modal").querySelector("[data-mstop]").click();
  eq(sent.some(x => x.type === "unshare" && x.id === "501"), true, "stop sent");
});
t("returning to Kiri restores sign-in", () => {
  kiri.on({ type: "shareaccount", signedIn: false });
  show("share"); sh.open = null; renderShare();
  eq(!!document.querySelector("[data-shlogin]"), true, "Kiri login");
  eq(shAvailable(), false, "requires sign-in");
});
report(R);
