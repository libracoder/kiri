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
t("custom-domain setup is accessible from Share", () => {
  show("share"); sh.open = null; renderShare(); sent.length = 0;
  document.querySelector("[data-shdomain]").click();
  eq(sent.at(-1).type, "shareconfig", "load settings");
  kiri.on({ type: "shareconfig", id: sent.at(-1).id, settings: { base_domain: null, routes: [] } });
  eq($("cf-mode").value, "quick", "temporary mode");
  eq($("cf-named").disabled, true, "hidden custom fields do not block validation");
  $("cf-mode").value = "custom"; $("cf-mode").dispatchEvent(new Event("change", { bubbles: true }));
  $("cf-base").value = "example.com";
  $("sh-domain").querySelector("[data-cf-add]").click();
  $("sh-domain").querySelector("[data-cf-name]").value = "web";
  $("sh-domain").querySelector("[data-cf-file]").value = "/credentials with spaces/web.json";
});
t("custom-domain setup saves routes and displays the DNS records", () => {
  sent.length = 0;
  $("sh-domain").querySelector("button[type=submit]").click();
  const request = sent.find(x => x.type === "shareconfig");
  eq(request.value, { base_domain: "example.com", routes: [{ name: "web", credentials_file: "/credentials with spaces/web.json" }] }, "setup payload");
  eq($("sh-domain").querySelector("[data-cf-form]").disabled, true, "prevents duplicate saves");
  kiri.on({ type: "shareconfig", id: request.id, saved: true, settings: { base_domain: "example.com", routes: [{ name: "web", credentials_file: "/credentials with spaces/web.json", hostname: "web.example.com", dns_target: "tunnel-uuid.cfargotunnel.com" }] } });
  eq($("sh-domain").textContent.includes("web.example.com → tunnel-uuid.cfargotunnel.com"), true, "DNS route");
  eq($("cf-status").textContent.includes("Settings apply to new shares"), true, "save acknowledged");
});
t("invalid domain setup keeps edits and allows correction", () => {
  $("cf-base").value = "https://example.com";
  $("sh-domain").querySelector("button[type=submit]").click();
  kiri.on({ type: "shareconfig", id: shDomain.id, error: "Use a DNS name without a scheme" });
  eq($("cf-base").value, "https://example.com", "preserves edit");
  eq($("cf-error").textContent, "Use a DNS name without a scheme", "visible validation error");
  eq($("sh-domain").querySelector("[data-cf-form]").disabled, false, "can retry");
  kiri.on({ type: "shareconfig", id: "outdated-request", settings: { base_domain: null, routes: [] } });
  eq($("cf-base").value, "https://example.com", "ignores stale response");
});
t("temporary mode explicitly clears the local named routes", () => {
  $("cf-mode").value = "quick"; $("cf-mode").dispatchEvent(new Event("change", { bubbles: true }));
  sent.length = 0; $("sh-domain").querySelector("button[type=submit]").click();
  eq(sent.at(-1).value, { base_domain: null, routes: [] }, "clears domain mappings");
  eq($("cf-quick-note").hidden, false, "explains clearing routes");
  const oldId = shDomain.id;
  $("sh-domain").querySelector("[data-cf-close]").click();
  eq(!!$("sh-domain"), false, "dialog closed");
  kiri.on({ type: "shareconfig", id: oldId, saved: true, settings: { base_domain: null, routes: [] } });
  eq(!!$("sh-domain"), false, "late save does not reopen dialog");
});
t("returning to Kiri restores sign-in", () => {
  kiri.on({ type: "shareaccount", signedIn: false });
  show("share"); sh.open = null; renderShare();
  eq(!!document.querySelector("[data-shlogin]"), true, "Kiri login");
  eq(shAvailable(), false, "requires sign-in");
});
report(R);
