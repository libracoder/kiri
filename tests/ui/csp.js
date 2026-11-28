// parity: macos windows linux
// The page's Content-Security-Policy: only the page's own scripts run (by hash), never a script or an on…= handler
// that markup brings in; nothing is fetched (no images but data:, no fetch, no fonts, no frames); a form never
// navigates. The page itself never breaks it: fixture's CATCH fails any test on a violation it doesn't expect.
(async () => {
window.CSP_EXPECTED = true;
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const seen = [];
document.addEventListener("securitypolicyviolation", (e) => seen.push(e.effectiveDirective || e.violatedDirective));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
t("the page has its policy", () => {
  if (!meta) throw new Error("no policy");
  const p = meta.content;
  for (const d of ["default-src 'none'", "connect-src 'none'", "img-src data:", "object-src 'none'", "base-uri 'none'", "form-action 'none'"]) eq(p.includes(d), true, d);
  const script = p.split(";").map((x) => x.trim()).find((x) => x.startsWith("script-src "));
  eq(/'unsafe-inline'|'unsafe-eval'|\*|https?:|data:/.test(script), false, "script-src allows more than hashes: " + script);
  eq(script.split(" ").slice(1).every((x) => /^'sha256-[A-Za-z0-9+/]+=*'$/.test(x)), true, "script-src is hashes only");
  eq(script.split(" ").length - 1, document.scripts.length, "one hash for each script");
});
window.ran = 0;
const box = document.createElement("div");
document.body.append(box);
box.innerHTML = '<img src="data:," onerror="window.ran++"><svg onload="window.ran++"></svg><button onclick="window.ran++">x</button>';
box.querySelector("button").click();
const s = document.createElement("script");
s.textContent = "window.ran++";
document.body.append(s);
const remote = new Image();
remote.src = "https://example.invalid/x.png";
let fetched = "not tried";
try { await fetch("https://example.invalid/"); fetched = "fetched"; } catch { fetched = "refused"; }
let evaled = "not tried";
try { (0, eval)("1"); evaled = "ran"; } catch { evaled = "refused"; }
await wait(200);
t("an on…= handler from markup does not run", () => eq(window.ran, 0, "handlers or an added script ran"));
t("a script element added later does not run", () => eq(seen.includes("script-src-elem") || seen.includes("script-src"), true, "no script-src violation: " + seen.join(",")));
t("eval does not run", () => eq(evaled, "refused", "eval"));
t("nothing is fetched", () => {
  eq(fetched, "refused", "fetch");
  eq(seen.includes("img-src"), true, "no img-src violation: " + seen.join(","));
  eq(seen.includes("connect-src"), true, "no connect-src violation: " + seen.join(","));
});
box.remove();
report(R);
})();
