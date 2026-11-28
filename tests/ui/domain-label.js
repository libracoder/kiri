// parity: macos windows linux
// A container's local address comes from its dev.kiri.domain label (anyone's text), else Compose's service.project,
// else its name (Compose's own rows are compose-*.js's; localUrl is checked for them here). Only a plain host name makes an address: a hostile label gives none at all, so no Open button, no
// address under the name, no chip in its page and no Open in its ⋯ menu; and it never reaches the HTML as markup.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const now = Math.floor(Date.now() / 1000);
const C = (id, labels, name = id) => ({ Id: id, Names: [`/${name}`], Image: "nginx", State: "running", Status: "Up 1 hour", Created: now - 60,
  Ports: [{ IP: "0.0.0.0", PrivatePort: 80, PublicPort: 8080, Type: "tcp" }], Labels: labels });
const HOSTILE = {
  query: "outside.example?x",
  hash: "outside.example/#",
  at: "x@outside.example",
  backslash: "outside.example\\x",
  markup: '"><img src=x onerror="window.pwned=1">',
  space: "a b",
  dot: "web.",
  idn: "bücher",
};
ui.vm = "running";
kiri.on({ type: "status", version: "0.1.4", dev: true, share: true, app: "Kiri", ours: "kiri", context: "kiri" });
kiri.on({ type: "lists", containers: [
  C("good", { "dev.kiri.domain": "api.myapp" }),
  C("upper", { "dev.kiri.domain": "Api.Shop.kiri.localhost" }),
  ...Object.entries(HOSTILE).map(([k, v]) => C("h-" + k, { "dev.kiri.domain": v })),
], images: [], volumes: [], networks: [] });
const click = (el) => el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
const row = (k) => document.querySelector(`#content tr[data-key="${k}"]`);
const opens = (el) => [...el.querySelectorAll("[data-open]")].map((b) => b.dataset.open);

t("a plain label, a Compose name and a typed suffix make an address", () => {
  eq(localUrl(C("a", { "dev.kiri.domain": "api.myapp" }), "a"), "http://api.myapp.kiri.localhost", "label");
  eq(localUrl(C("a", { "dev.kiri.domain": "Api.Shop.kiri.localhost, other" }), "a"), "http://api.shop.kiri.localhost", "typed suffix, upper case");
  eq(localUrl(C("a", { "com.docker.compose.project": "shop", "com.docker.compose.service": "web" }), "a"), "http://web.shop.kiri.localhost", "compose");
  eq(localUrl(C("a", {}), "My_App"), "http://my_app.kiri.localhost", "container name");
});
t("a hostile label makes no address", () => {
  for (const [k, v] of Object.entries(HOSTILE)) eq(localUrl(C("a", { "dev.kiri.domain": v }), "a"), "", k);
  eq(localUrl(C("a", { "com.docker.compose.project": "shop", "com.docker.compose.service": "w/#x" }), "a"), "", "compose service");
  eq(localUrl(C("a", {}), "a b"), "", "container name");
});
t("the list shows the good addresses only", () => {
  eq(opens(row("good")).includes("http://api.myapp.kiri.localhost"), true, "good row");
  eq(opens(row("upper")).includes("http://api.shop.kiri.localhost"), true, "upper row");
  for (const k of Object.keys(HOSTILE).map((k) => "h-" + k)) {
    const r = row(k);
    if (!r) throw new Error(`no row for ${k}`);
    eq(opens(r).filter((u) => /kiri\.local/.test(u)), [], `${k}: an address`);
    eq(r.querySelector(".sub-addr, .kbadge"), null, `${k}: address under the name or badge`);
  }
});
t("a hostile label's ⋯ menu has no Open", () => {
  click(row("h-query").querySelector("[data-more]"));
  const items = [...document.querySelectorAll(".menu button")].map((b) => b.textContent);
  eq(items.some((x) => /^Open /.test(x)), false, "Open in menu: " + items.join(" | "));
  document.body.click();
});
t("a hostile label's page has no chip and no Open", () => {
  click(row("h-markup").querySelector("[data-detail]"));
  eq(document.querySelector("#content .dhead .local"), null, "chip");
  eq(document.querySelector('#content .dacts [data-open]'), null, "Open button");
});
t("the markup label never ran", () => {
  eq(window.pwned, undefined, "onerror ran");
  eq(document.querySelector('img[src="x"]'), null, "an injected img");
});
report(R);
