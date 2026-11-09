// The USB view: devices listed whether the engine runs or not; Attach and
// Detach say what they're doing and come back with a toast; Linux rows say
// where containers find the device; Windows without usbipd-win offers it.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };
const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(m + ": got " + JSON.stringify(a) + " want " + JSON.stringify(b)); };
const rows = () => [...document.querySelectorAll("#content tbody tr")];
const mac = { type: "usb", can: "attach", note: "A device in Kiri is gone from the Mac until you detach it.", devices: [
  { key: "0x01100000", name: "Zigbee 3.0 USB Dongle Plus", id: "10c4:ea60", speed: "full", state: "host", path: "" },
  { key: "0x02200000", name: "USB Mouse", id: "046d:c077", speed: "low", state: "kiri", path: "" }] };

sent.length = 0;
show("usb");
t("opening the view asks for the devices", () => eq(sent.some((m) => m.type === "usb"), true, "sent"));
t("it says it's looking until they come", () => eq(/Looking for USB devices/.test($("content").textContent), true, "text"));
kiri.on(mac);
t("the title is USB, marked Beta", () => eq([$("title").firstChild.textContent, $("title").querySelector(".beta")?.textContent], ["USB", "Beta"], "title"));
t("a banner says it's in beta, what works, and links to feedback", () => {
  const b = document.querySelector(".usb-beta");
  eq([!!b, /in beta/.test(b?.textContent), /webcams and audio/.test(b?.textContent), /issues\/new/.test(b?.querySelector("[data-open-site]")?.dataset.openSite || "")], [true, true, true, true], "banner");
});
sent.length = 0;
document.querySelector("[data-usbbeta]").click();
t("closing it saves that, and it stays closed", () => {
  eq(sent.filter((m) => m.type === "setpref").map((m) => [m.name, m.value]), [["usbBetaClosed", true]], "pref");
  kiri.on(mac);
  eq(document.querySelector(".usb-beta"), null, "gone");
});
t("the sidebar marks it Beta too", () => eq(document.querySelector('nav [data-view="usb"] .beta')?.textContent, "Beta", "nav"));
t("one row per device", () => eq(rows().map((r) => r.dataset.key), ["0x01100000", "0x02200000"], "rows"));
t("a device on the Mac can be attached, one in Kiri detached", () => {
  eq(rows().map((r) => r.querySelector("[data-usbgo]")?.dataset.usbgo), ["attach", "detach"], "actions");
  eq(rows().map((r) => r.querySelector(".pill").textContent), ["On this Mac", "In Kiri"], "state");
});
t("the sidebar counts the devices in Kiri", () => eq($("n-usb").textContent, "1", "count"));
t("the subtitle says how many", () => eq($("subtitle").textContent, "1 in Kiri · 2 devices", "subtitle"));
t("the note says what attaching means", () => eq(/gone from the Mac/.test(document.querySelector(".usb-note")?.textContent || ""), true, "note"));

sent.length = 0;
rows()[0].querySelector("[data-usbgo]").click();
t("Attach sends the device's key", () => eq(sent.filter((m) => m.type === "usbattach").map((m) => m.name), ["0x01100000"], "sent"));
t("and the row says it's attaching, not clickable twice", () => {
  const b = rows()[0].querySelector(".actions button");
  eq([b.textContent, b.disabled], ["Attaching…", true], "busy");
});
t("a refresh while it works keeps it busy", () => { kiri.on(mac); eq(rows()[0].querySelector(".actions button").textContent, "Attaching…", "busy"); });
kiri.on({ type: "usbdone", key: "0x01100000", text: "Zigbee 3.0 USB Dongle Plus is in Kiri" });
kiri.on({ ...mac, devices: mac.devices.map((d) => ({ ...d, state: "kiri" })) });
t("done: the toast says so and the row can be detached", () => {
  eq(/is in Kiri/.test(document.body.textContent), true, "toast");
  eq(rows()[0].querySelector("[data-usbgo]")?.dataset.usbgo, "detach", "action");
  eq($("n-usb").textContent, "2", "count");
});
sent.length = 0;
rows()[1].querySelector("[data-usbgo]").click();
kiri.on({ type: "usbdone", key: "0x02200000", error: "USB Mouse was not attached: the device is busy" });
t("Detach sends its key; an error is a toast and the row is free again", () => {
  eq(sent.filter((m) => m.type === "usbdetach").map((m) => m.name), ["0x02200000"], "sent");
  eq(/device is busy/.test(document.body.textContent), true, "toast");
  eq(rows()[1].querySelector("[data-usbgo]")?.dataset.usbgo, "detach", "free");
});
kiri.on({ type: "usbdone", key: "0x01100000" });
t("a cancelled password prompt says nothing", () => eq(rows()[0].querySelector(".actions button").disabled, false, "free"));

t("each device's icon says what it is", () => {
  kiri.on({ type: "usb", can: "attach", devices: [
    { key: "m", name: "Razer Basilisk V3 Pro 35K", id: "1532:00d6", state: "host", kind: "mouse" },
    { key: "k", name: "ROG AZOTH", id: "0b05:1a83", state: "host", kind: "keyboard" },
    { key: "z", name: "Sonoff Zigbee 3.0 USB Dongle Plus", id: "10c4:ea60", state: "host" },
    { key: "s", name: "USB-SERIAL CH340 (COM4)", id: "1a86:7523", state: "host" },
    { key: "h", name: "USB2.0 HID", id: "0bda:1100", state: "host", kind: "" }] });
  const d = (k) => document.querySelector(`tr[data-key="${k}"] .tile path`)?.getAttribute("d");
  eq([d("m") === PH.mouse, d("k") === PH.keyboard, d("z") === PH.broadcast, d("s") === PH.circuitry, d("h") === PH.usb], [true, true, true, true, true], "icons");
  // In Kiri the engine can't read its interfaces: the kind it had stays.
  kiri.on({ type: "usb", can: "attach", devices: [{ key: "m", name: "Razer Basilisk V3 Pro 35K", id: "1532:00d6", state: "kiri", kind: "" }] });
  eq(d("m") === PH.mouse, true, "kept");
  kiri.on(mac);
});
$("gq").value = "zig"; $("gq").dispatchEvent(new Event("input"));
t("the search narrows the devices", () => eq(rows().length, 1, "rows"));
$("gq").value = ""; $("gq").dispatchEvent(new Event("input"));

kiri.on({ type: "state", state: "stopped" });
t("with the engine stopped the devices are still listed", () => eq(rows().length, 2, "rows"));
kiri.on({ type: "state", state: "running" });

kiri.on({ type: "usb", can: "none", note: "Containers see them.", devices: [{ key: "/dev/bus/usb/001/003", name: "CP2102", id: "10c4:ea60", speed: "full", state: "shared", path: "/dev/ttyUSB0" }] });
t("Linux: no attach; the row says where containers find it, with a copy button", () => {
  eq(rows()[0].querySelector("[data-usbgo]"), null, "no attach");
  eq(rows()[0].querySelector("[data-copy]")?.dataset.copy, "--device /dev/ttyUSB0", "copy");
  eq(rows()[0].querySelector(".pill").textContent, "Containers see it", "state");
});

kiri.on({ type: "usb", devices: [], missing: true });
sent.length = 0;
t("Windows without usbipd-win: it offers to install it", () => eq(!!document.querySelector('[data-usbgo="install"]'), true, "button"));
document.querySelector('[data-usbgo="install"]').click();
t("Install sends usbinstall and waits", () => {
  eq(sent.map((m) => m.type).includes("usbinstall"), true, "sent");
  eq(document.querySelector('[data-usbgo="install"]').disabled, true, "busy");
});
kiri.on({ type: "usb", devices: [] });
t("no devices: it says to plug one in", () => eq(/No USB devices/.test($("content").textContent), true, "empty"));
show("containers");
report(R);
