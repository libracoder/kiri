// Settings → Resources → WSL integration: empty state, distro list,
// toggling On/Off, no duplicate sends, and server round-trip updates.
const R = [];
const t = (name, fn) => { try { fn(); R.push("PASS " + name); } catch (e) { R.push("FAIL " + name + ": " + e.message); } };

const baseRes = {
  type: "resources", cpus: 8, memory_mib: 16384, running_cpus: 8, running_memory_mib: 16384,
  awake: true, max_cpus: 16, max_memory_mib: 32768, overridden: false,
};

show("settings");
document.querySelector('[data-stab="resources"]').click();

t("WSL pane hidden when wsl_distros is absent on non-Windows", () => {
  kiri.on({ ...baseRes });
  if (document.querySelector("[data-wsldistro]")) throw new Error("unexpected distro toggle");
  const titles = [...document.querySelectorAll(".settings .pane h3")].map((h) => h.textContent.trim());
  if (titles.includes("WSL integration")) throw new Error("WSL integration pane shown without wsl_distros");
});

t("WSL pane shows empty message when no other distros are installed", () => {
  kiri.on({ ...baseRes, wsl_distros: [] });
  const panes = [...document.querySelectorAll(".settings .pane")];
  const wsl = panes.find((p) => p.querySelector("h3")?.textContent.trim() === "WSL integration");
  if (!wsl) throw new Error("WSL integration pane missing");
  if (!wsl.textContent.includes("No other WSL distros installed.")) {
    throw new Error("missing empty-state text: " + wsl.textContent);
  }
});

t("WSL pane renders distros, toggles On/Off, ignores no-op clicks, and reflects round-trip", () => {
  sent.length = 0;
  kiri.on({
    ...baseRes,
    wsl_distros: [
      { name: "Ubuntu", on: false },
      { name: "NixOS", on: true },
    ],
  });
  const tabs = document.querySelector(".settings .tabs").getBoundingClientRect();
  const ubuntuOff = document.querySelector('[data-wsldistro="Ubuntu"][data-wslon="0"]');
  const ubuntuOn = document.querySelector('[data-wsldistro="Ubuntu"][data-wslon="1"]');
  const nixosOn = document.querySelector('[data-wsldistro="NixOS"][data-wslon="1"]');
  const nixosOff = document.querySelector('[data-wsldistro="NixOS"][data-wslon="0"]');
  if (!ubuntuOff || !ubuntuOn || !nixosOn || !nixosOff) throw new Error("missing distro toggle buttons");
  if (ubuntuOn.getBoundingClientRect().left < tabs.right) throw new Error("WSL pane sits under tabs");
  if (ubuntuOff.getAttribute("aria-pressed") !== "true" || ubuntuOn.getAttribute("aria-pressed") !== "false") {
    throw new Error("Ubuntu initial toggle state wrong");
  }
  if (nixosOn.getAttribute("aria-pressed") !== "true" || nixosOff.getAttribute("aria-pressed") !== "false") {
    throw new Error("NixOS initial toggle state wrong");
  }

  // Clicking already-active Off button does not send a message.
  ubuntuOff.click();
  if (sent.length !== 0) throw new Error("clicking active Off button sent a message");

  // Toggle Ubuntu On.
  ubuntuOn.click();
  if (sent.length !== 1 || sent[0].type !== "setresources" || sent[0].value?.wsl_distro !== "Ubuntu" || sent[0].value?.on !== true) {
    throw new Error("expected setresources { wsl_distro: 'Ubuntu', on: true }, got " + JSON.stringify(sent));
  }
  if (document.querySelector('[data-wsldistro="Ubuntu"][data-wslon="1"]')?.getAttribute("aria-pressed") !== "true") {
    throw new Error("Ubuntu did not update optimistically to On");
  }

  // Toggle NixOS Off.
  document.querySelector('[data-wsldistro="NixOS"][data-wslon="0"]').click();
  if (sent.length !== 2 || sent[1].type !== "setresources" || sent[1].value?.wsl_distro !== "NixOS" || sent[1].value?.on !== false) {
    throw new Error("expected setresources { wsl_distro: 'NixOS', on: false }, got " + JSON.stringify(sent[1]));
  }

  // Round-trip reply from host reconciles authoritative state (e.g., if Ubuntu stayed on and NixOS turned off).
  kiri.on({
    ...baseRes,
    wsl_distros: [
      { name: "Ubuntu", on: true },
      { name: "NixOS", on: false },
    ],
  });
  if (document.querySelector('[data-wsldistro="Ubuntu"][data-wslon="1"]')?.getAttribute("aria-pressed") !== "true") {
    throw new Error("Ubuntu not On after round-trip");
  }
  if (document.querySelector('[data-wsldistro="NixOS"][data-wslon="0"]')?.getAttribute("aria-pressed") !== "true") {
    throw new Error("NixOS not Off after round-trip");
  }
});

report(R);
