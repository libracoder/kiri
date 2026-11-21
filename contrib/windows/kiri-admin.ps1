# The steps of Kiri on Windows that need an administrator, run elevated by
# kiri-win (crates/kiri-win/src/setup.rs and dns.rs): Windows asks for an
# administrator's approval first. Installed beside kiri-win.exe, which checks
# it against the SHA-256 it was built with and runs
#   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File kiri-admin.ps1 -Wsl -Msi <wsl .msi> -Sha256 <hex>
#   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File kiri-admin.ps1 -Components
#   powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File kiri-admin.ps1 -Dns -Suffix kiri.local [-Off]
# A script file with parameters, not script text in kiri-win.exe handed to
# PowerShell encoded: an elevated, hidden PowerShell fed an encoded script
# is what malware droppers do, and Defender's heuristics quarantined a
# kiri-win.exe that carried that (as update.rs says of kiri.ps1 -Update).
param(
  [switch]$Wsl,
  [switch]$Components,
  [string]$Msi,
  [string]$Sha256,
  [switch]$Dns,
  [ValidatePattern('^[A-Za-z0-9.-]+$')]
  [string]$Suffix = "kiri.local",
  [switch]$Off
)
$ErrorActionPreference = "Stop"
# Both WSL optional components in one dism.exe call: they share the Windows
# Foundation parent package, so it is one servicing transaction. /all brings
# their parent features, /norestart leaves the restart to setup, and exit
# 3010 says one is needed.
$featureArgs = '/online', '/enable-feature', '/featurename:Microsoft-Windows-Subsystem-Linux', '/featurename:VirtualMachinePlatform', '/all', '/norestart'

# -Wsl: setup step 1, in one elevated run: both optional components on, and
# WSL installed from the MSI kiri-win downloaded. That MSI lives in a
# user-writable folder, so a process at the user's own integrity could swap
# it between kiri-win's SHA-256 check and this run: it is checked again
# here, as admin, on a copy the user cannot touch, and must be signed by
# Microsoft. setup.rs reads the exit code: 22 the copy does not match
# -Sha256, 23 not validly signed by Microsoft, 24 the components could not
# be turned on, 21 the WSL installer failed, 3010 done but Windows must
# restart.
if ($Wsl) {
  if (-not $Msi -or -not $Sha256) { throw "-Wsl needs -Msi and -Sha256" }
  $dst = Join-Path $env:windir ('Temp\kiri-wsl-' + [guid]::NewGuid().ToString('N') + '.msi')
  Copy-Item -LiteralPath $Msi -Destination $dst -Force
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $dst).Hash.ToLower() -ne $Sha256.ToLower()) { Remove-Item -LiteralPath $dst -Force; exit 22 }
  $sig = Get-AuthenticodeSignature -LiteralPath $dst
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*Microsoft*') { Remove-Item -LiteralPath $dst -Force; exit 23 }
  $features = (Start-Process "$env:SystemRoot\System32\dism.exe" -ArgumentList $featureArgs -Wait -PassThru -WindowStyle Hidden).ExitCode
  if ($features -ne 0 -and $features -ne 3010) { Remove-Item -LiteralPath $dst -Force; exit 24 }
  $msiexec = (Start-Process "$env:SystemRoot\System32\msiexec.exe" -ArgumentList '/i', ('"' + $dst + '"'), '/qn', '/norestart' -Wait -PassThru -WindowStyle Hidden).ExitCode
  Remove-Item -LiteralPath $dst -Force
  if ($msiexec -ne 0 -and $msiexec -ne 3010) { exit 21 }
  if ($features -eq 3010 -or $msiexec -eq 3010) { exit 3010 } else { exit 0 }
}

# -Components: the two optional components only, for a PC whose WSL is
# installed (wsl.exe answers) but says WSL_E_WSL_OPTIONAL_COMPONENT_REQUIRED:
# an earlier setup turned on Virtual Machine Platform alone. Exit 24 they
# could not be turned on, 3010 done but Windows must restart.
if ($Components) {
  $features = (Start-Process "$env:SystemRoot\System32\dism.exe" -ArgumentList $featureArgs -Wait -PassThru -WindowStyle Hidden).ExitCode
  if ($features -eq 0 -or $features -eq 3010) { exit $features } else { exit 24 }
}

# -Dns: the name-resolution policy (NRPT) rule that sends `.<suffix>`
# lookups to kiri-win's DNS answerer on 127.0.0.1 (dns.rs), added, or
# removed with -Off. Any rule already there for the suffix goes first, so
# adding twice leaves one. A failure exits 1, which dns.rs reports.
if ($Dns) {
  $namespace = ".$Suffix"
  Get-DnsClientNrptRule | Where-Object { $_.Namespace -contains $namespace } | Remove-DnsClientNrptRule -Force
  if (-not $Off) {
    Add-DnsClientNrptRule -Namespace $namespace -NameServers '127.0.0.1' -Comment "Kiri: containers answer at <name>.$Suffix"
  }
  Clear-DnsClientCache
  exit 0
}

throw "kiri-admin.ps1 needs -Wsl, -Components or -Dns"
