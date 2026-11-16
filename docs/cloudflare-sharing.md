# Share through Cloudflare Tunnel

Select Cloudflare for both `kiri share` and the app's Share buttons. Kiri
starts the installed `cloudflared` for each share, shows its HTTPS URL, and
closes it on Disconnect, Stop, or when its owning Kiri process exits.
There is no Kiri Cloud sign-in for this provider.

## Start before choosing a domain

Install [cloudflared](https://developers.cloudflare.com/tunnel/downloads/)
on the computer running Kiri, then:

```sh
kiri share provider cloudflare
kiri share 3000
```

With no base domain configured, each share gets a temporary
`https://<random>.trycloudflare.com` URL. A requested name is ignored in this
mode. A Cloudflare account and domain are not required. These are
[Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/),
intended for development, subject to Cloudflare's limitations, and with a
new address on each restart.

The selection is saved in `~/.kiri/share.json` (`%USERPROFILE%\.kiri\share.json`
on Windows). `KIRI_SHARE_CONFIG` selects a different file. Kiri Dev uses its
own config. An app opened from Finder may need an absolute executable path:

```json
{
  "provider": "cloudflare",
  "cloudflare": {
    "executable": "/opt/homebrew/bin/cloudflared"
  }
}
```

Merge these fields into an existing config, keeping its other fields.
On Windows use an escaped absolute path, for example
`"C:\\Program Files\\cloudflared\\cloudflared.exe"`.

## Use your domain later

Choose a domain on Cloudflare, then provision one **locally managed** tunnel
for each share name. For example, after replacing `example.com` with your
domain:

```sh
cloudflared tunnel login
cloudflared tunnel create kiri-web
cloudflared tunnel route dns kiri-web web.example.com
```

The create command prints a tunnel UUID and creates its credentials JSON.
Add that UUID and the absolute credentials path to Kiri's config:

```json
{
  "provider": "cloudflare",
  "cloudflare": {
    "executable": "/opt/homebrew/bin/cloudflared",
    "base_domain": "example.com",
    "tunnels": {
      "web": {
        "id": "01234567-89ab-cdef-0123-456789abcdef",
        "credentials_file": "/absolute/path/to/.cloudflared/01234567-89ab-cdef-0123-456789abcdef.json"
      }
    }
  }
}
```

Then `kiri share 3000 --name web` serves `https://web.example.com`. Sharing
a container named `web` from the app uses that entry automatically. For a
different container, port or Kubernetes service, configure its name or
specify an explicit name in the CLI. Missing entries fail with an explanation;
Kiri does not fall back to Kiri Cloud or a temporary URL when a base domain
is configured.

Kiri generates an isolated ingress configuration for the selected origin,
with that exact hostname followed by a 404 catch-all. It does not change
existing cloudflared configuration, create DNS records, or provision/delete
Cloudflare resources. DNS and tunnel provisioning remain separate and persist
when a share stops. Follow Cloudflare's
[local tunnel setup](https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/create-local-tunnel/)
for the account and DNS steps. If you choose a nested base such as
`apps.example.com`, ensure Cloudflare has an edge certificate covering
`web.apps.example.com`; a certificate for `*.example.com` does not cover it.

Each named share needs a distinct UUID. Do not run the same tunnel elsewhere
or as a background service: Cloudflare treats those processes as replicas
and may route a visitor to either. Kiri locks beside the credentials file to
prevent concurrent use of that file on this computer; that folder must be
writable. Do not copy the credentials to bypass the lock. Remotely managed
tunnel tokens are not supported by this integration.

## Manage shares

```sh
kiri share status --json
kiri share list --json
kiri share stop <ID-from-list>
kiri share provider kiri          # return to Kiri Cloud for new shares
```

The app shows Cloudflare shares opened by the CLI and app using the same
config directory, and its Stop action closes those shares on this computer.
Close existing shares before switching providers. Other computers' Cloudflare
tunnels are not listed. Cloudflare's own reconnect logic handles transient
network failures; Kiri observes its readiness endpoint. Startup times out
after 90 seconds. No background tunnel is installed as a system service.

Cloudflare forwards HTTP and WebSocket traffic. This integration does not
provide Kiri's per-request logs, traffic counters, Cloudflare account quotas,
or Kiri Cloud name reservation. Kiri's UI marks request statistics unavailable.
The selected provider affects sharing; Kiri's update and diagnostic-report
settings remain separate.

## Development checks

```sh
cargo build -p kiri
cargo test -p kiri share::
python3 tests/cloudflare-share.py target/debug/kiri
python3 scripts/ui-test.py
```

The lifecycle integration test uses a local fake cloudflared; it creates no
public tunnel and needs no account. A real custom-domain test requires the
domain, DNS record and tunnel credentials configured above.
