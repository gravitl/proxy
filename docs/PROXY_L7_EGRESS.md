# L7 egress proxy — HTTP CONNECT for app domains

**Packages:** `github.com/gravitl/proxy/l7`, `github.com/gravitl/proxy/sysproxy`  
**Status:** CONNECT MVP + Netmaker integration (`routing_mode=proxy`).

## Problem

Egress “app domains” today often resolve domain → IPs, publish ranges, and install WireGuard routes. That is brittle for global SaaS/CDN (IP churn, shared IPs, wildcards).

## Modes (per app egress)

| `routing_mode` | Behavior |
|----------------|----------|
| `ip` (default) | Existing path: resolve → `EgressWithDomains` → `/32` routes via egress GW |
| `proxy` | No domain IP routes. Clients use HTTP CONNECT through the egress GW |

## End-to-end flow (`proxy`)

```text
UI: create app egress with routing_mode=proxy
  → netmaker stores domains; skips EGRESS_UPDATE
  → PeerUpdate / HostPull includes egress_proxy_routes[]
       { domains, node_id, proxy_addr=meshIP:3128 }

Egress GW netclient:
  → starts l7.Server on mesh IP:3128 with Allowlist(domains)

Other netclients:
  → local CONNECT forwarder on 127.0.0.1:17832
  → writes egress_proxy.pac and applies OS system PAC automatically
  → browser / PAC-aware apps → CONNECT api.foo.com → forwarder → GW over WG → dial by name
```

WireGuard only carries TCP to the **mesh proxy address**. CDN IPs are never installed as client WG routes.

## Client usage (automatic)

`sysproxy` (called by netclient) writes the PAC and applies/clears the OS proxy:

| Platform | Mechanism |
|----------|-----------|
| macOS | `networksetup -setautoproxyurl` / `-setautoproxystate` on active services |
| Windows | `AutoConfigURL` in Internet Settings (current user + loaded user hives) |
| Linux | GNOME `gsettings` auto PAC + optional `/etc/profile.d` drop-in |

API: `sysproxy.WritePAC`, `sysproxy.Apply`, `sysproxy.Clear`.

Browsers that honor system PAC need no manual config. When all proxy routes are removed (or the daemon stops), the system PAC is cleared.

CLI tools that ignore system proxy can still use:

```bash
export HTTPS_PROXY=http://127.0.0.1:17832
curl -v https://allowed.example.com/
```

**Not supported via proxy:** ICMP/`ping`, most UDP. Use `routing_mode=ip` or internet egress for those.

## Package API (`l7`)

- `DomainMatcher` / `Allowlist` / `AllowAll`
- `Server` — CONNECT accept, ACL, dial, bidirectional pipe
- Responses: `200` / `403` / `400` / `502`

## Package API (`sysproxy`)

- `WritePAC(path, domains, proxyHostPort)` — PAC that steers listed domains
- `Apply(pacPath, Options)` / `Clear(Options)` — install/remove OS auto-proxy

## Netclient

- `internal/proxyegress.ApplyProxyRoutes` — wires `l7` + `sysproxy` from peer update / pull
- `internal/proxyegress.Stop()` on daemon teardown (calls `sysproxy.Clear`)

## Control plane fields

- `schema.Egress.RoutingMode` — `ip` | `proxy`
- `models.EgressProxyRoute` on `HostPeerUpdate` / `HostPull`
- Node `EgressProxyListenPort` (default 3128)

## Relation to `uplink`

| `uplink` | `l7` / proxy egress |
|----------|---------------------|
| Framed WG ciphertext C↔B | HTTP CONNECT for app domains |
| UDP-blocked uplink | Avoid domain IP management |
