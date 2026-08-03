# L7 egress proxy — HTTP CONNECT for app domains

**Package:** `github.com/gravitl/proxy/l7`  
**Status:** HTTP CONNECT MVP implemented (listen, ACL, dial, bidirectional tunnel).

## Problem

Egress “app domains” today often resolve domain → IPs, publish ranges, and install WireGuard routes. That is brittle (CDN churn, shared IPs, wildcards).

## Approach

Keep the **WireGuard underlay** to the egress gateway. For listed domains, the **client** directs traffic to an L7 proxy on the gateway (proxy settings / PAC / netclient-managed). The gateway dials by **hostname**.

```text
App --HTTPS--> client proxy settings
       --CONNECT api.foo.com:443--> GW_mesh_IP:l7_port   (over WG)
       --GW dials api.foo.com--> internet
```

| Role | Responsibility |
|------|----------------|
| Client / control plane | Which domains use egress L7 |
| WireGuard | Path from client to egress GW |
| `l7.Server` on GW | CONNECT + domain ACL + dial-out |

CIDR / network egress remains L3. L7 is additive for named apps.

## Package API

- `DomainMatcher` / `Allowlist` / `AllowAll` — exact and `*.suffix` domain rules
- `ServerOptions` — `ListenAddr`, `Matcher` (required), optional `Dialer`, timeouts, logger
- `Server.Start` / `Stop` / `Addr` — TCP listen and CONNECT handling
- Responses: `200 Connection Established`, `403` deny, `400` bad request, `502` dial failure

## Non-goals (for now)

- SOCKS5, transparent TPROXY, TLS MITM
- PAC generation, UI, control-plane domain publishing (netclient follow-up)
- Sharing code with `uplink` framed WG transport

## Relation to `uplink`

| `uplink` | `l7` |
|----------|------|
| Framed WG ciphertext C↔B | HTTP CONNECT to egress GW |
| Userspace Bind inject | `net.Dial` to internet hostnames |
| Same module, separate import | `github.com/gravitl/proxy/l7` |

## Example (gateway side)

```go
srv, err := l7.NewServer(l7.ServerOptions{
    ListenAddr: "0.0.0.0:3128", // prefer mesh IP in production
    Matcher:    l7.Allowlist{Domains: []string{"api.foo.com", "*.saas.com"}},
})
// srv.Start(ctx) … srv.Stop(ctx)
```
