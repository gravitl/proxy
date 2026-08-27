# TCP Uplink WebSocket Transport

Netmaker TCP uplink uses **WebSocket** (`/uplink/v1`) as the application transport in every deployment. TLS termination is configured independently via `tcp_proxy_tls_mode`.

## TLS modes

| Mode | Value | Behavior |
|------|-------|----------|
| Self-signed (default) | `selfsigned` | Uplink terminates TLS with a persisted self-signed certificate and serves `wss://` |
| Reverse proxy | `proxy` | Upstream reverse proxy terminates TLS; uplink serves plain `ws://` on an internal bind |

Invalid modes fail startup/API with: `unsupported uplink TLS mode: …`

## Standalone gateway

```json
{
  "enabled": true,
  "listen_port": 443,
  "tls_mode": "selfsigned"
}
```

Client dials: `wss://<gateway-ip>:443/uplink/v1`

## Behind a reverse proxy

```json
{
  "enabled": true,
  "listen_port": 51822,
  "listen_addr": "127.0.0.1",
  "tls_mode": "proxy",
  "public_hostname": "gateway.example.com"
}
```

- `listen_port` / `listen_addr` are the **backend** bind (what Caddy/nginx proxies to).
- Set gateway `tcp_proxy_public_hostname` (e.g. `gateway.example.com`) so clients dial the reverse-proxy DNS name.
- Clients are published `wss://<public-hostname-or-ip>:<public-port>/uplink/v1` in `proxy` mode.
- Public port defaults to **443** (server env `TCP_PROXY_PUBLIC_PORT` can override).
- The reverse proxy must expose that public port and forward `/uplink/v1` to the backend.

Generic reverse-proxy route (works with Caddy, nginx, HAProxy, Ingress, etc.):

```text
:443 /uplink/v1  →  127.0.0.1:51822
```

Example Caddy (documentation only — not required by the implementation):

```caddy
gateway.example.com {
    reverse_proxy /uplink/v1 127.0.0.1:51822
}
```

Client dials: `wss://gateway.example.com:443/uplink/v1` (falls back to gateway IP if hostname unset)

## Client trust

- Public / reverse-proxy certificates: normal system TLS verification
- Self-signed gateways: SHA-256 leaf fingerprint published as `tcp_proxy_cert_fingerprint`
- Temporary legacy: IP dial without fingerprint may skip verify (deprecated)

## Origin policy

Netclient is a machine client and typically sends no browser `Origin` header. The uplink WebSocket upgrader accepts missing Origin; authentication remains the HELLO/WG-proof security boundary.
