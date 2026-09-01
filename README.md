# proxy

Netmaker proxy libraries (one Go module, feature packages).

## Packages

| Import | Role |
|--------|------|
| [`github.com/gravitl/proxy/uplink`](uplink/) | Framed WireGuard uplink over WebSocket (`C` ↔ relay/gateway `B`) |
| [`github.com/gravitl/proxy/l7`](l7/) | L7: HTTP CONNECT forward proxy for app-domain egress |

There is **no** root package API — import the subpackage you need.

### Uplink

Application transport is always **WebSocket** on `/uplink/v1`. Each binary message carries one uplink frame (12-byte header + payload) with `MsgData` WireGuard packet bytes.

TLS termination is independent of that transport:

| Mode | Value | Behavior |
|------|-------|----------|
| Self-signed (default) | `selfsigned` | Uplink terminates TLS and serves `wss://` |
| Reverse proxy | `proxy` | Upstream proxy terminates TLS; uplink serves plain `ws://` on an internal bind |

- **Client** dials `wss://…/uplink/v1` (or `ws://` when the listener is behind a TLS terminator), completes `ClientHello` authentication (WireGuard key proofs), then exchanges framed `MsgData` and keepalive pings.
- **Server** (relay / gateway, still a WireGuard peer) accepts the WebSocket, authenticates, registers sessions, and supports `SendToPeer` for reverse traffic.

See [`uplink/example_test.go`](uplink/example_test.go), [docs/PROXY_WSS_UPLINK.md](docs/PROXY_WSS_UPLINK.md), and [docs/PROXY_PHASE1_ARCHITECTURE.md](docs/PROXY_PHASE1_ARCHITECTURE.md).

### L7

Name-based egress via HTTP CONNECT over the mesh (underlay remains WireGuard). See [docs/PROXY_L7_EGRESS.md](docs/PROXY_L7_EGRESS.md).

## Develop

```bash
go test ./... -race
```

## Release

From GitHub Actions → **Release** → **Run workflow**: enter a semver (`v0.1.0` or `0.1.0`). The workflow runs tests, pushes an annotated tag, and creates a GitHub Release (notes auto-generated). Consumers can then:

```bash
go get github.com/gravitl/proxy/l7@v0.1.0
```
