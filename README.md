# proxy

Netmaker proxy libraries (one Go module, feature packages).

## Packages

| Import | Role |
|--------|------|
| [`github.com/gravitl/proxy/uplink`](uplink/) | Phase 1: TCP/TLS framed WireGuard uplink (C ↔ relay/gateway B) |
| [`github.com/gravitl/proxy/l7`](l7/) | L7: HTTP CONNECT forward proxy for app-domain egress |

There is **no** root package API — import the subpackage you need.

### Uplink

- **Client**: TCP + TLS + framed `MsgData` carrying WireGuard packet bytes to the relay.
- **Server** (relay / gateway, also a WireGuard peer): terminates TLS, authenticates `ClientHello`, registers sessions, and supports `SendToPeer` for reverse traffic.

See [`uplink/example_test.go`](uplink/example_test.go) and [docs/PROXY_PHASE1_ARCHITECTURE.md](docs/PROXY_PHASE1_ARCHITECTURE.md).

### L7

Name-based egress via HTTP CONNECT over the mesh (underlay remains WireGuard). See [docs/PROXY_L7_EGRESS.md](docs/PROXY_L7_EGRESS.md).

## Develop

```bash
go test ./... -race
```
