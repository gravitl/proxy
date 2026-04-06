# proxy

WireGuard TCP/TLS uplink transport for Netmaker-style relay paths.

## Library

Import path: `github.com/gravitl/proxy`

- **Client**: TCP + TLS + framed `MsgData` carrying WireGuard packet bytes to the relay.
- **Server** (relay / gateway, also a WireGuard peer): terminates TLS, authenticates `ClientHello`, registers sessions, and supports `SendToPeer` for reverse traffic.

See package documentation and `example_test.go` for wiring patterns.

## Develop

```bash
go test ./... -race
```

