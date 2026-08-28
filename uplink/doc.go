// Package uplink provides a WebSocket Secure (WSS) framed transport for carrying
// WireGuard packet payloads between a relay-attached peer and its relay/gateway.
//
// The application transport is always WebSocket (/uplink/v1). TLS termination is
// configurable independently:
//
//   - selfsigned (default): uplink terminates TLS with a persisted certificate
//   - proxy: an upstream reverse proxy terminates TLS; uplink serves plain WS
//
// Each WebSocket binary message carries one uplink protocol frame (12-byte header
// + payload). The length prefix is retained as compatibility framing.
//
// It owns connection setup, framing, session lifecycle, keepalive, and
// peer→session registration for reverse traffic. It does not implement routing
// policy, relay selection, or Netmaker control-plane logic—integrate those in a
// separate adapter.
//
// For application-layer (HTTP CONNECT) egress, see package l7.
package uplink
