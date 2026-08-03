// Package uplink provides a TCP/TLS framed transport for carrying WireGuard packet
// payloads between a relay-attached peer and its relay/gateway (Phase 1 uplink).
//
// It owns connection setup, TLS, framing, session lifecycle, keepalive, and
// peer→session registration for reverse traffic. It does not implement routing policy,
// relay selection, or Netmaker control-plane logic—integrate those in a separate adapter.
//
// For application-layer (HTTP CONNECT) egress, see package l7.
package uplink
