// Package l7 provides an HTTP CONNECT forward proxy for name-based egress.
//
// Product intent: clients direct listed app domains to an egress gateway over the
// mesh (WireGuard underlay). The gateway runs this server, matches CONNECT targets
// against a domain policy, and dials the internet by hostname — avoiding brittle
// domain→IP→route collection used for L3 egress ranges.
//
// This package does not own Netmaker control-plane config or WireGuard.
// Client PAC / OS system-proxy helpers live in package sysproxy.
// See docs/PROXY_L7_EGRESS.md.
package l7
