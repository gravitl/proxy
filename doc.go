// Module github.com/gravitl/proxy hosts Netmaker proxy libraries as subpackages.
//
// Import paths:
//
//	github.com/gravitl/proxy/uplink    — TCP/TLS framed WireGuard uplink transport
//	github.com/gravitl/proxy/l7       — HTTP CONNECT app-domain egress proxy
//	github.com/gravitl/proxy/sysproxy — PAC file + OS system proxy apply/clear
//
// The module root has no public API; use the packages above.
package proxy
