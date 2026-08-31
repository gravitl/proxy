package uplink

import (
	"errors"
	"fmt"
	"strings"
)

// TLSMode controls where TLS is terminated for the uplink HTTP/WebSocket listener.
type TLSMode string

const (
	// TLSModeSelfSigned: uplink terminates TLS with a persisted self-signed certificate.
	TLSModeSelfSigned TLSMode = "selfsigned"
	// TLSModeProxy: upstream reverse proxy terminates TLS; uplink serves plain HTTP/WS.
	TLSModeProxy TLSMode = "proxy"
)

// DefaultTLSMode is used when TLS mode is omitted.
const DefaultTLSMode = TLSModeSelfSigned

// ParseTLSMode validates and normalises a TLS mode string.
// Empty input returns DefaultTLSMode (selfsigned).
func ParseTLSMode(s string) (TLSMode, error) {
	m := TLSMode(strings.ToLower(strings.TrimSpace(s)))
	if m == "" {
		return DefaultTLSMode, nil
	}
	switch m {
	case TLSModeSelfSigned, TLSModeProxy:
		return m, nil
	default:
		return "", fmt.Errorf("unsupported uplink TLS mode: %s", s)
	}
}

// Validate reports whether m is a supported TLS mode.
func (m TLSMode) Validate() error {
	switch m {
	case TLSModeSelfSigned, TLSModeProxy:
		return nil
	case "":
		return errors.New("unsupported uplink TLS mode: (empty)")
	default:
		return fmt.Errorf("unsupported uplink TLS mode: %s", m)
	}
}
