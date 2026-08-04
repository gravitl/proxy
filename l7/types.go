package l7

import (
	"errors"
	"time"
)

// Common errors returned by the L7 proxy.
var (
	ErrServerClosed = errors.New("l7: server closed")
	ErrForbidden    = errors.New("l7: destination not allowed")
	ErrBadRequest   = errors.New("l7: bad CONNECT request")
)

// ConnectTarget is the host:port from an HTTP CONNECT request.
type ConnectTarget struct {
	Host string
	Port string // e.g. "443"
}

// HostPort returns host:port for dialing.
func (t ConnectTarget) HostPort() string {
	if t.Port == "" {
		return t.Host
	}
	return t.Host + ":" + t.Port
}

// ServerOptions configures the CONNECT forward proxy.
type ServerOptions struct {
	// ListenAddr is the TCP address to bind (typically a mesh IP:port on the egress GW).
	ListenAddr string
	// Matcher decides whether a CONNECT target is allowed (required).
	Matcher DomainMatcher
	// Dialer is optional; nil uses net.Dialer with DialTimeout.
	Dialer Dialer
	// Logger is optional; nil uses a no-op logger.
	Logger Logger
	// DialTimeout bounds outbound dials and CONNECT header read (default 15s).
	DialTimeout time.Duration
	// IdleTimeout is the max lifetime of an established tunnel (default 5m).
	IdleTimeout time.Duration
}

// Logger is a minimal structured logging facade.
type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}
