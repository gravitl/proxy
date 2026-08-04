package uplink

import "context"

// PacketHandler receives inbound DATA frames on the server (spec §10.1).
type PacketHandler interface {
	HandleInboundPacket(ctx context.Context, peerID string, pkt []byte) error
}

// Authenticator validates ClientHello after MsgHello (spec §10.2).
type Authenticator interface {
	ValidateClientHello(ctx context.Context, hello ClientHello) (*AuthResult, error)
}

// SessionRegistry tracks peer ID to active session (spec §10.3).
type SessionRegistry interface {
	Attach(peerID string, sess Session) error
	Get(peerID string) (Session, bool)
	Detach(peerID string)
}

// Session is the handle stored per attached peer (spec §14).
type Session interface {
	PeerID() string
	State() SessionState
}

// Logger is a structured logging facade (spec §10.4).
type Logger interface {
	Debug(msg string, kv ...any)
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, kv ...any)
}

// MetricsSink is optional telemetry (spec §10.5).
type MetricsSink interface {
	IncCounter(name string, labels map[string]string)
	ObserveHistogram(name string, value float64, labels map[string]string)
	SetGauge(name string, value float64, labels map[string]string)
}
