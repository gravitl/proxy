package proxy

import "time"

// ClientHello is serialized as JSON in MsgHello payload (spec §12).
type ClientHello struct {
	Version     int    `json:"version"`
	NodeID      string `json:"node_id"`
	RelayPeerID string `json:"relay_peer_id"`
	NetworkID   string `json:"network_id,omitempty"`
	Token       string `json:"token"`
	Timestamp   int64  `json:"timestamp"`
}

// AuthResult is produced by Authenticator after validating ClientHello.
type AuthResult struct {
	PeerID       string
	RelayPeerID  string
	NetworkID    string
	SessionScope map[string]string
}

// helloAckWire is JSON for MsgHelloAck payload.
type helloAckWire struct {
	SessionID uint32 `json:"session_id"`
}

// errorPayloadWire is JSON for MsgError payload.
type errorPayloadWire struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ClientState (spec §13.1).
type ClientState string

const (
	StateDisconnected   ClientState = "disconnected"
	StateConnecting     ClientState = "connecting"
	StateTLSReady       ClientState = "tls_ready"
	StateAuthenticating ClientState = "authenticating"
	StateActive         ClientState = "active"
	StateClosing        ClientState = "closing"
	StateFailed         ClientState = "failed"
)

// SessionState (spec §13.2).
type SessionState string

const (
	SessionPending       SessionState = "pending"
	SessionAuthenticated SessionState = "authenticated"
	SessionAttached      SessionState = "attached"
	SessionStale         SessionState = "stale"
	SessionClosed        SessionState = "closed"
)

// BackoffConfig controls reconnect delays on the client.
type BackoffConfig struct {
	Initial time.Duration
	Max     time.Duration
	Factor  float64 // >= 1.0; multiplier applied after each failed attempt
}

func (b BackoffConfig) withDefaults() BackoffConfig {
	if b.Initial <= 0 {
		b.Initial = time.Second
	}
	if b.Max <= 0 {
		b.Max = 30 * time.Second
	}
	if b.Factor < 1.0 {
		b.Factor = 1.5
	}
	return b
}
