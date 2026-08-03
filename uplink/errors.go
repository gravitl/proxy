package uplink

import "errors"

var (
	// ErrNoSession is returned when SendToPeer cannot find an active session for the peer.
	ErrNoSession = errors.New("proxy: no active session for peer")
	// ErrSessionClosed is returned when writing to a closed session.
	ErrSessionClosed = errors.New("proxy: session closed")
	// ErrInvalidFrame is returned for malformed or oversized frames.
	ErrInvalidFrame = errors.New("proxy: invalid frame")
	// ErrProtocolVersion is returned when the peer uses an unsupported protocol version.
	ErrProtocolVersion = errors.New("proxy: unsupported protocol version")
	// ErrAuthFailed is returned when authentication fails (client-side).
	ErrAuthFailed = errors.New("proxy: authentication failed")
	// ErrServerClosed is returned when the server is not running.
	ErrServerClosed = errors.New("proxy: server closed")
	// ErrClientClosed is returned when the client is not running or connection is gone.
	ErrClientClosed = errors.New("proxy: client not connected")
)
