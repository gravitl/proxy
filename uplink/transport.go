package uplink

import "time"

// Conn is the transport used by uplink session logic.
// Implementations must be safe for one reader and one writer concurrently
// (writer serialisation is the caller's responsibility unless documented otherwise).
type Conn interface {
	// ReadFrame reads the next uplink protocol frame.
	ReadFrame(maxPayload uint32) (FrameHeader, []byte, error)
	// WriteFrame writes one uplink protocol frame.
	WriteFrame(h FrameHeader, payload []byte) error
	// Close closes the underlying transport.
	Close() error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
