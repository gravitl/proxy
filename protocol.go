package proxy

// Protocol version for Phase 1 framing.
const ProtocolVersion uint8 = 1

// Message types (spec §11.2).
const (
	MsgHello uint8 = iota + 1
	MsgHelloAck
	MsgData
	MsgPing
	MsgPong
	MsgClose
	MsgError
)

const (
	frameHeaderSize = 12
	// DefaultMaxFrameSize caps payload length (single frame) to limit memory use.
	DefaultMaxFrameSize = 65536
)
