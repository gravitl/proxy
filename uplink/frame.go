package uplink

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// FrameHeader is the 12-byte header (spec §11.1), big-endian.
type FrameHeader struct {
	Version    uint8
	MsgType    uint8
	Flags      uint16
	SessionID  uint32
	PayloadLen uint32
}

func encodeFrameHeader(h FrameHeader) [frameHeaderSize]byte {
	var b [frameHeaderSize]byte
	b[0] = h.Version
	b[1] = h.MsgType
	binary.BigEndian.PutUint16(b[2:4], h.Flags)
	binary.BigEndian.PutUint32(b[4:8], h.SessionID)
	binary.BigEndian.PutUint32(b[8:12], h.PayloadLen)
	return b
}

func decodeFrameHeader(b [frameHeaderSize]byte) FrameHeader {
	return FrameHeader{
		Version:    b[0],
		MsgType:    b[1],
		Flags:      binary.BigEndian.Uint16(b[2:4]),
		SessionID:  binary.BigEndian.Uint32(b[4:8]),
		PayloadLen: binary.BigEndian.Uint32(b[8:12]),
	}
}

var frameBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, frameHeaderSize+DefaultMaxFrameSize)
		return &b
	},
}

// writeFrame emits a frame in a single Write. Writing the header and payload
// separately allows a concurrent writer on the same connection to interleave
// between them, and allows a write deadline to expire mid-frame; either leaves a
// truncated frame that desynchronises the peer's framing for the life of the
// connection. Callers must still serialise writes per connection and must close
// the connection if this returns an error, since a single Write can also flush
// partially.
func writeFrame(w io.Writer, h FrameHeader, payload []byte) error {
	if uint32(len(payload)) != h.PayloadLen {
		return fmt.Errorf("proxy: payload length mismatch: %w", ErrInvalidFrame)
	}
	hdr := encodeFrameHeader(h)
	if len(payload) == 0 {
		_, err := w.Write(hdr[:])
		return err
	}

	need := frameHeaderSize + len(payload)
	bufPtr := frameBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	if cap(buf) < need {
		buf = make([]byte, 0, need)
	}
	buf = append(buf, hdr[:]...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	*bufPtr = buf[:0]
	frameBufPool.Put(bufPtr)
	return err
}

func readFrame(r io.Reader, maxPayload uint32) (FrameHeader, []byte, error) {
	var raw [frameHeaderSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return FrameHeader{}, nil, err
	}
	h := decodeFrameHeader(raw)
	if h.Version != ProtocolVersion {
		return FrameHeader{}, nil, ErrProtocolVersion
	}
	if h.PayloadLen > maxPayload {
		return FrameHeader{}, nil, ErrInvalidFrame
	}
	if h.PayloadLen == 0 {
		return h, nil, nil
	}
	payload := make([]byte, h.PayloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return FrameHeader{}, nil, err
	}
	return h, payload, nil
}

// encodeFrameBytes builds a complete framed message (header + payload) for
// message-oriented transports (e.g. one WebSocket binary message per frame).
// The length prefix is retained as compatibility framing; the message boundary
// also equals the uplink message boundary.
func encodeFrameBytes(h FrameHeader, payload []byte) ([]byte, error) {
	if uint32(len(payload)) != h.PayloadLen {
		return nil, fmt.Errorf("proxy: payload length mismatch: %w", ErrInvalidFrame)
	}
	hdr := encodeFrameHeader(h)
	out := make([]byte, 0, frameHeaderSize+len(payload))
	out = append(out, hdr[:]...)
	out = append(out, payload...)
	return out, nil
}

// decodeFrameBytes parses a complete framed message from a single buffer.
func decodeFrameBytes(msg []byte, maxPayload uint32) (FrameHeader, []byte, error) {
	if len(msg) < frameHeaderSize {
		return FrameHeader{}, nil, ErrInvalidFrame
	}
	var raw [frameHeaderSize]byte
	copy(raw[:], msg[:frameHeaderSize])
	h := decodeFrameHeader(raw)
	if h.Version != ProtocolVersion {
		return FrameHeader{}, nil, ErrProtocolVersion
	}
	if h.PayloadLen > maxPayload {
		return FrameHeader{}, nil, ErrInvalidFrame
	}
	if int(h.PayloadLen) != len(msg)-frameHeaderSize {
		return FrameHeader{}, nil, ErrInvalidFrame
	}
	if h.PayloadLen == 0 {
		return h, nil, nil
	}
	payload := make([]byte, h.PayloadLen)
	copy(payload, msg[frameHeaderSize:])
	return h, payload, nil
}
