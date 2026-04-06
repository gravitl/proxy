package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
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

func writeFrame(w io.Writer, h FrameHeader, payload []byte) error {
	if uint32(len(payload)) != h.PayloadLen {
		return fmt.Errorf("proxy: payload length mismatch: %w", ErrInvalidFrame)
	}
	hdr := encodeFrameHeader(h)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
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
