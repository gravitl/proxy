package uplink

import (
	"bytes"
	"testing"
)

func TestWriteReadFrame(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello-wg")
	h := FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    MsgData,
		SessionID:  42,
		PayloadLen: uint32(len(payload)),
	}
	if err := writeFrame(&buf, h, payload); err != nil {
		t.Fatal(err)
	}
	rh, rp, err := readFrame(&buf, DefaultMaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if rh.MsgType != MsgData || rh.SessionID != 42 || string(rp) != string(payload) {
		t.Fatalf("got %+v %q", rh, rp)
	}
}

func TestReadFrameOversize(t *testing.T) {
	var buf bytes.Buffer
	p := bytes.Repeat([]byte("x"), 100)
	h := FrameHeader{Version: ProtocolVersion, MsgType: MsgData, PayloadLen: uint32(len(p))}
	_ = writeFrame(&buf, h, p)
	_, _, err := readFrame(&buf, 50)
	if err != ErrInvalidFrame {
		t.Fatalf("want ErrInvalidFrame, got %v", err)
	}
}

func TestEncodeDecodeFrameBytes(t *testing.T) {
	payload := []byte("hello-wg")
	h := FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    MsgData,
		SessionID:  7,
		PayloadLen: uint32(len(payload)),
	}
	msg, err := encodeFrameBytes(h, payload)
	if err != nil {
		t.Fatal(err)
	}
	rh, rp, err := decodeFrameBytes(msg, DefaultMaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if rh.MsgType != MsgData || rh.SessionID != 7 || string(rp) != string(payload) {
		t.Fatalf("got %+v %q", rh, rp)
	}
}

func TestDecodeFrameBytesOversize(t *testing.T) {
	p := bytes.Repeat([]byte("x"), 100)
	h := FrameHeader{Version: ProtocolVersion, MsgType: MsgData, PayloadLen: uint32(len(p))}
	msg, err := encodeFrameBytes(h, p)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = decodeFrameBytes(msg, 50)
	if err != ErrInvalidFrame {
		t.Fatalf("want ErrInvalidFrame, got %v", err)
	}
}
