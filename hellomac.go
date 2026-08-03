package proxy

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// HelloMACInput returns the stable byte sequence covered by ClientHello.Proof.
// Proof itself is excluded so the client can compute the MAC before setting it.
//
// Encoding is length-prefixed to avoid delimiter ambiguity:
//   version (uint32 BE) ||
//   len||node_id || len||relay_peer_id || len||network_id || len||public_key ||
//   timestamp (int64 BE)
// where each len is a uint32 big-endian byte length of the following field.
func HelloMACInput(h ClientHello) []byte {
	n := 4 + 4 + len(h.NodeID) + 4 + len(h.RelayPeerID) + 4 + len(h.NetworkID) + 4 + len(h.PublicKey) + 8
	b := make([]byte, 0, n)
	var tmp [8]byte
	binary.BigEndian.PutUint32(tmp[:4], uint32(h.Version))
	b = append(b, tmp[:4]...)
	b = appendLenPrefixed(b, h.NodeID)
	b = appendLenPrefixed(b, h.RelayPeerID)
	b = appendLenPrefixed(b, h.NetworkID)
	b = appendLenPrefixed(b, h.PublicKey)
	binary.BigEndian.PutUint64(tmp[:], uint64(h.Timestamp))
	b = append(b, tmp[:]...)
	return b
}

func appendLenPrefixed(b []byte, s string) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
	b = append(b, lenBuf[:]...)
	return append(b, s...)
}

// ComputeHelloProof builds Proof = base64(HMAC-SHA256(X25519(ourPriv, peerPub), macInput)).
// ourPriv and peerPub are raw 32-byte WireGuard Curve25519 keys.
func ComputeHelloProof(ourPriv, peerPub *[32]byte, macInput []byte) (string, error) {
	if ourPriv == nil || peerPub == nil {
		return "", fmt.Errorf("proxy: nil key for hello proof")
	}
	priv, err := ecdh.X25519().NewPrivateKey(ourPriv[:])
	if err != nil {
		return "", fmt.Errorf("proxy: x25519 private key: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub[:])
	if err != nil {
		return "", fmt.Errorf("proxy: x25519 public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return "", fmt.Errorf("proxy: x25519 ecdh: %w", err)
	}
	mac := hmac.New(sha256.New, shared)
	_, _ = mac.Write(macInput)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyHelloProof checks Proof against the expected MAC for this hello.
func VerifyHelloProof(ourPriv, peerPub *[32]byte, h ClientHello) bool {
	if h.Proof == "" || ourPriv == nil || peerPub == nil {
		return false
	}
	want, err := ComputeHelloProof(ourPriv, peerPub, HelloMACInput(h))
	if err != nil {
		return false
	}
	gotRaw, err1 := base64.StdEncoding.DecodeString(h.Proof)
	wantRaw, err2 := base64.StdEncoding.DecodeString(want)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(gotRaw, wantRaw)
}
