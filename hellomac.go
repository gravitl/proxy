package proxy

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
)

// HelloMACInput returns the stable byte sequence covered by ClientHello.Proof.
// Proof itself is excluded so the client can compute the MAC before setting it.
func HelloMACInput(h ClientHello) []byte {
	// version|node_id|relay_peer_id|network_id|public_key|timestamp
	return []byte(strconv.Itoa(h.Version) + "|" +
		h.NodeID + "|" +
		h.RelayPeerID + "|" +
		h.NetworkID + "|" +
		h.PublicKey + "|" +
		strconv.FormatInt(h.Timestamp, 10))
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
