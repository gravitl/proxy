package uplink

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func TestHelloMACInputNoDelimiterAmbiguity(t *testing.T) {
	a := HelloMACInput(ClientHello{
		Version: 1, NodeID: "a|b", RelayPeerID: "r", NetworkID: "", PublicKey: "pk", Timestamp: 1,
	})
	b := HelloMACInput(ClientHello{
		Version: 1, NodeID: "a", RelayPeerID: "b|r", NetworkID: "", PublicKey: "pk", Timestamp: 1,
	})
	c := HelloMACInput(ClientHello{
		Version: 1, NodeID: "a", RelayPeerID: "r", NetworkID: "b", PublicKey: "pk", Timestamp: 1,
	})
	if bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(b, c) {
		t.Fatal("length-prefixed MAC input should distinguish field boundaries")
	}
}

func TestHelloProofRoundTrip(t *testing.T) {
	clientKP, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gwKP, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var clientPriv, gwPriv, clientPub, gwPub [32]byte
	copy(clientPriv[:], clientKP.Bytes())
	copy(gwPriv[:], gwKP.Bytes())
	copy(clientPub[:], clientKP.PublicKey().Bytes())
	copy(gwPub[:], gwKP.PublicKey().Bytes())

	h := ClientHello{
		Version:     1,
		NodeID:      "node-1",
		RelayPeerID: "gw-1",
		NetworkID:   "net",
		PublicKey:   "client-pub-b64",
		Timestamp:   1700000000,
	}
	proof, err := ComputeHelloProof(&clientPriv, &gwPub, HelloMACInput(h))
	if err != nil {
		t.Fatal(err)
	}
	h.Proof = proof

	if !VerifyHelloProof(&gwPriv, &clientPub, h) {
		t.Fatal("gateway failed to verify client proof")
	}

	h.NodeID = "tampered"
	if VerifyHelloProof(&gwPriv, &clientPub, h) {
		t.Fatal("tampered hello should fail")
	}
}
