package uplink

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"
)

func TestClientServerDataRoundTrip(t *testing.T) {
	srvTLS, cliTLS := testTLSConfigs(t)

	var received [][]byte
	var mu sync.Mutex
	var srv *Server

	ph := &fnPacketHandler{fn: func(ctx context.Context, peerID string, pkt []byte) error {
		mu.Lock()
		received = append(received, append([]byte(nil), pkt...))
		mu.Unlock()
		return srv.SendToPeer(ctx, peerID, pkt)
	}}

	auth := &fnAuthenticator{fn: func(ctx context.Context, hello ClientHello) (*AuthResult, error) {
		return &AuthResult{PeerID: "peer-1"}, nil
	}}

	s, err := NewServer(ServerOptions{
		ListenAddr:    "127.0.0.1:0",
		TLSConfig:     srvTLS,
		Authenticator: auth,
		PacketHandler: ph,
		Logger:        noopLogger{},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv = s

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr := s.Addr().String()

	var inbound [][]byte
	var inMu sync.Mutex
	cli, err := NewClient(ClientOptions{
		Addr: addr,
		TLSConfig: func() *tls.Config {
			c := cliTLS.Clone()
			c.ServerName = "test.local"
			return c
		}(),
		HelloFactory: func() (ClientHello, error) {
			return ClientHello{Version: 1, NodeID: "n1", RelayPeerID: "r1", PublicKey: "pk", Proof: "p"}, nil
		},
		PacketHandler: func(b []byte) error {
			inMu.Lock()
			inbound = append(inbound, append([]byte(nil), b...))
			inMu.Unlock()
			return nil
		},
		Logger:          noopLogger{},
		KeepAlivePeriod: time.Hour, // avoid ping noise in test
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for cli.State() != StateActive {
		select {
		case <-deadline:
			t.Fatalf("client not active: %s", cli.State())
		case <-time.After(10 * time.Millisecond):
		}
	}

	pkt := []byte{0x01, 0x02, 0x03}
	if err := cli.SendPacket(ctx, pkt); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	got := append([][]byte(nil), received...)
	mu.Unlock()
	if len(got) != 1 || string(got[0]) != string(pkt) {
		t.Fatalf("server got %v want %v", got, pkt)
	}

	inMu.Lock()
	gotIn := append([][]byte(nil), inbound...)
	inMu.Unlock()
	if len(gotIn) != 1 || string(gotIn[0]) != string(pkt) {
		t.Fatalf("client inbound %v want %v", gotIn, pkt)
	}

	_ = cli.Stop(context.Background())
	_ = s.Stop(context.Background())
}

// TestServerStopClosesSessions ensures Stop closes attached TLS sessions so a client
// leaves StateActive (gateway soft-restart must force re-HELLO onto a new server).
func TestServerStopClosesSessions(t *testing.T) {
	srvTLS, cliTLS := testTLSConfigs(t)

	s, err := NewServer(ServerOptions{
		ListenAddr: "127.0.0.1:0",
		TLSConfig:  srvTLS,
		Authenticator: &fnAuthenticator{fn: func(ctx context.Context, hello ClientHello) (*AuthResult, error) {
			return &AuthResult{PeerID: "peer-1"}, nil
		}},
		PacketHandler: &fnPacketHandler{fn: func(ctx context.Context, peerID string, pkt []byte) error {
			return nil
		}},
		Logger: noopLogger{},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	cli, err := NewClient(ClientOptions{
		Addr: s.Addr().String(),
		TLSConfig: func() *tls.Config {
			c := cliTLS.Clone()
			c.ServerName = "test.local"
			return c
		}(),
		HelloFactory: func() (ClientHello, error) {
			return ClientHello{Version: 1, NodeID: "n1", RelayPeerID: "r1", PublicKey: "pk", Proof: "p"}, nil
		},
		PacketHandler:   func(b []byte) error { return nil },
		Logger:          noopLogger{},
		KeepAlivePeriod: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for cli.State() != StateActive {
		select {
		case <-deadline:
			t.Fatalf("client not active: %s", cli.State())
		case <-time.After(10 * time.Millisecond):
		}
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if err := s.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	deadline = time.After(3 * time.Second)
	for cli.State() == StateActive {
		select {
		case <-deadline:
			t.Fatal("client still Active after Server.Stop; session was not closed")
		case <-time.After(10 * time.Millisecond):
		}
	}

	_ = cli.Stop(context.Background())
}

type fnPacketHandler struct {
	fn func(context.Context, string, []byte) error
}

func (f *fnPacketHandler) HandleInboundPacket(ctx context.Context, peerID string, pkt []byte) error {
	return f.fn(ctx, peerID, pkt)
}

type fnAuthenticator struct {
	fn func(context.Context, ClientHello) (*AuthResult, error)
}

func (f *fnAuthenticator) ValidateClientHello(ctx context.Context, hello ClientHello) (*AuthResult, error) {
	return f.fn(ctx, hello)
}

func testTLSConfigs(t *testing.T) (server *tls.Config, client *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial := big.NewInt(1)
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"test.local"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	cli := &tls.Config{
		RootCAs: func() *x509.CertPool {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(certPEM)
			return pool
		}(),
		ServerName: "test.local",
		MinVersion: tls.VersionTLS12,
	}
	return srv, cli
}
