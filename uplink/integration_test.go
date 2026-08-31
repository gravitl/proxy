package uplink

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func testClientURL(t *testing.T, s *Server, scheme string) string {
	t.Helper()
	addr := s.Addr()
	if addr == nil {
		t.Fatal("nil server addr")
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	if host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s://%s/uplink/v1", scheme, net.JoinHostPort(host, port))
}

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
		TLSMode:       TLSModeSelfSigned,
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
	url := testClientURL(t, s, "wss")

	var inbound [][]byte
	var inMu sync.Mutex
	cli, err := NewClient(ClientOptions{
		Addr: url,
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

func TestProxyTLSModePlainWS(t *testing.T) {
	var received [][]byte
	var mu sync.Mutex

	s, err := NewServer(ServerOptions{
		ListenAddr: "127.0.0.1:0",
		TLSMode:    TLSModeProxy,
		Authenticator: &fnAuthenticator{fn: func(ctx context.Context, hello ClientHello) (*AuthResult, error) {
			return &AuthResult{PeerID: "peer-1"}, nil
		}},
		PacketHandler: &fnPacketHandler{fn: func(ctx context.Context, peerID string, pkt []byte) error {
			mu.Lock()
			received = append(received, append([]byte(nil), pkt...))
			mu.Unlock()
			return nil
		}},
		Logger: noopLogger{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Stop(context.Background()) }()

	cli, err := NewClient(ClientOptions{
		Addr: testClientURL(t, s, "ws"),
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
	defer func() { _ = cli.Stop(context.Background()) }()

	deadline := time.After(5 * time.Second)
	for cli.State() != StateActive {
		select {
		case <-deadline:
			t.Fatalf("client not active: %s", cli.State())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := cli.SendPacket(ctx, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || string(received[0]) != "hi" {
		t.Fatalf("got %v", received)
	}
}

func TestDefaultTLSModeSelfSigned(t *testing.T) {
	mode, err := ParseTLSMode("")
	if err != nil || mode != TLSModeSelfSigned {
		t.Fatalf("got %q %v", mode, err)
	}
}

func TestInvalidTLSMode(t *testing.T) {
	_, err := NewServer(ServerOptions{
		ListenAddr: "127.0.0.1:0",
		TLSMode:    "acme",
		Authenticator: &fnAuthenticator{fn: func(ctx context.Context, hello ClientHello) (*AuthResult, error) {
			return &AuthResult{PeerID: "p"}, nil
		}},
		PacketHandler: &fnPacketHandler{fn: func(ctx context.Context, peerID string, pkt []byte) error {
			return nil
		}},
	})
	if err == nil {
		t.Fatal("expected error for invalid TLS mode")
	}
}

func TestWrongRouteRejected(t *testing.T) {
	s, err := NewServer(ServerOptions{
		ListenAddr: "127.0.0.1:0",
		TLSMode:    TLSModeProxy,
		Authenticator: &fnAuthenticator{fn: func(ctx context.Context, hello ClientHello) (*AuthResult, error) {
			return &AuthResult{PeerID: "p"}, nil
		}},
		PacketHandler: &fnPacketHandler{fn: func(ctx context.Context, peerID string, pkt []byte) error {
			return nil
		}},
		Logger: noopLogger{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Stop(context.Background()) }()

	addr := s.Addr().String()
	_, err = DialWebSocket(ctx, "ws://"+addr+"/wrong", nil, time.Second)
	if err == nil {
		t.Fatal("expected dial to wrong path to fail")
	}
}

func TestAuthRejected(t *testing.T) {
	s, err := NewServer(ServerOptions{
		ListenAddr: "127.0.0.1:0",
		TLSMode:    TLSModeProxy,
		Authenticator: &fnAuthenticator{fn: func(ctx context.Context, hello ClientHello) (*AuthResult, error) {
			return nil, errorsNew("nope")
		}},
		PacketHandler: &fnPacketHandler{fn: func(ctx context.Context, peerID string, pkt []byte) error {
			return nil
		}},
		Logger: noopLogger{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Stop(context.Background()) }()

	cli, err := NewClient(ClientOptions{
		Addr: testClientURL(t, s, "ws"),
		HelloFactory: func() (ClientHello, error) {
			return ClientHello{Version: 1, NodeID: "n1", RelayPeerID: "r1", PublicKey: "pk", Proof: "p"}, nil
		},
		PacketHandler:   func(b []byte) error { return nil },
		Logger:          noopLogger{},
		KeepAlivePeriod: time.Hour,
		ReconnectBackoff: BackoffConfig{Initial: 50 * time.Millisecond, Max: 100 * time.Millisecond, Factor: 1.5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Stop(context.Background()) }()

	time.Sleep(300 * time.Millisecond)
	if cli.State() == StateActive {
		t.Fatal("client should not be active after auth failure")
	}
}

func errorsNew(s string) error { return fmt.Errorf("%s", s) }

func TestServerStopClosesSessions(t *testing.T) {
	srvTLS, cliTLS := testTLSConfigs(t)

	s, err := NewServer(ServerOptions{
		ListenAddr: "127.0.0.1:0",
		TLSMode:    TLSModeSelfSigned,
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
		Addr: testClientURL(t, s, "wss"),
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

func TestConcurrentSendPacketFramingIntegrity(t *testing.T) {
	const (
		senders        = 8
		perSender      = 150
		wantPackets    = senders * perSender
		payloadMinSize = 200
	)

	srvTLS, cliTLS := testTLSConfigs(t)

	var mu sync.Mutex
	seen := make(map[int]int, wantPackets)
	corrupt := 0
	done := make(chan struct{})
	var closeOnce sync.Once

	ph := &fnPacketHandler{fn: func(ctx context.Context, peerID string, pkt []byte) error {
		seq, ok := decodeTestPacket(pkt)
		mu.Lock()
		if !ok {
			corrupt++
		} else {
			seen[seq]++
		}
		total := len(seen) + corrupt
		mu.Unlock()
		if total >= wantPackets {
			closeOnce.Do(func() { close(done) })
		}
		return nil
	}}

	s, err := NewServer(ServerOptions{
		ListenAddr: "127.0.0.1:0",
		TLSMode:    TLSModeSelfSigned,
		TLSConfig:  srvTLS,
		Authenticator: &fnAuthenticator{fn: func(ctx context.Context, hello ClientHello) (*AuthResult, error) {
			return &AuthResult{PeerID: "peer-1"}, nil
		}},
		PacketHandler: ph,
		Logger:        noopLogger{},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Stop(context.Background()) }()

	cli, err := NewClient(ClientOptions{
		Addr: testClientURL(t, s, "wss"),
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
		KeepAlivePeriod: 2 * time.Second,
		WriteTimeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Stop(context.Background()) }()

	deadline := time.After(5 * time.Second)
	for cli.State() != StateActive {
		select {
		case <-deadline:
			t.Fatalf("client not active: %s", cli.State())
		case <-time.After(10 * time.Millisecond):
		}
	}

	cli.mu.Lock()
	conn := cli.conn
	cli.mu.Unlock()
	if conn == nil {
		t.Fatal("no active connection")
	}

	pingStop := make(chan struct{})
	var pingWG sync.WaitGroup
	pingWG.Add(1)
	go func() {
		defer pingWG.Done()
		for {
			select {
			case <-pingStop:
				return
			default:
			}
			if err := cli.writeControl(conn, MsgPing, nil); err != nil {
				return
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func(sender int) {
			defer wg.Done()
			for j := 0; j < perSender; j++ {
				seq := sender*perSender + j
				if err := cli.SendPacket(ctx, encodeTestPacket(seq, payloadMinSize+seq%512)); err != nil {
					t.Errorf("SendPacket seq=%d: %v", seq, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(pingStop)
	pingWG.Wait()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}

	mu.Lock()
	defer mu.Unlock()
	if corrupt != 0 {
		t.Errorf("server received %d corrupt packets; frame writes interleaved", corrupt)
	}
	if len(seen) != wantPackets {
		t.Errorf("server received %d distinct packets, want %d", len(seen), wantPackets)
	}
	for seq, n := range seen {
		if n != 1 {
			t.Errorf("packet seq=%d received %d times, want 1", seq, n)
		}
	}
}

func encodeTestPacket(seq, size int) []byte {
	if size < 8 {
		size = 8
	}
	pkt := make([]byte, size)
	binary.BigEndian.PutUint32(pkt[0:4], uint32(seq))
	binary.BigEndian.PutUint32(pkt[4:8], uint32(size))
	for i := 8; i < size; i++ {
		pkt[i] = byte(seq % 251)
	}
	return pkt
}

func decodeTestPacket(pkt []byte) (int, bool) {
	if len(pkt) < 8 {
		return 0, false
	}
	seq := int(binary.BigEndian.Uint32(pkt[0:4]))
	size := int(binary.BigEndian.Uint32(pkt[4:8]))
	if size != len(pkt) {
		return 0, false
	}
	for i := 8; i < len(pkt); i++ {
		if pkt[i] != byte(seq%251) {
			return 0, false
		}
	}
	return seq, true
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
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
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
