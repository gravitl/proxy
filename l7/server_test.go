package l7_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gravitl/proxy/l7"
)

func TestAllowlist(t *testing.T) {
	m := l7.Allowlist{Domains: []string{"api.example.com", "*.saas.com"}}
	if err := m.Allow("api.example.com", "443"); err != nil {
		t.Fatalf("exact allow: %v", err)
	}
	if err := m.Allow("app.saas.com", "443"); err != nil {
		t.Fatalf("wildcard allow: %v", err)
	}
	if err := m.Allow("evil.com", "443"); err == nil {
		t.Fatal("expected deny for evil.com")
	}
}

func TestNewServerRequiresListenAddrAndMatcher(t *testing.T) {
	if _, err := l7.NewServer(l7.ServerOptions{}); err == nil {
		t.Fatal("expected error for empty options")
	}
	if _, err := l7.NewServer(l7.ServerOptions{ListenAddr: "127.0.0.1:0"}); err == nil {
		t.Fatal("expected error without Matcher")
	}
}

func TestConnectAllowedRoundTrip(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		_, _ = c.Write([]byte("world"))
	}()

	host, port, _ := net.SplitHostPort(backend.Addr().String())
	srv, err := l7.NewServer(l7.ServerOptions{
		ListenAddr: "127.0.0.1:0",
		Matcher:    l7.Allowlist{Domains: []string{host}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	req := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
	if _, err := io.WriteString(client, req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	if _, err := io.WriteString(client, "hello"); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 5)
	if _, err := io.ReadFull(br, out); err != nil {
		t.Fatal(err)
	}
	if string(out) != "world" {
		t.Fatalf("got %q", out)
	}
	<-backendDone
}

func TestConnectDenied(t *testing.T) {
	srv, err := l7.NewServer(l7.ServerOptions{
		ListenAddr: "127.0.0.1:0",
		Matcher:    l7.Allowlist{Domains: []string{"allowed.example"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, _ = io.WriteString(client, "CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("status=%d want 403", resp.StatusCode)
	}
}

func TestConnectBadMethod(t *testing.T) {
	srv, err := l7.NewServer(l7.ServerOptions{
		ListenAddr: "127.0.0.1:0",
		Matcher:    l7.AllowAll{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, _ = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func TestConnectDialFailure(t *testing.T) {
	// Port with nothing listening.
	srv, err := l7.NewServer(l7.ServerOptions{
		ListenAddr:  "127.0.0.1:0",
		Matcher:     l7.AllowAll{},
		DialTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Use a high port unlikely to be open on localhost.
	req := "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
	if _, err := io.WriteString(client, req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 502 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		t.Fatalf("status=%d want 502 body=%q", resp.StatusCode, body)
	}
}

func TestParseConnectViaServerBufferedPayload(t *testing.T) {
	// Ensure bytes after CONNECT headers reach the backend (TLS ClientHello case).
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()

	got := make(chan string, 1)
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		got <- string(buf[:n])
	}()

	host, port, _ := net.SplitHostPort(backend.Addr().String())
	srv, err := l7.NewServer(l7.ServerOptions{
		ListenAddr: "127.0.0.1:0",
		Matcher:    l7.AllowAll{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop(context.Background()) }()

	client, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := "early-bytes"
	msg := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n%s", host, port, host, port, payload)
	if _, err := io.WriteString(client, msg); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	select {
	case s := <-got:
		if !strings.HasPrefix(s, payload) {
			t.Fatalf("backend got %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for backend")
	}
}
