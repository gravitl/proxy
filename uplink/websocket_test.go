package uplink

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestWebSocketConn_StartPingLoopCloseNoPanic(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		conn := NewWebSocketConn(ws, DefaultMaxMessageSize)
		conn.pingInterval = 10 * time.Millisecond
		conn.StartPingLoop(r.Context())
		// Keep the connection open briefly so the ping loop is running,
		// then Close (stopPing) races with the goroutine exit.
		time.Sleep(30 * time.Millisecond)
		_ = conn.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[len("http"):]
	cli, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Drain until server closes; panic in the ping loop would fail the test process.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = cli.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, _, err := cli.ReadMessage(); err != nil {
			return
		}
	}
}

func TestWebSocketConn_stopPingIdempotent(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		conn := NewWebSocketConn(ws, DefaultMaxMessageSize)
		conn.pingInterval = time.Hour
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		conn.StartPingLoop(ctx)
		conn.stopPing()
		conn.stopPing() // second stop must not hang or panic
		_ = conn.ws.Close()
	}))
	defer srv.Close()

	wsURL := "ws" + srv.URL[len("http"):]
	cli, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	cli.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server handler did not finish")
	}
}
