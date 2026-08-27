package uplink

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// UplinkWSPath is the versioned WebSocket endpoint for TCP uplink.
	UplinkWSPath = "/uplink/v1"

	// DefaultMaxMessageSize caps a single WebSocket binary message (frame header + payload).
	DefaultMaxMessageSize = frameHeaderSize + DefaultMaxFrameSize

	defaultWSPingInterval = 25 * time.Second
	defaultWSPongWait     = 15 * time.Second
)

// wsUpgrader upgrades HTTP connections to WebSocket.
// CheckOrigin allows missing Origin (machine clients / netclient are not browsers).
// Authentication remains the security boundary after upgrade.
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// WebSocketConn implements Conn over a gorilla WebSocket connection.
// One reader and one writer may run concurrently; WriteFrame is serialised internally.
//
// Each WebSocket binary message carries one complete uplink frame (12-byte header +
// payload). The length prefix inside the message is retained as compatibility framing.
type WebSocketConn struct {
	ws           *websocket.Conn
	writeMu      sync.Mutex
	maxMsgSize   int64
	pingInterval time.Duration
	pongWait     time.Duration
	remote       string // peer TCP address (or forwarded client IP when set)
	status       int    // HTTP status of the WebSocket handshake (typically 101)

	pingMu     sync.Mutex
	pingCancel context.CancelFunc
	pingDone   chan struct{}
}

// NewWebSocketConn wraps an upgraded WebSocket connection.
func NewWebSocketConn(ws *websocket.Conn, maxMsgSize int) *WebSocketConn {
	if maxMsgSize <= 0 {
		maxMsgSize = DefaultMaxMessageSize
	}
	remote := ""
	if ws != nil && ws.RemoteAddr() != nil {
		remote = ws.RemoteAddr().String()
	}
	c := &WebSocketConn{
		ws:           ws,
		maxMsgSize:   int64(maxMsgSize),
		pingInterval: defaultWSPingInterval,
		pongWait:     defaultWSPongWait,
		remote:       remote,
		status:       http.StatusSwitchingProtocols,
	}
	ws.SetReadLimit(c.maxMsgSize)
	_ = ws.SetReadDeadline(time.Now().Add(c.pongWait))
	ws.SetPongHandler(func(string) error {
		_ = ws.SetReadDeadline(time.Now().Add(c.pongWait))
		return nil
	})
	return c
}

// RemoteAddr returns the peer address associated with this connection.
func (c *WebSocketConn) RemoteAddr() string { return c.remote }

// HandshakeStatus returns the HTTP status from the WebSocket upgrade (typically 101).
func (c *WebSocketConn) HandshakeStatus() int { return c.status }

// SetRemoteAddr overrides the logged peer address (e.g. client IP behind a reverse proxy).
func (c *WebSocketConn) SetRemoteAddr(addr string) {
	if addr != "" {
		c.remote = addr
	}
}

// StartPingLoop sends WebSocket Ping frames on interval until ctx is cancelled or Close.
func (c *WebSocketConn) StartPingLoop(ctx context.Context) {
	c.pingMu.Lock()
	if c.pingCancel != nil {
		c.pingMu.Unlock()
		return
	}
	pctx, cancel := context.WithCancel(ctx)
	c.pingCancel = cancel
	c.pingDone = make(chan struct{})
	c.pingMu.Unlock()

	go func() {
		defer close(c.pingDone)
		t := time.NewTicker(c.pingInterval)
		defer t.Stop()
		for {
			select {
			case <-pctx.Done():
				return
			case <-t.C:
				c.writeMu.Lock()
				err := c.ws.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(c.pongWait))
				c.writeMu.Unlock()
				if err != nil {
					_ = c.ws.Close()
					return
				}
			}
		}
	}()
}

func (c *WebSocketConn) stopPing() {
	c.pingMu.Lock()
	cancel := c.pingCancel
	done := c.pingDone
	c.pingCancel = nil
	c.pingDone = nil
	c.pingMu.Unlock()
	if cancel != nil {
		cancel()
		if done != nil {
			<-done
		}
	}
}

func (c *WebSocketConn) ReadFrame(maxPayload uint32) (FrameHeader, []byte, error) {
	for {
		msgType, data, err := c.ws.ReadMessage()
		if err != nil {
			return FrameHeader{}, nil, err
		}
		if msgType != websocket.BinaryMessage {
			continue // ignore text/control handled by library
		}
		return decodeFrameBytes(data, maxPayload)
	}
}

func (c *WebSocketConn) WriteFrame(h FrameHeader, payload []byte) error {
	msg, err := encodeFrameBytes(h, payload)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.WriteMessage(websocket.BinaryMessage, msg)
}

func (c *WebSocketConn) Close() error {
	c.stopPing()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second))
	return c.ws.Close()
}

func (c *WebSocketConn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

func (c *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return c.ws.SetWriteDeadline(t)
}

// DialWebSocket dials a WSS (or WS) uplink endpoint and returns a WebSocketConn.
// urlStr should be like wss://gateway.example.com/uplink/v1 (path defaults if omitted).
func DialWebSocket(ctx context.Context, urlStr string, tlsConfig *tls.Config, handshakeTimeout time.Duration) (*WebSocketConn, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid uplink URL: %w", err)
	}
	switch u.Scheme {
	case "wss", "ws", "https", "http":
	default:
		return nil, fmt.Errorf("proxy: unsupported uplink URL scheme %q", u.Scheme)
	}
	// Normalise http(s) → ws(s) for the dialer.
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = UplinkWSPath
	}

	if handshakeTimeout <= 0 {
		handshakeTimeout = 15 * time.Second
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: handshakeTimeout,
		TLSClientConfig:  tlsConfig,
		NetDialContext:   (&net.Dialer{Timeout: handshakeTimeout}).DialContext,
	}

	ws, resp, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, err
	}
	conn := NewWebSocketConn(ws, DefaultMaxMessageSize)
	if resp != nil {
		conn.status = resp.StatusCode
		_ = resp.Body.Close()
	}
	return conn, nil
}

// UpgradeWebSocket upgrades an HTTP request to a WebSocketConn.
func UpgradeWebSocket(w http.ResponseWriter, r *http.Request, maxMsgSize int) (*WebSocketConn, error) {
	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	conn := NewWebSocketConn(ws, maxMsgSize)
	conn.status = http.StatusSwitchingProtocols
	// Prefer forwarded client IP when behind a reverse proxy; fall back to TCP peer.
	if ip := ClientIPFromRequest(r); ip != "" {
		conn.SetRemoteAddr(ip)
	}
	return conn, nil
}

// ClientIPFromRequest extracts the connecting client IP for logging.
// Prefers X-Forwarded-For (first hop) / X-Real-IP when present (reverse-proxy deployments),
// otherwise uses the TCP RemoteAddr host. Never used for authentication.
func ClientIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// First address is the original client when proxies append.
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := strings.TrimSpace(xff); ip != "" {
			return ip
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
