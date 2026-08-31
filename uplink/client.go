package uplink

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ClientOptions configures the WebSocket uplink client.
type ClientOptions struct {
	// Addr is the uplink endpoint. Prefer a full URL:
	//   wss://gateway.example.com/uplink/v1
	// Legacy host:port is accepted and rewritten to wss://host:port/uplink/v1.
	Addr string
	// ServerName is TLS SNI (optional; derived from URL host when empty).
	ServerName string
	// TLSConfig configures TLS verification for wss:// dials.
	// Required for wss; ignored for plain ws:// (proxy-mode internal tests).
	TLSConfig        *tls.Config
	HelloFactory     func() (ClientHello, error)
	PacketHandler    func([]byte) error
	Logger           Logger
	Metrics          MetricsSink
	KeepAlivePeriod  time.Duration
	WriteTimeout     time.Duration
	ReconnectBackoff BackoffConfig
	MaxFrameSize     int
	PingInterval     time.Duration
	PongWait         time.Duration
	HandshakeTimeout time.Duration
}

// Client maintains a WebSocket session to the relay/gateway.
type Client struct {
	opts         ClientOptions
	addr         string // normalised dial URL
	log          Logger
	metrics      MetricsSink
	maxPayload   uint32
	backoff      BackoffConfig
	keepAlive    time.Duration
	writeTimeout time.Duration
	pingInterval time.Duration
	pongWait     time.Duration
	tlsConfig    *tls.Config

	mu      sync.Mutex
	state   atomic.Value // ClientState
	conn    Conn
	sessID  uint32
	cancel  context.CancelFunc
	runWG   sync.WaitGroup
	closed  atomic.Bool
	started atomic.Bool

	// writeMu serialises frames. Never acquire writeMu while holding mu.
	writeMu sync.Mutex
}

// NewClient validates options and returns a Client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Addr == "" {
		return nil, errors.New("proxy: Addr is required")
	}
	dialURL, err := NormaliseUplinkURL(opts.Addr)
	if err != nil {
		return nil, err
	}
	needsTLS := strings.HasPrefix(dialURL, "wss://")
	if needsTLS && opts.TLSConfig == nil {
		return nil, errors.New("proxy: TLSConfig is required for wss://")
	}
	if opts.HelloFactory == nil {
		return nil, errors.New("proxy: HelloFactory is required")
	}
	if opts.PacketHandler == nil {
		return nil, errors.New("proxy: PacketHandler is required")
	}
	log := opts.Logger
	if log == nil {
		log = noopLogger{}
	}
	metrics := opts.Metrics
	if metrics == nil {
		metrics = noopMetrics{}
	}
	max := opts.MaxFrameSize
	if max <= 0 {
		max = DefaultMaxFrameSize
	}
	ka := opts.KeepAlivePeriod
	if ka <= 0 {
		ka = 30 * time.Second
	}
	wt := opts.WriteTimeout
	if wt <= 0 {
		wt = 2 * time.Second
	}
	pi := opts.PingInterval
	if pi <= 0 {
		pi = defaultWSPingInterval
	}
	pw := opts.PongWait
	if pw <= 0 {
		pw = defaultWSPongWait
	}
	var cfg *tls.Config
	if opts.TLSConfig != nil {
		cfg = opts.TLSConfig.Clone()
		if opts.ServerName != "" {
			cfg.ServerName = opts.ServerName
		} else if cfg.ServerName == "" {
			if u, err := url.Parse(dialURL); err == nil {
				cfg.ServerName = u.Hostname()
			}
		}
	}
	c := &Client{
		opts:         opts,
		addr:         dialURL,
		log:          log,
		metrics:      metrics,
		maxPayload:   uint32(max),
		backoff:      opts.ReconnectBackoff.withDefaults(),
		keepAlive:    ka,
		writeTimeout: wt,
		pingInterval: pi,
		pongWait:     pw,
		tlsConfig:    cfg,
	}
	c.state.Store(ClientState(StateDisconnected))
	return c, nil
}

// NormaliseUplinkURL accepts wss://…/uplink/v1 or legacy host:port.
func NormaliseUplinkURL(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("proxy: empty uplink address")
	}
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return "", err
		}
		switch u.Scheme {
		case "wss", "ws", "https", "http":
		default:
			return "", errors.New("proxy: unsupported uplink URL scheme")
		}
		switch u.Scheme {
		case "https":
			u.Scheme = "wss"
		case "http":
			u.Scheme = "ws"
		}
		if u.Path == "" || u.Path == "/" {
			u.Path = UplinkWSPath
		}
		return u.String(), nil
	}
	// Legacy host:port → wss://host:port/uplink/v1
	return "wss://" + addr + UplinkWSPath, nil
}

// State returns the current client state.
func (c *Client) State() ClientState {
	v := c.state.Load()
	if v == nil {
		return StateDisconnected
	}
	return v.(ClientState)
}

func (c *Client) setState(st ClientState) {
	c.state.Store(st)
}

// Start begins the connection supervisor until ctx is cancelled or Stop is called.
func (c *Client) Start(ctx context.Context) error {
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("proxy: client already started")
	}
	runCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancel = cancel
	c.mu.Unlock()
	c.runWG.Add(1)
	go func() {
		defer c.runWG.Done()
		c.run(runCtx)
	}()
	return nil
}

// Stop cancels the client and closes the active connection.
func (c *Client) Stop(ctx context.Context) error {
	c.closed.Store(true)
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if conn != nil {
		_ = conn.Close()
	}
	done := make(chan struct{})
	go func() {
		c.runWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// SendPacket sends a DATA frame with the current session ID. Safe for concurrent use.
func (c *Client) SendPacket(ctx context.Context, pkt []byte) error {
	_ = ctx
	if c.closed.Load() {
		return ErrClientClosed
	}
	if uint32(len(pkt)) > c.maxPayload {
		return ErrInvalidFrame
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil || c.State() != StateActive {
		return ErrClientClosed
	}

	if err := c.writeOnConn(conn, MsgData, pkt); err != nil {
		return err
	}
	c.metrics.IncCounter("proxy_client_frames_out_total", nil)
	c.metrics.IncCounter("uplink_packets_tx_total", map[string]string{"transport": "wss"})
	return nil
}

func (c *Client) writeOnConn(conn Conn, msgType uint8, payload []byte) error {
	c.mu.Lock()
	if c.conn != conn {
		c.mu.Unlock()
		return ErrClientClosed
	}
	sid := c.sessID
	c.mu.Unlock()

	c.writeMu.Lock()
	_ = conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	err := conn.WriteFrame(FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    msgType,
		SessionID:  sid,
		PayloadLen: uint32(len(payload)),
	}, payload)
	_ = conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()

	if err != nil {
		c.log.Debug("uplink write failed, closing session", "msgType", msgType, "err", err)
		_ = conn.Close()
	}
	return err
}

func (c *Client) run(ctx context.Context) {
	b := c.backoff
	cur := b.Initial
	for {
		select {
		case <-ctx.Done():
			c.setState(StateClosing)
			return
		default:
		}
		if c.closed.Load() {
			return
		}

		c.setState(StateConnecting)
		c.log.Info("uplink: connecting",
			"transport", "wss",
			"url", c.addr,
		)

		wsConn, err := DialWebSocket(ctx, c.addr, c.tlsConfig, c.opts.HandshakeTimeout)
		if err != nil {
			c.log.Warn("uplink: websocket dial failed",
				"transport", "wss",
				"url", c.addr,
				"err", err,
			)
			c.setState(StateFailed)
			c.metrics.IncCounter("uplink_connection_errors_total", map[string]string{"transport": "wss"})
			c.metrics.IncCounter("uplink_reconnects_total", map[string]string{"transport": "wss"})
			c.log.Info("uplink: reconnect scheduled",
				"transport", "wss",
				"url", c.addr,
				"backoff", cur.String(),
			)
			if !c.sleepBackoff(ctx, jitterDuration(cur)) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		wsConn.pingInterval = c.pingInterval
		wsConn.pongWait = c.pongWait
		c.setState(StateTLSReady)
		c.log.Info("uplink: websocket connection established",
			"transport", "wss",
			"url", c.addr,
			"remote", wsConn.RemoteAddr(),
			"status", wsConn.HandshakeStatus(),
		)

		hello, err := c.opts.HelloFactory()
		if err != nil {
			c.log.Error("hello factory", "err", err)
			_ = wsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, jitterDuration(cur)) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		c.setState(StateAuthenticating)
		payload, err := json.Marshal(hello)
		if err != nil {
			_ = wsConn.Close()
			c.setState(StateFailed)
			continue
		}
		_ = wsConn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
		err = wsConn.WriteFrame(FrameHeader{
			Version:    ProtocolVersion,
			MsgType:    MsgHello,
			PayloadLen: uint32(len(payload)),
		}, payload)
		_ = wsConn.SetWriteDeadline(time.Time{})
		if err != nil {
			_ = wsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, jitterDuration(cur)) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}

		_ = wsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		h, ack, err := wsConn.ReadFrame(c.maxPayload)
		if err != nil {
			c.log.Warn("read hello ack", "err", err)
			_ = wsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, jitterDuration(cur)) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		if h.MsgType == MsgError {
			c.log.Warn("uplink: authentication failed",
				"transport", "wss",
				"url", c.addr,
			)
			_ = wsConn.Close()
			c.setState(StateFailed)
			c.metrics.IncCounter("proxy_client_auth_failures_total", nil)
			c.metrics.IncCounter("uplink_auth_failures_total", map[string]string{"transport": "wss"})
			if !c.sleepBackoff(ctx, jitterDuration(cur)) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		if h.MsgType != MsgHelloAck {
			c.log.Warn("uplink: unexpected hello response",
				"transport", "wss",
				"type", h.MsgType,
			)
			_ = wsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, jitterDuration(cur)) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		var hw helloAckWire
		if err := json.Unmarshal(ack, &hw); err != nil {
			_ = wsConn.Close()
			c.setState(StateFailed)
			continue
		}

		sessCtx, sessCancel := context.WithCancel(ctx)
		wsConn.StartPingLoop(sessCtx)

		c.mu.Lock()
		c.conn = wsConn
		c.sessID = hw.SessionID
		c.mu.Unlock()
		c.setState(StateActive)
		cur = b.Initial
		c.metrics.IncCounter("proxy_client_sessions_active_total", nil)
		c.log.Info("uplink: authenticated",
			"transport", "wss",
			"url", c.addr,
			"remote", wsConn.RemoteAddr(),
			"session_id", hw.SessionID,
		)

		pingCtx, pingCancel := context.WithCancel(sessCtx)
		pingDone := make(chan struct{})
		go func() {
			defer close(pingDone)
			c.pingLoop(pingCtx, wsConn)
		}()

		readErr := make(chan error, 1)
		go func() {
			readErr <- c.readLoop(sessCtx, wsConn)
		}()

		select {
		case <-ctx.Done():
			pingCancel()
			sessCancel()
			<-pingDone
			_ = wsConn.Close()
			c.clearConn()
			c.setState(StateClosing)
			return
		case err := <-readErr:
			pingCancel()
			sessCancel()
			<-pingDone
			if err != nil && !errors.Is(err, io.EOF) {
				c.log.Debug("read loop ended", "err", err)
			}
			_ = wsConn.Close()
			c.clearConn()
			c.setState(StateFailed)
			c.log.Info("uplink: websocket disconnected",
				"transport", "wss",
				"url", c.addr,
			)
			c.metrics.IncCounter("uplink_reconnects_total", map[string]string{"transport": "wss"})
			if c.closed.Load() {
				return
			}
			c.log.Info("uplink: reconnect scheduled",
				"transport", "wss",
				"url", c.addr,
				"backoff", cur.String(),
			)
			if !c.sleepBackoff(ctx, jitterDuration(cur)) {
				return
			}
			cur = nextBackoff(cur, b)
		}
	}
}

func (c *Client) clearConn() {
	c.mu.Lock()
	c.conn = nil
	c.sessID = 0
	c.mu.Unlock()
}

func (c *Client) sleepBackoff(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(cur time.Duration, b BackoffConfig) time.Duration {
	next := time.Duration(float64(cur) * b.Factor)
	if next > b.Max {
		return b.Max
	}
	return next
}

func jitterDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	// Full jitter in [d/2, d].
	half := d / 2
	return half + time.Duration(rand.Int63n(int64(half)+1))
}

func (c *Client) pingLoop(ctx context.Context, conn Conn) {
	t := time.NewTicker(c.keepAlive)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.mu.Lock()
			active := c.conn == conn && c.State() == StateActive
			c.mu.Unlock()
			if !active {
				return
			}
			if err := c.writeControl(conn, MsgPing, nil); err != nil {
				return
			}
			c.metrics.IncCounter("proxy_client_pings_total", nil)
		}
	}
}

func (c *Client) writeControl(conn Conn, msgType uint8, payload []byte) error {
	return c.writeOnConn(conn, msgType, payload)
}

func (c *Client) readLoop(ctx context.Context, conn Conn) error {
	idle := c.pongWait * 2
	if idle < c.keepAlive*3 {
		idle = c.keepAlive * 3
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		h, payload, err := conn.ReadFrame(c.maxPayload)
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				c.log.Info("uplink pong timeout")
				c.metrics.IncCounter("uplink_ping_timeout_total", map[string]string{"transport": "wss"})
			}
			return err
		}
		switch h.MsgType {
		case MsgData:
			if err := c.opts.PacketHandler(payload); err != nil {
				c.log.Warn("packet handler error", "err", err)
			}
			c.metrics.IncCounter("proxy_client_frames_in_total", nil)
			c.metrics.IncCounter("uplink_packets_rx_total", map[string]string{"transport": "wss"})
		case MsgPing:
			_ = c.writeControl(conn, MsgPong, nil)
		case MsgPong:
			// ok
		case MsgClose, MsgError:
			return io.EOF
		default:
			c.log.Warn("unexpected msg type", "type", h.MsgType)
		}
	}
}
