package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ClientOptions configures the TCP/TLS uplink client (spec §9.1).
type ClientOptions struct {
	Addr             string
	ServerName       string
	TLSConfig        *tls.Config
	HelloFactory     func() (ClientHello, error)
	PacketHandler    func([]byte) error
	Logger           Logger
	Metrics          MetricsSink
	KeepAlivePeriod  time.Duration
	ReconnectBackoff BackoffConfig
	MaxFrameSize     int
}

// Client maintains a TCP/TLS session to the relay (spec §9.1).
type Client struct {
	opts       ClientOptions
	addr       string
	log        Logger
	metrics    MetricsSink
	maxPayload uint32
	backoff    BackoffConfig
	keepAlive  time.Duration
	tlsConfig  *tls.Config

	mu      sync.Mutex
	state   atomic.Value // ClientState
	tlsConn *tls.Conn
	sessID  uint32
	cancel  context.CancelFunc
	runWG   sync.WaitGroup
	closed  atomic.Bool
	started atomic.Bool
}

// NewClient validates options and returns a Client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Addr == "" {
		return nil, errors.New("proxy: Addr is required")
	}
	if opts.TLSConfig == nil {
		return nil, errors.New("proxy: TLSConfig is required")
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
	cfg := opts.TLSConfig.Clone()
	if opts.ServerName != "" {
		cfg.ServerName = opts.ServerName
	}
	c := &Client{
		opts:       opts,
		addr:       opts.Addr,
		log:        log,
		metrics:    metrics,
		maxPayload: uint32(max),
		backoff:    opts.ReconnectBackoff.withDefaults(),
		keepAlive:  ka,
		tlsConfig:  cfg,
	}
	c.state.Store(ClientState(StateDisconnected))
	return c, nil
}

// State returns the current client state (spec §13.1).
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
	conn := c.tlsConn
	c.tlsConn = nil
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

// SendPacket sends a DATA frame with the current session ID (spec §9.1).
func (c *Client) SendPacket(ctx context.Context, pkt []byte) error {
	_ = ctx
	if c.closed.Load() {
		return ErrClientClosed
	}
	if uint32(len(pkt)) > c.maxPayload {
		return ErrInvalidFrame
	}
	c.mu.Lock()
	conn := c.tlsConn
	sid := c.sessID
	st := c.State()
	if conn == nil || st != StateActive {
		c.mu.Unlock()
		return ErrClientClosed
	}
	hdr := FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    MsgData,
		SessionID:  sid,
		PayloadLen: uint32(len(pkt)),
	}
	// Copy conn under lock; release before write so Stop can close the conn and
	// unblock a stuck writer via SetWriteDeadline / Close.
	c.mu.Unlock()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	err := writeFrame(conn, hdr, pkt)
	_ = conn.SetWriteDeadline(time.Time{})
	if err == nil {
		c.metrics.IncCounter("proxy_client_frames_out_total", nil)
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
		d := net.Dialer{Timeout: 15 * time.Second}
		raw, err := d.DialContext(ctx, "tcp", c.addr)
		if err != nil {
			c.log.Warn("dial failed", "addr", c.addr, "err", err)
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, cur) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}

		tlsConn := tls.Client(raw, c.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			c.log.Warn("tls handshake failed", "err", err)
			_ = tlsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, cur) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		c.setState(StateTLSReady)

		hello, err := c.opts.HelloFactory()
		if err != nil {
			c.log.Error("hello factory", "err", err)
			_ = tlsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, cur) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		c.setState(StateAuthenticating)
		payload, err := json.Marshal(hello)
		if err != nil {
			_ = tlsConn.Close()
			c.setState(StateFailed)
			continue
		}
		if err := writeFrame(tlsConn, FrameHeader{
			Version:    ProtocolVersion,
			MsgType:    MsgHello,
			PayloadLen: uint32(len(payload)),
		}, payload); err != nil {
			_ = tlsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, cur) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}

		_ = tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		h, ack, err := readFrame(tlsConn, c.maxPayload)
		if err != nil {
			c.log.Warn("read hello ack", "err", err)
			_ = tlsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, cur) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		if h.MsgType == MsgError {
			c.log.Warn("server rejected hello")
			_ = tlsConn.Close()
			c.setState(StateFailed)
			c.metrics.IncCounter("proxy_client_auth_failures_total", nil)
			if !c.sleepBackoff(ctx, cur) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		if h.MsgType != MsgHelloAck {
			c.log.Warn("unexpected hello response", "type", h.MsgType)
			_ = tlsConn.Close()
			c.setState(StateFailed)
			if !c.sleepBackoff(ctx, cur) {
				return
			}
			cur = nextBackoff(cur, b)
			continue
		}
		var hw helloAckWire
		if err := json.Unmarshal(ack, &hw); err != nil {
			_ = tlsConn.Close()
			c.setState(StateFailed)
			continue
		}

		c.mu.Lock()
		c.tlsConn = tlsConn
		c.sessID = hw.SessionID
		c.mu.Unlock()
		c.setState(StateActive)
		cur = b.Initial
		c.metrics.IncCounter("proxy_client_sessions_active_total", nil)

		pingCtx, pingCancel := context.WithCancel(ctx)
		pingDone := make(chan struct{})
		go func() {
			defer close(pingDone)
			c.pingLoop(pingCtx, tlsConn)
		}()

		readErr := make(chan error, 1)
		go func() {
			readErr <- c.readLoop(ctx, tlsConn)
		}()

		select {
		case <-ctx.Done():
			pingCancel()
			<-pingDone
			_ = tlsConn.Close()
			c.clearConn()
			c.setState(StateClosing)
			return
		case err := <-readErr:
			pingCancel()
			<-pingDone
			if err != nil && !errors.Is(err, io.EOF) {
				c.log.Debug("read loop ended", "err", err)
			}
			_ = tlsConn.Close()
			c.clearConn()
			c.setState(StateFailed)
			if c.closed.Load() {
				return
			}
			if !c.sleepBackoff(ctx, cur) {
				return
			}
			cur = nextBackoff(cur, b)
		}
	}
}

func (c *Client) clearConn() {
	c.mu.Lock()
	c.tlsConn = nil
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

func (c *Client) pingLoop(ctx context.Context, conn *tls.Conn) {
	t := time.NewTicker(c.keepAlive)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.mu.Lock()
			active := c.tlsConn == conn && c.State() == StateActive
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

func (c *Client) writeControl(conn *tls.Conn, msgType uint8, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tlsConn != conn {
		return ErrClientClosed
	}
	sid := c.sessID
	return writeFrame(conn, FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    msgType,
		SessionID:  sid,
		PayloadLen: uint32(len(payload)),
	}, payload)
}

func (c *Client) readLoop(ctx context.Context, conn *tls.Conn) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(c.keepAlive * 3))
		h, payload, err := readFrame(conn, c.maxPayload)
		if err != nil {
			return err
		}
		switch h.MsgType {
		case MsgData:
			if err := c.opts.PacketHandler(payload); err != nil {
				c.log.Warn("packet handler error", "err", err)
			}
			c.metrics.IncCounter("proxy_client_frames_in_total", nil)
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
