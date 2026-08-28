package uplink

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ServerOptions configures the WebSocket uplink server.
type ServerOptions struct {
	ListenAddr string
	// TLSMode selects TLS termination. Empty defaults to TLSModeSelfSigned.
	TLSMode TLSMode
	// TLSConfig is required when TLSMode is selfsigned; ignored in proxy mode.
	TLSConfig       *tls.Config
	Authenticator   Authenticator
	PacketHandler   PacketHandler
	SessionRegistry SessionRegistry
	Logger          Logger
	Metrics         MetricsSink
	KeepAlivePeriod time.Duration // used for app MsgPing fallback / read idle
	WriteTimeout    time.Duration
	MaxFrameSize    int
	// PingInterval for WebSocket Ping control frames (default 25s).
	PingInterval time.Duration
	// PongWait is how long after a Ping to allow for a Pong / read idle slack
	// (default 60s). Effective read deadline is PingInterval+PongWait.
	PongWait time.Duration
}

// Server serves /uplink/v1 over WebSocket and manages framed sessions.
type Server struct {
	opts         ServerOptions
	log          Logger
	metrics      MetricsSink
	registry     SessionRegistry
	maxPayload   uint32
	keepAlive    time.Duration
	writeTimeout time.Duration
	pingInterval time.Duration
	pongWait     time.Duration
	tlsMode      TLSMode
	sessionIDGen atomic.Uint32
	httpServer   *http.Server
	listener     net.Listener
	serveCtx     context.Context
	closed       atomic.Bool
	shutdown     chan struct{}
	shutdownOnce sync.Once
	startMu      sync.Mutex
	serveWG      sync.WaitGroup
	connWG       sync.WaitGroup
}

// NewServer validates options and constructs a Server.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.ListenAddr == "" {
		return nil, errors.New("proxy: ListenAddr is required")
	}
	mode := opts.TLSMode
	if mode == "" {
		mode = DefaultTLSMode
	}
	if err := mode.Validate(); err != nil {
		return nil, err
	}
	if mode == TLSModeSelfSigned && opts.TLSConfig == nil {
		return nil, errors.New("proxy: TLSConfig is required for selfsigned TLS mode")
	}
	if opts.Authenticator == nil {
		return nil, errors.New("proxy: Authenticator is required")
	}
	if opts.PacketHandler == nil {
		return nil, errors.New("proxy: PacketHandler is required")
	}
	reg := opts.SessionRegistry
	if reg == nil {
		reg = NewInMemoryRegistry()
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
	return &Server{
		opts:         opts,
		log:          log,
		metrics:      metrics,
		registry:     reg,
		maxPayload:   uint32(max),
		keepAlive:    ka,
		writeTimeout: wt,
		pingInterval: pi,
		pongWait:     pw,
		tlsMode:      mode,
		shutdown:     make(chan struct{}),
	}, nil
}

// Start binds the listen address and serves WebSocket uplink until ctx is cancelled or Stop.
func (s *Server) Start(ctx context.Context) error {
	s.startMu.Lock()
	if s.httpServer != nil {
		s.startMu.Unlock()
		return errors.New("proxy: server already started")
	}

	mux := http.NewServeMux()
	mux.HandleFunc(UplinkWSPath, s.handleUplinkHTTP)

	hs := &http.Server{
		Addr:              s.opts.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// Do not set WriteTimeout / ReadTimeout — they apply to upgraded WebSockets.
	}

	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		s.startMu.Unlock()
		return err
	}
	if s.tlsMode == TLSModeSelfSigned {
		ln = tls.NewListener(ln, s.opts.TLSConfig)
	}

	s.listener = ln
	s.httpServer = hs
	s.serveCtx = ctx
	s.startMu.Unlock()

	labels := map[string]string{"transport": "wss", "tls_mode": string(s.tlsMode)}
	s.log.Info("uplink websocket listener started",
		"listen", ln.Addr().String(),
		"tls_mode", string(s.tlsMode),
		"path", UplinkWSPath,
	)
	if s.tlsMode == TLSModeProxy {
		s.log.Info("uplink started in reverse-proxy TLS mode", "listen", ln.Addr().String())
		if warnPublicListen(ln.Addr()) {
			s.log.Warn("proxy TLS mode listen address is not loopback/private; ensure only a trusted reverse proxy can reach this listener",
				"listen", ln.Addr().String())
		}
	}
	s.metrics.IncCounter("uplink_connections_total", labels) // zero-ish marker for scrape presence

	s.serveWG.Add(1)
	go func() {
		defer s.serveWG.Done()
		var serveErr error
		if s.tlsMode == TLSModeSelfSigned {
			serveErr = hs.Serve(ln)
		} else {
			serveErr = hs.Serve(ln)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !s.closed.Load() {
			s.log.Warn("http serve ended", "err", serveErr)
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			_ = s.Stop(context.Background())
		case <-s.shutdown:
		}
	}()

	return nil
}

func warnPublicListen(addr net.Addr) bool {
	ta, ok := addr.(*net.TCPAddr)
	if !ok || ta.IP == nil {
		return false
	}
	if ta.IP.IsUnspecified() {
		return true
	}
	if ta.IP.IsLoopback() || ta.IP.IsPrivate() || ta.IP.IsLinkLocalUnicast() {
		return false
	}
	return true
}

func (s *Server) handleUplinkHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientIP := ClientIPFromRequest(r)
	s.log.Info("uplink: websocket upgrade request",
		"transport", "wss",
		"tls_mode", string(s.tlsMode),
		"client_ip", clientIP,
		"remote", r.RemoteAddr,
		"path", r.URL.Path,
	)
	wsConn, err := UpgradeWebSocket(w, r, int(s.maxPayload)+frameHeaderSize)
	if err != nil {
		s.log.Warn("uplink: websocket upgrade failed",
			"transport", "wss",
			"client_ip", clientIP,
			"remote", r.RemoteAddr,
			"err", err,
		)
		s.metrics.IncCounter("uplink_connection_errors_total", map[string]string{
			"transport": "wss", "tls_mode": string(s.tlsMode),
		})
		return
	}
	wsConn.pingInterval = s.pingInterval
	wsConn.pongWait = s.pongWait
	_ = wsConn.SetReadDeadline(time.Now().Add(s.pongWait * 2))
	s.log.Info("uplink: websocket connection established",
		"transport", "wss",
		"tls_mode", string(s.tlsMode),
		"client_ip", clientIP,
		"remote", r.RemoteAddr,
		"status", wsConn.HandshakeStatus(),
	)

	s.connWG.Add(1)
	go func() {
		defer s.connWG.Done()
		// Do not use r.Context(): it is cancelled when this HTTP handler returns
		// after a successful WebSocket upgrade.
		base := s.serveCtx
		if base == nil {
			base = context.Background()
		}
		s.handleConnection(base, wsConn, clientIP)
	}()
}

// Addr returns the bound listen address (e.g. after Start with ":0").
func (s *Server) Addr() net.Addr {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// TLSMode returns the configured TLS mode.
func (s *Server) TLSMode() TLSMode { return s.tlsMode }

// Stop closes the HTTP server, attached sessions, and waits for handlers.
func (s *Server) Stop(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		close(s.shutdown)
		s.closed.Store(true)
		s.startMu.Lock()
		hs := s.httpServer
		s.httpServer = nil
		ln := s.listener
		s.listener = nil
		s.startMu.Unlock()
		if hs != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = hs.Shutdown(shutdownCtx)
			cancel()
		}
		if ln != nil {
			_ = ln.Close()
		}
		if closer, ok := s.registry.(interface{ CloseAll() }); ok {
			closer.CloseAll()
		}
	})

	done := make(chan struct{})
	go func() {
		s.serveWG.Wait()
		s.connWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// SendToPeer sends a DATA frame to the attached peer's session.
func (s *Server) SendToPeer(ctx context.Context, peerID string, pkt []byte) error {
	if s.closed.Load() {
		return ErrServerClosed
	}
	sess, ok := s.registry.Get(peerID)
	if !ok {
		return ErrNoSession
	}
	sw, ok := sess.(interface {
		sendData(context.Context, []byte) error
	})
	if !ok {
		return ErrNoSession
	}
	return sw.sendData(ctx, pkt)
}

// SessionPeerIDs returns peer IDs with an attached session, if supported.
func (s *Server) SessionPeerIDs() []string {
	if reg, ok := s.registry.(interface{ PeerIDs() []string }); ok {
		return reg.PeerIDs()
	}
	return nil
}

func (s *Server) detach(peerID string, sess Session) {
	if reg, ok := s.registry.(interface {
		DetachSession(string, Session)
	}); ok {
		reg.DetachSession(peerID, sess)
		return
	}
	s.registry.Detach(peerID)
}

func (s *Server) handleConnection(ctx context.Context, conn Conn, clientIP string) {
	defer conn.Close()

	labels := map[string]string{"transport": "wss", "tls_mode": string(s.tlsMode)}
	s.metrics.IncCounter("proxy_server_connections_total", nil)
	s.metrics.IncCounter("uplink_connections_total", labels)
	if clientIP == "" {
		if ws, ok := conn.(*WebSocketConn); ok {
			clientIP = ws.RemoteAddr()
		}
	}
	s.log.Info("uplink: session started",
		"transport", "wss",
		"tls_mode", string(s.tlsMode),
		"client_ip", clientIP,
	)

	sessCtx, sessCancel := context.WithCancel(ctx)
	defer sessCancel()

	if ws, ok := conn.(*WebSocketConn); ok {
		ws.StartPingLoop(sessCtx)
	}

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	h, payload, err := conn.ReadFrame(s.maxPayload)
	if err != nil {
		s.log.Warn("uplink: read hello frame failed",
			"client_ip", clientIP,
			"err", err,
		)
		return
	}
	if h.MsgType != MsgHello {
		s.log.Warn("uplink: expected MsgHello",
			"client_ip", clientIP,
			"msgType", h.MsgType,
		)
		return
	}

	var hello ClientHello
	if err := json.Unmarshal(payload, &hello); err != nil {
		s.log.Warn("uplink: invalid ClientHello JSON",
			"client_ip", clientIP,
			"err", err,
		)
		_ = s.writeError(conn, 0, "invalid_hello", "invalid hello payload")
		return
	}

	authCtx, cancel := context.WithTimeout(sessCtx, 30*time.Second)
	res, err := s.opts.Authenticator.ValidateClientHello(authCtx, hello)
	cancel()
	if err != nil || res == nil || res.PeerID == "" {
		s.metrics.IncCounter("proxy_server_auth_failures_total", nil)
		s.metrics.IncCounter("uplink_auth_failures_total", labels)
		msg := "authentication failed"
		if err != nil {
			msg = err.Error()
		}
		_ = s.writeError(conn, 0, "auth_failed", msg)
		s.log.Warn("uplink: authentication failed",
			"transport", "wss",
			"client_ip", clientIP,
			"node_id", hello.NodeID,
			"err", err,
		)
		return
	}
	s.log.Info("uplink: authenticated",
		"transport", "wss",
		"tls_mode", string(s.tlsMode),
		"client_ip", clientIP,
		"peer", res.PeerID,
		"node_id", hello.NodeID,
	)

	sid := s.sessionIDGen.Add(1)
	cs := &connSession{
		server:    s,
		conn:      conn,
		peerID:    res.PeerID,
		sessionID: sid,
		state:     SessionAuthenticated,
		cancel:    sessCancel,
		clientIP:  clientIP,
	}

	ackBytes, err := json.Marshal(helloAckWire{SessionID: sid})
	if err != nil {
		s.log.Error("marshal hello ack", "err", err)
		return
	}
	if err := cs.writeFrameLocked(MsgHelloAck, ackBytes); err != nil {
		s.log.Warn("write hello ack", "err", err, "client_ip", clientIP)
		return
	}

	cs.setState(SessionAttached)
	if err := s.registry.Attach(res.PeerID, cs); err != nil {
		s.log.Error("session attach", "err", err, "client_ip", clientIP)
		_ = cs.Close()
		return
	}
	s.metrics.IncCounter("proxy_server_sessions_attached_total", nil)
	if reg, ok := s.registry.(*InMemoryRegistry); ok {
		s.metrics.SetGauge("proxy_server_active_sessions", float64(reg.Len()), nil)
		s.metrics.SetGauge("uplink_connections_active", float64(reg.Len()), labels)
	}

	defer func() {
		s.detach(res.PeerID, cs)
		cs.setState(SessionClosed)
		if reg, ok := s.registry.(*InMemoryRegistry); ok {
			s.metrics.SetGauge("proxy_server_active_sessions", float64(reg.Len()), nil)
			s.metrics.SetGauge("uplink_connections_active", float64(reg.Len()), labels)
		}
		s.log.Info("uplink: session cleanup complete",
			"transport", "wss",
			"client_ip", clientIP,
			"peer", res.PeerID,
		)
		s.log.Info("uplink: websocket disconnected",
			"transport", "wss",
			"client_ip", clientIP,
			"peer", res.PeerID,
		)
	}()

	cs.readLoop(sessCtx)
}

func (s *Server) writeError(conn Conn, sessionID uint32, code, msg string) error {
	b, err := json.Marshal(errorPayloadWire{Code: code, Message: msg})
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	err = conn.WriteFrame(FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    MsgError,
		SessionID:  sessionID,
		PayloadLen: uint32(len(b)),
	}, b)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

// connSession is the server's session for one WebSocket connection.
type connSession struct {
	server    *Server
	conn      Conn
	peerID    string
	sessionID uint32
	clientIP  string
	writeMu   sync.Mutex
	state     SessionState
	stateMu   sync.RWMutex
	closed    atomic.Bool
	cancel    context.CancelFunc
}

func (c *connSession) PeerID() string { return c.peerID }

func (c *connSession) State() SessionState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

func (c *connSession) setState(st SessionState) {
	c.stateMu.Lock()
	c.state = st
	c.stateMu.Unlock()
}

func (c *connSession) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	return c.conn.Close()
}

func (c *connSession) writeFrameLocked(msgType uint8, payload []byte) error {
	return c.conn.WriteFrame(FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    msgType,
		SessionID:  c.sessionID,
		PayloadLen: uint32(len(payload)),
	}, payload)
}

func (c *connSession) writeFrame(msgType uint8, payload []byte) error {
	c.writeMu.Lock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.server.writeTimeout))
	err := c.writeFrameLocked(msgType, payload)
	_ = c.conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()

	if err != nil {
		c.server.log.Debug("session write failed, closing session",
			"peer", c.peerID, "msgType", msgType, "err", err)
		_ = c.Close()
	}
	return err
}

func (c *connSession) sendData(_ context.Context, pkt []byte) error {
	if c.closed.Load() {
		return ErrSessionClosed
	}
	if uint32(len(pkt)) > c.server.maxPayload {
		return ErrInvalidFrame
	}
	return c.writeFrame(MsgData, pkt)
}

func (c *connSession) readLoop(ctx context.Context) {
	idle := c.server.pongWait * 2
	if idle < c.server.keepAlive*3 {
		idle = c.server.keepAlive * 3
	}
	for {
		if c.closed.Load() {
			return
		}
		select {
		case <-ctx.Done():
			_ = c.Close()
			return
		case <-c.server.shutdown:
			_ = c.Close()
			return
		default:
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(idle))
		h, payload, err := c.conn.ReadFrame(c.server.maxPayload)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				c.server.log.Info("uplink pong timeout", "peer", c.peerID)
				c.server.metrics.IncCounter("uplink_ping_timeout_total", map[string]string{
					"transport": "wss", "tls_mode": string(c.server.tlsMode),
				})
				select {
				case <-ctx.Done():
					_ = c.Close()
					return
				case <-c.server.shutdown:
					_ = c.Close()
					return
				default:
				}
			}
			c.server.log.Debug("read frame ended", "peer", c.peerID, "err", err)
			_ = c.Close()
			return
		}

		switch h.MsgType {
		case MsgData:
			if err := c.server.opts.PacketHandler.HandleInboundPacket(ctx, c.peerID, payload); err != nil {
				c.server.log.Warn("packet handler", "peer", c.peerID, "err", err)
			}
			c.server.metrics.IncCounter("proxy_server_frames_in_total", nil)
			c.server.metrics.IncCounter("uplink_packets_rx_total", map[string]string{"transport": "wss"})
			c.server.metrics.IncCounter("uplink_bytes_rx_total", map[string]string{"transport": "wss"})
		case MsgPing:
			_ = c.writeFrame(MsgPong, nil)
		case MsgPong:
			// ok
		case MsgClose:
			_ = c.Close()
			return
		case MsgError:
			_ = c.Close()
			return
		default:
			c.server.log.Warn("unexpected msg type", "type", h.MsgType)
		}
	}
}

// EndpointURL builds a client-facing wss:// URL for the given host and port.
func EndpointURL(host string, port int) string {
	return fmt.Sprintf("wss://%s/uplink/v1", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}
