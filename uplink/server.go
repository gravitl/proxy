package uplink

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

// ServerOptions configures the TCP/TLS uplink server (spec §9.2).
type ServerOptions struct {
	ListenAddr      string
	TLSConfig       *tls.Config
	Authenticator   Authenticator
	PacketHandler   PacketHandler
	SessionRegistry SessionRegistry
	Logger          Logger
	Metrics         MetricsSink
	KeepAlivePeriod time.Duration
	WriteTimeout    time.Duration
	MaxFrameSize    int
}

// Server terminates TLS and manages framed sessions (spec §9.2).
type Server struct {
	opts         ServerOptions
	log          Logger
	metrics      MetricsSink
	registry     SessionRegistry
	maxPayload   uint32
	keepAlive    time.Duration
	writeTimeout time.Duration
	sessionIDGen atomic.Uint32
	listener     net.Listener
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
	if opts.TLSConfig == nil {
		return nil, errors.New("proxy: TLSConfig is required")
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
	return &Server{
		opts:         opts,
		log:          log,
		metrics:      metrics,
		registry:     reg,
		maxPayload:   uint32(max),
		keepAlive:    ka,
		writeTimeout: wt,
		shutdown:     make(chan struct{}),
	}, nil
}

// Start listens with TLS and accepts sessions until ctx is cancelled or Stop is called.
func (s *Server) Start(ctx context.Context) error {
	s.startMu.Lock()
	if s.listener != nil {
		s.startMu.Unlock()
		return errors.New("proxy: server already started")
	}
	ln, err := tls.Listen("tcp", s.opts.ListenAddr, s.opts.TLSConfig)
	if err != nil {
		s.startMu.Unlock()
		return err
	}
	s.listener = ln
	s.startMu.Unlock()

	s.serveWG.Add(1)
	go func() {
		defer s.serveWG.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if s.closed.Load() {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-s.shutdown:
					return
				default:
				}
				s.log.Warn("accept failed", "err", err)
				continue
			}
			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				_ = conn.Close()
				continue
			}
			s.connWG.Add(1)
			go func(c *tls.Conn) {
				defer s.connWG.Done()
				s.handleConnection(ctx, c)
			}(tlsConn)
		}
	}()
	return nil
}

// Addr returns the bound listen address (e.g. after Start with ":0"). It is nil before Start or after Stop.
func (s *Server) Addr() net.Addr {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Stop closes the listener and waits for handlers to finish.
func (s *Server) Stop(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		close(s.shutdown)
		s.closed.Store(true)
		s.startMu.Lock()
		ln := s.listener
		s.listener = nil
		s.startMu.Unlock()
		if ln != nil {
			_ = ln.Close()
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

func (s *Server) handleConnection(ctx context.Context, conn *tls.Conn) {
	defer conn.Close()

	s.metrics.IncCounter("proxy_server_connections_total", nil)

	h, payload, err := readFrame(conn, s.maxPayload)
	if err != nil {
		s.log.Warn("read hello frame failed", "err", err)
		return
	}
	if h.MsgType != MsgHello {
		s.log.Warn("expected MsgHello", "msgType", h.MsgType)
		return
	}

	var hello ClientHello
	if err := json.Unmarshal(payload, &hello); err != nil {
		s.log.Warn("invalid ClientHello JSON", "err", err)
		_ = s.writeError(conn, 0, "invalid_hello", "invalid hello payload")
		return
	}

	authCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	res, err := s.opts.Authenticator.ValidateClientHello(authCtx, hello)
	cancel()
	if err != nil || res == nil || res.PeerID == "" {
		s.metrics.IncCounter("proxy_server_auth_failures_total", nil)
		msg := "authentication failed"
		if err != nil {
			msg = err.Error()
		}
		_ = s.writeError(conn, 0, "auth_failed", msg)
		s.log.Warn("auth failed", "node_id", hello.NodeID, "err", err)
		return
	}

	sid := s.sessionIDGen.Add(1)
	cs := &connSession{
		server:    s,
		conn:      conn,
		peerID:    res.PeerID,
		sessionID: sid,
		state:     SessionAuthenticated,
	}

	ackBytes, err := json.Marshal(helloAckWire{SessionID: sid})
	if err != nil {
		s.log.Error("marshal hello ack", "err", err)
		return
	}
	if err := cs.writeFrameLocked(MsgHelloAck, ackBytes); err != nil {
		s.log.Warn("write hello ack", "err", err)
		return
	}

	cs.setState(SessionAttached)
	if err := s.registry.Attach(res.PeerID, cs); err != nil {
		s.log.Error("session attach", "err", err)
		_ = cs.Close()
		return
	}
	s.metrics.IncCounter("proxy_server_sessions_attached_total", nil)
	if reg, ok := s.registry.(*InMemoryRegistry); ok {
		s.metrics.SetGauge("proxy_server_active_sessions", float64(reg.Len()), nil)
	}

	defer func() {
		s.registry.Detach(res.PeerID)
		cs.setState(SessionClosed)
		if reg, ok := s.registry.(*InMemoryRegistry); ok {
			s.metrics.SetGauge("proxy_server_active_sessions", float64(reg.Len()), nil)
		}
	}()

	cs.readLoop(ctx)
}

func (s *Server) writeError(conn net.Conn, sessionID uint32, code, msg string) error {
	b, err := json.Marshal(errorPayloadWire{Code: code, Message: msg})
	if err != nil {
		return err
	}
	return writeFrame(conn, FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    MsgError,
		SessionID:  sessionID,
		PayloadLen: uint32(len(b)),
	}, b)
}

// connSession is the server's session for one TLS connection.
type connSession struct {
	server    *Server
	conn      *tls.Conn
	peerID    string
	sessionID uint32
	writeMu   sync.Mutex
	state     SessionState
	stateMu   sync.RWMutex
	closed    atomic.Bool
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
	return c.conn.Close()
}

func (c *connSession) writeFrameLocked(msgType uint8, payload []byte) error {
	return writeFrame(c.conn, FrameHeader{
		Version:    ProtocolVersion,
		MsgType:    msgType,
		SessionID:  c.sessionID,
		PayloadLen: uint32(len(payload)),
	}, payload)
}

func (c *connSession) writeFrame(msgType uint8, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(c.server.writeTimeout))
	err := c.writeFrameLocked(msgType, payload)
	_ = c.conn.SetWriteDeadline(time.Time{})
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
	for {
		if c.closed.Load() {
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(c.server.keepAlive * 3))
		h, payload, err := readFrame(c.conn, c.server.maxPayload)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
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
