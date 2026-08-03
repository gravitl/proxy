package l7

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	defaultDialTimeout = 15 * time.Second
	defaultIdleTimeout = 5 * time.Minute
)

// Server is an HTTP CONNECT forward proxy intended to listen on a mesh address
// of an egress gateway.
type Server struct {
	opts   ServerOptions
	log    Logger
	dialer Dialer
	mu     sync.Mutex
	ln     net.Listener
	cancel context.CancelFunc
	closed bool
	wg     sync.WaitGroup
}

// Dialer dials TCP destinations for CONNECT tunnels.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// NewServer validates options and returns a Server. Does not listen until Start.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.ListenAddr == "" {
		return nil, errors.New("l7: ListenAddr is required")
	}
	if opts.Matcher == nil {
		return nil, errors.New("l7: Matcher is required")
	}
	log := opts.Logger
	if log == nil {
		log = noopLogger{}
	}
	dialer := opts.Dialer
	if dialer == nil {
		d := &net.Dialer{Timeout: opts.DialTimeout}
		if d.Timeout <= 0 {
			d.Timeout = defaultDialTimeout
		}
		dialer = d
	}
	return &Server{opts: opts, log: log, dialer: dialer}, nil
}

// Start binds ListenAddr and serves HTTP CONNECT.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrServerClosed
	}
	if s.ln != nil {
		return errors.New("l7: server already started")
	}
	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return fmt.Errorf("l7: listen: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.ln = ln
	s.cancel = cancel
	s.log.Info("l7 CONNECT proxy listening", "addr", ln.Addr().String())
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.serve(runCtx, ln)
	}()
	return nil
}

// Addr returns the bound address, or "" if not listening.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Stop closes the listener and waits for in-flight handlers to finish (bounded by ctx).
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	var err error
	if s.ln != nil {
		err = s.ln.Close()
		s.ln = nil
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}
	return err
}

func (s *Server) serve(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				s.log.Debug("accept ended", "err", err)
				return
			}
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(ctx, c)
		}(conn)
	}
}

func (s *Server) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(s.headerTimeout()))
	br := bufio.NewReaderSize(client, maxConnectHeaderBytes)
	target, _, err := parseConnect(br)
	if err != nil {
		s.log.Debug("bad CONNECT", "err", err)
		_ = writeConnectResponse(client, 400, "Bad Request")
		return
	}
	_ = client.SetDeadline(time.Time{})

	if err := s.opts.Matcher.Allow(target.Host, target.Port); err != nil {
		s.log.Info("CONNECT denied", "host", target.Host, "port", target.Port, "err", err)
		status := 403
		reason := "Forbidden"
		if errors.Is(err, ErrBadRequest) {
			status = 400
			reason = "Bad Request"
		}
		_ = writeConnectResponse(client, status, reason)
		return
	}

	dialTimeout := s.opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	upstream, err := s.dialer.DialContext(dialCtx, "tcp", target.HostPort())
	cancel()
	if err != nil {
		s.log.Warn("CONNECT dial failed", "target", target.HostPort(), "err", err)
		_ = writeConnectResponse(client, 502, "Bad Gateway")
		return
	}
	defer upstream.Close()

	if err := writeConnectResponse(client, 200, "Connection Established"); err != nil {
		s.log.Debug("write 200 failed", "err", err)
		return
	}

	idle := s.opts.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	deadline := time.Now().Add(idle)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)

	// Any bytes buffered past the CONNECT headers (e.g. TLS ClientHello) must go upstream.
	clientReader := io.Reader(br)
	if br.Buffered() == 0 {
		clientReader = client
	} else {
		clientReader = io.MultiReader(br, client)
	}

	s.log.Debug("CONNECT tunnel up", "target", target.HostPort())
	tunnel(client, upstream, clientReader)
}

func (s *Server) headerTimeout() time.Duration {
	if s.opts.DialTimeout > 0 {
		return s.opts.DialTimeout
	}
	return defaultDialTimeout
}

func tunnel(client, upstream net.Conn, clientReader io.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientReader)
		_ = closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		_ = closeWrite(client)
	}()
	wg.Wait()
}

func closeWrite(c net.Conn) error {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

type noopLogger struct{}

func (noopLogger) Debug(string, ...any) {}
func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Warn(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}
