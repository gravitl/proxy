package l7

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const maxConnectHeaderBytes = 64 << 10

// parseConnect reads one HTTP request from br and returns the CONNECT target.
// Only Method CONNECT is accepted. The remainder of br (if any) must be forwarded
// to the upstream after a successful tunnel setup.
func parseConnect(br *bufio.Reader) (ConnectTarget, *http.Request, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return ConnectTarget{}, nil, fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	if req.Method != http.MethodConnect {
		return ConnectTarget{}, req, fmt.Errorf("%w: method %s", ErrBadRequest, req.Method)
	}
	hostPort := req.Host
	if hostPort == "" && req.URL != nil {
		hostPort = req.URL.Host
	}
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return ConnectTarget{}, req, fmt.Errorf("%w: missing host", ErrBadRequest)
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		// CONNECT without port — default 443 for HTTPS-style use.
		host = hostPort
		port = "443"
		if strings.Contains(host, ":") {
			return ConnectTarget{}, req, fmt.Errorf("%w: invalid host %q", ErrBadRequest, hostPort)
		}
	}
	if host == "" || port == "" {
		return ConnectTarget{}, req, fmt.Errorf("%w: invalid host %q", ErrBadRequest, hostPort)
	}
	return ConnectTarget{Host: host, Port: port}, req, nil
}

func writeConnectResponse(w io.Writer, status int, reason string) error {
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n\r\n", status, reason)
	return err
}
