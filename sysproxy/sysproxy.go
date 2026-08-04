// Package sysproxy manages client-side PAC files and OS system proxy settings
// for L7 HTTP CONNECT egress (see package l7).
//
// Callers (e.g. netclient) write a PAC with WritePAC, then Apply to install it as
// the OS auto-proxy; Clear removes it when proxy routes are gone.
package sysproxy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const stateFileName = "egress_proxy_sys.state"

// Options configure where state is stored and how Linux shell drop-ins are written.
type Options struct {
	// StateDir holds the apply-state file (and optional Linux profile script copy).
	// Required for Apply/Clear.
	StateDir string
	// LocalProxyURL is the HTTP proxy URL for profile.d / env hints (e.g. http://127.0.0.1:17832).
	LocalProxyURL string
	// ProfileScriptName is the basename under StateDir and /etc/profile.d (Linux).
	// Default: proxy-egress.sh
	ProfileScriptName string
}

func (o Options) profileScriptName() string {
	if o.ProfileScriptName != "" {
		return o.ProfileScriptName
	}
	return "proxy-egress.sh"
}

func (o Options) statePath() string {
	return filepath.Join(o.StateDir, stateFileName)
}

type state struct {
	Applied        bool     `json:"applied"`
	PACFileURL     string   `json:"pac_file_url"`
	DarwinServices []string `json:"darwin_services,omitempty"`
}

func loadState(opts Options) state {
	if opts.StateDir == "" {
		return state{}
	}
	b, err := os.ReadFile(opts.statePath())
	if err != nil {
		return state{}
	}
	var st state
	if json.Unmarshal(b, &st) != nil {
		return state{}
	}
	return st
}

func saveState(opts Options, st state) {
	if opts.StateDir == "" {
		return
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(opts.statePath(), b, 0644)
}

func clearStateFile(opts Options) {
	if opts.StateDir == "" {
		return
	}
	_ = os.Remove(opts.statePath())
}

// FileURL returns a file:// URL for an on-disk PAC path (OS settings need a URL).
func FileURL(pacPath string) string {
	abs, err := filepath.Abs(pacPath)
	if err != nil {
		abs = pacPath
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	// Windows: file:///C:/...
	if len(abs) >= 2 && abs[1] == ':' {
		u.Path = "/" + filepath.ToSlash(abs)
	}
	return u.String()
}

// WritePAC writes a PAC that sends the given domains through proxyHostPort
// (host:port, typically 127.0.0.1:17832). Domains may include *.example.com wildcards.
func WritePAC(path string, domains []string, proxyHostPort string) error {
	host, port, ok := splitHostPort(proxyHostPort)
	if !ok {
		return fmt.Errorf("sysproxy: invalid proxy address %q", proxyHostPort)
	}
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase();\n")
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			suf := d[1:] // .example.com
			fmt.Fprintf(&b, "  if (dnsDomainIs(host, %q) || host == %q) return \"PROXY %s:%s\";\n",
				suf, d[2:], host, port)
			continue
		}
		fmt.Fprintf(&b, "  if (host == %q) return \"PROXY %s:%s\";\n", d, host, port)
	}
	b.WriteString("  return \"DIRECT\";\n}\n")
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func splitHostPort(addr string) (host, port string, ok bool) {
	// net.SplitHostPort requires brackets for IPv6; keep simple for 127.0.0.1:port
	i := strings.LastIndex(addr, ":")
	if i <= 0 || i == len(addr)-1 {
		return "", "", false
	}
	return addr[:i], addr[i+1:], true
}

// Apply installs the PAC file as the OS system auto-proxy.
func Apply(pacPath string, opts Options) error {
	if opts.StateDir == "" {
		return fmt.Errorf("sysproxy: StateDir is required")
	}
	return apply(pacPath, opts)
}

// Clear removes the OS system auto-proxy previously installed by Apply.
func Clear(opts Options) error {
	return clear(opts)
}
