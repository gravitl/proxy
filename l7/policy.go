package l7

import (
	"fmt"
	"strings"
)

// DomainMatcher decides whether a CONNECT destination is allowed.
// Implementations are supplied by the integrator (e.g. netclient from control-plane lists).
type DomainMatcher interface {
	// Allow returns nil if host (and optional port) may be dialed; otherwise a reason error.
	Allow(host, port string) error
}

// Allowlist matches exact hostnames and optional "*.suffix" wildcards (one or more labels).
// Matching is case-insensitive. Empty Allowlist denies all hosts.
type Allowlist struct {
	// Domains are exact names (example.com) or wildcards (*.example.com).
	Domains []string
}

// Allow implements DomainMatcher.
func (a Allowlist) Allow(host, port string) error {
	_ = port
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrBadRequest)
	}
	for _, raw := range a.Domains {
		pat := strings.ToLower(strings.TrimSpace(raw))
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "*.") {
			suf := pat[1:] // ".example.com"
			if strings.HasSuffix(host, suf) && len(host) > len(suf) {
				return nil
			}
			continue
		}
		if host == pat {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrForbidden, host)
}

// AllowAll permits any non-empty host (useful for tests; not for production egress).
type AllowAll struct{}

// Allow implements DomainMatcher.
func (AllowAll) Allow(host, port string) error {
	_ = port
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%w: empty host", ErrBadRequest)
	}
	return nil
}
