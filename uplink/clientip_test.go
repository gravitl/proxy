package uplink

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPFromRequest(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/uplink/v1", nil)
	req.RemoteAddr = "203.0.113.10:54321"
	if got := ClientIPFromRequest(req); got != "203.0.113.10" {
		t.Fatalf("RemoteAddr: got %q", got)
	}

	req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got := ClientIPFromRequest(req); got != "198.51.100.7" {
		t.Fatalf("X-Forwarded-For: got %q", got)
	}

	req.Header.Del("X-Forwarded-For")
	req.Header.Set("X-Real-IP", "192.0.2.55")
	if got := ClientIPFromRequest(req); got != "192.0.2.55" {
		t.Fatalf("X-Real-IP: got %q", got)
	}
}
