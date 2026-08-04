package sysproxy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gravitl/proxy/sysproxy"
)

func TestWritePAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "egress_proxy.pac")
	err := sysproxy.WritePAC(path, []string{"api.example.com", "*.cdn.example.com"}, "127.0.0.1:17832")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`host == "api.example.com"`,
		`PROXY 127.0.0.1:17832`,
		`dnsDomainIs(host, ".cdn.example.com")`,
		`return "DIRECT"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("PAC missing %q:\n%s", want, s)
		}
	}
}

func TestFileURL(t *testing.T) {
	u := sysproxy.FileURL("/tmp/egress_proxy.pac")
	if !strings.HasPrefix(u, "file://") {
		t.Fatalf("got %q", u)
	}
	if !strings.Contains(u, "egress_proxy.pac") {
		t.Fatalf("got %q", u)
	}
}
