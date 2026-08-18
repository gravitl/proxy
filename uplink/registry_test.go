package uplink

import (
	"sort"
	"testing"
)

type fakeSession struct {
	peerID string
	closed bool
}

func (f *fakeSession) PeerID() string      { return f.peerID }
func (f *fakeSession) State() SessionState { return SessionAttached }
func (f *fakeSession) Close() error {
	f.closed = true
	return nil
}

func TestInMemoryRegistryPeerIDs(t *testing.T) {
	r := NewInMemoryRegistry()
	if got := r.PeerIDs(); len(got) != 0 {
		t.Fatalf("empty registry returned %v", got)
	}

	for _, id := range []string{"a", "b", "c"} {
		if err := r.Attach(id, &fakeSession{peerID: id}); err != nil {
			t.Fatal(err)
		}
	}
	got := r.PeerIDs()
	sort.Strings(got)
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("PeerIDs = %v, want [a b c]", got)
	}

	r.Detach("b")
	got = r.PeerIDs()
	sort.Strings(got)
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("after Detach PeerIDs = %v, want [a c]", got)
	}
}

// TestDetachSessionKeepsReplacement covers a client reconnect: the new session is
// attached while the old session's read loop is still unwinding, so the old
// session's detach must not evict the live replacement.
func TestDetachSessionKeepsReplacement(t *testing.T) {
	r := NewInMemoryRegistry()
	old := &fakeSession{peerID: "peer-1"}
	if err := r.Attach("peer-1", old); err != nil {
		t.Fatal(err)
	}

	replacement := &fakeSession{peerID: "peer-1"}
	if err := r.Attach("peer-1", replacement); err != nil {
		t.Fatal(err)
	}
	if !old.closed {
		t.Error("replaced session was not closed on re-attach")
	}

	r.DetachSession("peer-1", old)

	sess, ok := r.Get("peer-1")
	if !ok {
		t.Fatal("live session evicted by the replaced session's detach")
	}
	if sess != Session(replacement) {
		t.Fatalf("registry holds %v, want the replacement session", sess)
	}

	r.DetachSession("peer-1", replacement)
	if _, ok := r.Get("peer-1"); ok {
		t.Error("session still registered after its own detach")
	}
}
