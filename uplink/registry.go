package uplink

import "sync"

// InMemoryRegistry is a thread-safe SessionRegistry with replace-on-attach semantics.
// If a new session is attached for an existing peer ID, the previous session's Close()
// is called when the previous value implements interface{ Close() error }.
type InMemoryRegistry struct {
	mu sync.RWMutex
	m  map[string]Session
}

// NewInMemoryRegistry returns an empty registry.
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{m: make(map[string]Session)}
}

// Attach registers a session for peerID, replacing any existing session.
func (r *InMemoryRegistry) Attach(peerID string, sess Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.m[peerID]; ok && old != nil && old != sess {
		if c, ok := old.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
	r.m[peerID] = sess
	return nil
}

// Get returns the session for peerID.
func (r *InMemoryRegistry) Get(peerID string) (Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.m[peerID]
	return s, ok && s != nil
}

// Detach removes a peer from the registry, whichever session is registered.
func (r *InMemoryRegistry) Detach(peerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, peerID)
}

// DetachSession removes peerID only if sess is still the registered session.
// A reconnecting client attaches its new session before the old session's read
// loop finishes unwinding, so an unconditional Detach from the old session would
// evict the live one and leave the peer looking session-less.
func (r *InMemoryRegistry) DetachSession(peerID string, sess Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.m[peerID]; ok && cur != sess {
		return
	}
	delete(r.m, peerID)
}

// PeerIDs returns the peer IDs with a registered session.
func (r *InMemoryRegistry) PeerIDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.m))
	for id, s := range r.m {
		if s != nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// CloseAll closes every registered session and clears the registry.
// Used by Server.Stop so clients drop and re-HELLO after a gateway restart
// (closing the listener alone leaves accepted TLS conns answering PING forever).
func (r *InMemoryRegistry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, s := range r.m {
		if c, ok := s.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		delete(r.m, id)
	}
}

// Len returns the number of registered sessions (for metrics / tests).
func (r *InMemoryRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.m)
}
