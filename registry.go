package proxy

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

// Detach removes a peer from the registry.
func (r *InMemoryRegistry) Detach(peerID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, peerID)
}

// Len returns the number of registered sessions (for metrics / tests).
func (r *InMemoryRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.m)
}
