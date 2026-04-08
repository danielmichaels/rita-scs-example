package main

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// NATSStore implements the scs.Store interface using NATS KV.
//
// This is the glue between SCS (which manages cookies and session lifecycle)
// and NATS (which stores the actual session data). No Redis or Postgres needed.
//
// Session expiry is handled by the KV bucket TTL configured in main.go.
// NATS automatically purges expired keys - no cleanup job required.
type NATSStore struct {
	kv jetstream.KeyValue
}

// Find retrieves encoded session data by token.
// SCS calls this on every request to load the session.
func (s *NATSStore) Find(token string) ([]byte, bool, error) {
	entry, err := s.kv.Get(context.Background(), token)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, false, nil // not found is not an error - just no session
	}
	if err != nil {
		return nil, false, err
	}
	return entry.Value(), true, nil
}

// Commit saves encoded session data for a token.
// SCS calls this at the end of every request where session data changed.
// The expiry parameter is ignored here - TTL is set globally on the bucket.
// For per-session expiry, store expiry inside the value and check it in Find.
func (s *NATSStore) Commit(token string, b []byte, _ time.Time) error {
	_, err := s.kv.Put(context.Background(), token, b)
	return err
}

// Delete removes a session. SCS calls this on logout (Destroy).
func (s *NATSStore) Delete(token string) error {
	err := s.kv.Delete(context.Background(), token)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil // already gone, not an error
	}
	return err
}
