package main

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/nats-io/nats.go/jetstream"
)

type KVCredentialStore struct {
	kv jetstream.KeyValue
}

func (s *KVCredentialStore) Save(ctx context.Context, userID, passwordHash string) error {
	_, err := s.kv.Put(ctx, userID, []byte(passwordHash))
	return err
}

func (s *KVCredentialStore) Lookup(ctx context.Context, userID string) (string, error) {
	entry, err := s.kv.Get(ctx, userID)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return "", ErrCredentialNotFound
	}
	if err != nil {
		return "", err
	}
	return string(entry.Value()), nil
}

func (s *KVCredentialStore) Delete(ctx context.Context, userID string) error {
	err := s.kv.Delete(ctx, userID)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	return err
}

type KVEmailIndex struct {
	kv jetstream.KeyValue
}

func (s *KVEmailIndex) Reserve(ctx context.Context, email, userID string) error {
	_, err := s.kv.Create(ctx, emailKey(email), []byte(userID))
	if errors.Is(err, jetstream.ErrKeyExists) {
		return ErrEmailAlreadyRegistered
	}
	return err
}

func (s *KVEmailIndex) Lookup(ctx context.Context, email string) (string, error) {
	entry, err := s.kv.Get(ctx, emailKey(email))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return "", ErrEmailNotFound
	}
	if err != nil {
		return "", err
	}
	return string(entry.Value()), nil
}

func (s *KVEmailIndex) Release(ctx context.Context, email, userID string) error {
	entry, err := s.kv.Get(ctx, emailKey(email))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(entry.Value()) != userID {
		return nil
	}
	if err := s.kv.Delete(ctx, emailKey(email), jetstream.LastRevision(entry.Revision())); errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil
	} else {
		return err
	}
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func emailKey(email string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(normalizeEmail(email)))
}
