package main

import (
	"testing"
	"time"

	"github.com/synadia-labs/rita"
)

func newTestState() *AuthState {
	return NewAuthState()
}

func registerTestUser(t *testing.T, state *AuthState) *UserRegistered {
	t.Helper()
	events, err := state.Decide(&rita.Command{
		Type: "RegisterUser",
		Data: &RegisterUser{UserID: "uid-1", Email: "dan@test.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := state.Evolve(e); err != nil {
			t.Fatal(err)
		}
	}
	return events[0].Data.(*UserRegistered)
}

func TestDecide_RegisterUser_Success(t *testing.T) {
	state := newTestState()

	events, err := state.Decide(&rita.Command{
		Type: "RegisterUser",
		Data: &RegisterUser{
			UserID: "uid-1",
			Email:  "dan@test.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "UserRegistered" {
		t.Fatalf("expected UserRegistered, got %s", events[0].Type)
	}

	reg := events[0].Data.(*UserRegistered)
	if reg.Email != "dan@test.com" {
		t.Fatalf("expected dan@test.com, got %s", reg.Email)
	}
	if reg.UserID == "" {
		t.Fatal("expected non-empty user ID")
	}
}

func TestDecide_RegisterUser_DuplicateEmail(t *testing.T) {
	state := newTestState()

	events, err := state.Decide(&rita.Command{
		Type: "RegisterUser",
		Data: &RegisterUser{UserID: "uid-1", Email: "dan@test.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := state.Evolve(e); err != nil {
			t.Fatal(err)
		}
	}

	_, err = state.Decide(&rita.Command{
		Type: "RegisterUser",
		Data: &RegisterUser{UserID: "uid-2", Email: "dan@test.com"},
	})
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
}

func TestDecide_RecordSuccessfulLogin(t *testing.T) {
	state := newTestState()
	reg := registerTestUser(t, state)

	events, err := state.Decide(&rita.Command{
		Type: "RecordSuccessfulLogin",
		Data: &RecordSuccessfulLogin{
			UserID:    reg.UserID,
			Email:     "dan@test.com",
			IP:        "127.0.0.1",
			UserAgent: "curl/8.0",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "UserLoginSucceeded" {
		t.Fatalf("expected UserLoginSucceeded, got %s", events[0].Type)
	}

	login := events[0].Data.(*UserLoginSucceeded)
	if login.UserID != reg.UserID {
		t.Fatalf("expected user ID %s, got %s", reg.UserID, login.UserID)
	}
}

func TestDecide_RecordFailedLogin(t *testing.T) {
	state := newTestState()

	events, err := state.Decide(&rita.Command{
		Type: "RecordFailedLogin",
		Data: &RecordFailedLogin{
			Email:  "nobody@test.com",
			IP:     "10.0.0.1",
			Reason: "unknown_email",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != "UserLoginFailed" {
		t.Fatalf("expected UserLoginFailed, got %s", events[0].Type)
	}

	failed := events[0].Data.(*UserLoginFailed)
	if failed.Reason != "unknown_email" {
		t.Fatalf("expected reason unknown_email, got %s", failed.Reason)
	}
}

func TestDecide_RecordSuccessfulLogin_SuspiciousActivityLog(t *testing.T) {
	state := newTestState()
	registerTestUser(t, state)

	for i := 0; i < 5; i++ {
		events, err := state.Decide(&rita.Command{
			Type: "RecordFailedLogin",
			Data: &RecordFailedLogin{
				Email:  "dan@test.com",
				IP:     "10.0.0.1",
				Reason: "bad_credentials",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if err := state.Evolve(e); err != nil {
				t.Fatal(err)
			}
		}
	}

	events, err := state.Decide(&rita.Command{
		Type: "RecordSuccessfulLogin",
		Data: &RecordSuccessfulLogin{
			UserID: state.usersByEmail["dan@test.com"].UserID,
			Email:  "dan@test.com",
			IP:     "10.0.0.1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestEvolve_UserRegistered(t *testing.T) {
	state := newTestState()

	err := state.Evolve(&rita.Event{
		Type: "UserRegistered",
		Time: time.Now(),
		Data: &UserRegistered{
			UserID: "uid-1",
			Email:  "dan@test.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := state.usersByEmail["dan@test.com"]; !ok {
		t.Fatal("user not indexed by email")
	}
	if _, ok := state.usersByID["uid-1"]; !ok {
		t.Fatal("user not indexed by ID")
	}
	if state.usersByEmail["dan@test.com"].Status != "active" {
		t.Fatalf("expected active, got %s", state.usersByEmail["dan@test.com"].Status)
	}
}

func TestEvolve_UserLoginSucceeded_TracksAttempt(t *testing.T) {
	state := newTestState()

	_ = state.Evolve(&rita.Event{
		Type: "UserRegistered",
		Time: time.Now(),
		Data: &UserRegistered{UserID: "uid-1", Email: "dan@test.com"},
	})

	err := state.Evolve(&rita.Event{
		Type: "UserLoginSucceeded",
		Time: time.Now(),
		Data: &UserLoginSucceeded{
			UserID:    "uid-1",
			Email:     "dan@test.com",
			IP:        "10.0.0.1",
			UserAgent: "curl",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	attempts := state.loginAttempts["dan@test.com"]
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	if !attempts[0].Success {
		t.Fatal("expected success=true")
	}
}

func TestEvolve_UserLoginFailed_TracksAttempt(t *testing.T) {
	state := newTestState()

	err := state.Evolve(&rita.Event{
		Type: "UserLoginFailed",
		Time: time.Now(),
		Data: &UserLoginFailed{
			Email:  "dan@test.com",
			IP:     "10.0.0.1",
			Reason: "bad_credentials",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	attempts := state.loginAttempts["dan@test.com"]
	if len(attempts) != 1 {
		t.Fatalf("expected 1 attempt, got %d", len(attempts))
	}
	if attempts[0].Success {
		t.Fatal("expected success=false")
	}
}

func TestEvolve_LoginAttempts_BoundedTo100(t *testing.T) {
	state := newTestState()

	for i := 0; i < 150; i++ {
		_ = state.Evolve(&rita.Event{
			Type: "UserLoginFailed",
			Time: time.Now(),
			Data: &UserLoginFailed{
				Email:  "dan@test.com",
				IP:     "10.0.0.1",
				Reason: "bad_credentials",
			},
		})
	}

	if len(state.loginAttempts["dan@test.com"]) != 100 {
		t.Fatalf("expected 100 attempts (bounded), got %d", len(state.loginAttempts["dan@test.com"]))
	}
}
