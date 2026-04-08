package main

import (
	"fmt"
	"hash/fnv"
	"log/slog"
	"time"

	"github.com/synadia-labs/rita"
)

const maxLoginAttempts = 100

type AuthState struct {
	usersByID     map[string]*UserRecord
	usersByEmail  map[string]*UserRecord
	loginAttempts map[string][]LoginAttempt
}

func NewAuthState() *AuthState {
	return &AuthState{
		usersByID:     make(map[string]*UserRecord),
		usersByEmail:  make(map[string]*UserRecord),
		loginAttempts: make(map[string][]LoginAttempt),
	}
}

func (s *AuthState) Decide(cmd *rita.Command) ([]*rita.Event, error) {
	switch c := cmd.Data.(type) {
	case *RegisterUser:
		return s.decideRegister(c)
	case *RecordSuccessfulLogin:
		return s.decideSuccessfulLogin(c)
	case *RecordFailedLogin:
		return s.decideFailedLogin(c)
	case *RecordLogout:
		return s.decideLogout(c)
	default:
		return nil, fmt.Errorf("unknown command type: %T", cmd.Data)
	}
}

func (s *AuthState) decideRegister(cmd *RegisterUser) ([]*rita.Event, error) {
	if cmd.UserID == "" {
		return nil, fmt.Errorf("user id required")
	}
	if _, exists := s.usersByEmail[cmd.Email]; exists {
		return nil, ErrEmailAlreadyRegistered
	}

	return []*rita.Event{{
		Type:   "UserRegistered",
		Entity: fmt.Sprintf("user.%s", cmd.UserID),
		Data: &UserRegistered{
			UserID: cmd.UserID,
			Email:  cmd.Email,
		},
	}}, nil
}

func (s *AuthState) decideSuccessfulLogin(cmd *RecordSuccessfulLogin) ([]*rita.Event, error) {
	attempts := s.loginAttempts[cmd.Email]
	recentFailures := 0
	cutoff := time.Now().Add(-10 * time.Minute)
	for _, a := range attempts {
		if !a.Success && a.At.After(cutoff) {
			recentFailures++
		}
	}
	if recentFailures >= 5 {
		slog.Warn("login: suspicious activity detected",
			"email", cmd.Email,
			"recent_failures", recentFailures,
			"window", "10m",
		)
	}

	return []*rita.Event{{
		Type:   "UserLoginSucceeded",
		Entity: fmt.Sprintf("user.%s", cmd.UserID),
		Data: &UserLoginSucceeded{
			UserID:    cmd.UserID,
			Email:     cmd.Email,
			IP:        cmd.IP,
			UserAgent: cmd.UserAgent,
		},
	}}, nil
}

// emailHasher returns a hash of the email address for use as a user ID during login attempts.
func emailHasher(email string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(email))
	return fmt.Sprintf("%x", h.Sum64())
}

// Returns event with nil error — failed logins must be persisted for forensics.
// Rita drops events when Decide returns an error.
func (s *AuthState) decideFailedLogin(cmd *RecordFailedLogin) ([]*rita.Event, error) {
	emailHash := emailHasher(cmd.Email)
	return []*rita.Event{{
		Type:   "UserLoginFailed",
		Entity: fmt.Sprintf("loginattempt.%s", emailHash),
		Data: &UserLoginFailed{
			Email:     cmd.Email,
			IP:        cmd.IP,
			UserAgent: cmd.UserAgent,
			Reason:    cmd.Reason,
		},
	}}, nil
}

func (s *AuthState) decideLogout(cmd *RecordLogout) ([]*rita.Event, error) {
	if cmd.UserID == "" {
		return nil, nil
	}
	return []*rita.Event{{
		Type:   "UserLoggedOut",
		Entity: fmt.Sprintf("user.%s", cmd.UserID),
		Data: &UserLoggedOut{
			UserID: cmd.UserID,
		},
	}}, nil
}

func (s *AuthState) Evolve(evt *rita.Event) error {
	switch e := evt.Data.(type) {
	case *UserRegistered:
		record := &UserRecord{
			UserID: e.UserID,
			Email:  e.Email,
			Status: "active",
		}
		s.usersByID[e.UserID] = record
		s.usersByEmail[e.Email] = record
		return nil

	case *UserLoginSucceeded:
		s.trackAttempt(e.Email, LoginAttempt{
			IP:        e.IP,
			UserAgent: e.UserAgent,
			Success:   true,
			At:        evt.Time,
		})
		return nil

	case *UserLoginFailed:
		s.trackAttempt(e.Email, LoginAttempt{
			IP:        e.IP,
			UserAgent: e.UserAgent,
			Success:   false,
			At:        evt.Time,
		})
		return nil

	case *UserLoggedOut:
		return nil

	default:
		return fmt.Errorf("unknown event type: %T", evt.Data)
	}
}

func (s *AuthState) trackAttempt(email string, attempt LoginAttempt) {
	s.loginAttempts[email] = append(s.loginAttempts[email], attempt)
	if len(s.loginAttempts[email]) > maxLoginAttempts {
		s.loginAttempts[email] = s.loginAttempts[email][len(s.loginAttempts[email])-maxLoginAttempts:]
	}
}

func (s *AuthState) UserByEmail(email string) *UserRecord {
	return s.usersByEmail[email]
}

func (s *AuthState) UserByID(id string) *UserRecord {
	return s.usersByID[id]
}

func (s *AuthState) LoginAttemptsByEmail(email string) []LoginAttempt {
	src := s.loginAttempts[email]
	dst := make([]LoginAttempt, len(src))
	copy(dst, src)
	return dst
}
