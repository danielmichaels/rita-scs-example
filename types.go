package main

import (
	"time"

	"errors"

	"github.com/synadia-labs/rita/types"
)

var (
	ErrCredentialNotFound     = errors.New("credential not found")
	ErrEmailAlreadyRegistered = errors.New("email already registered")
	ErrEmailNotFound          = errors.New("email not found")
)

type RegisterUser struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

type RecordSuccessfulLogin struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

type RecordFailedLogin struct {
	Email     string `json:"email"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Reason    string `json:"reason"`
}

type RecordLogout struct {
	UserID string `json:"user_id"`
}

// Events — facts persisted to the stream. Never deleted, always replayable.

type UserRegistered struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

type UserLoginSucceeded struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

type UserLoginFailed struct {
	Email     string `json:"email"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
	Reason    string `json:"reason"`
}

type UserLoggedOut struct {
	UserID string `json:"user_id"`
}

// Read model — shaped for the queries handlers actually make.

type UserRecord struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Status string `json:"status"`
}

type LoginAttempt struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Success   bool      `json:"success"`
	At        time.Time `json:"at"`
}

// Registry — maps type names to constructors so rita can deserialize.

var authTypes = map[string]*types.Type{
	"RegisterUser":          {Init: func() any { return &RegisterUser{} }},
	"RecordSuccessfulLogin": {Init: func() any { return &RecordSuccessfulLogin{} }},
	"RecordFailedLogin":     {Init: func() any { return &RecordFailedLogin{} }},
	"RecordLogout":          {Init: func() any { return &RecordLogout{} }},
	"UserRegistered":        {Init: func() any { return &UserRegistered{} }},
	"UserLoginSucceeded":    {Init: func() any { return &UserLoginSucceeded{} }},
	"UserLoginFailed":       {Init: func() any { return &UserLoginFailed{} }},
	"UserLoggedOut":         {Init: func() any { return &UserLoggedOut{} }},
}

func newRegistry() (*types.Registry, error) {
	return types.NewRegistry(authTypes)
}
