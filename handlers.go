package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/nats-io/nuid"
	"github.com/synadia-labs/rita"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const ctxUser contextKey = "user"

type App struct {
	es             *rita.EventStore
	model          *rita.Model[*AuthState]
	emailIndex     *KVEmailIndex
	credentials    *KVCredentialStore
	sessionManager *scs.SessionManager
}

func (a *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		slog.Warn("register: parse form failed", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := normalizeEmail(r.PostFormValue("email"))
	password := r.PostFormValue("password")

	slog.Info("register: attempt", "email", email, "has_password", password != "")

	if email == "" || password == "" {
		slog.Warn("register: missing fields", "email_empty", email == "", "password_empty", password == "")
		http.Error(w, "email and password required", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		slog.Error("register: bcrypt failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	userID := nuid.Next()
	if err := a.emailIndex.Reserve(r.Context(), email, userID); err != nil {
		if errors.Is(err, ErrEmailAlreadyRegistered) {
			slog.Warn("register: duplicate email", "email", email)
			http.Error(w, "email already registered", http.StatusConflict)
			return
		}
		slog.Error("register: reserve email failed", "email", email, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	cleanup := func() {
		if err := a.credentials.Delete(r.Context(), userID); err != nil {
			slog.Error("register: cleanup credential failed", "user_id", userID, "error", err)
		}
		if err := a.emailIndex.Release(r.Context(), email, userID); err != nil {
			slog.Error("register: cleanup email reservation failed", "email", email, "user_id", userID, "error", err)
		}
	}

	if err := a.credentials.Save(r.Context(), userID, string(hash)); err != nil {
		slog.Error("register: save credential failed", "user_id", userID, "error", err)
		cleanup()
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_, _, err = a.es.DecideAndEvolve(r.Context(), a.model, &rita.Command{
		Type: "RegisterUser",
		Data: &RegisterUser{
			UserID: userID,
			Email:  email,
		},
	})
	if err != nil {
		cleanup()
		if errors.Is(err, ErrEmailAlreadyRegistered) {
			slog.Warn("register: rejected", "email", email, "error", err)
			http.Error(w, "email already registered", http.StatusConflict)
			return
		}
		slog.Error("register: append failed", "email", email, "user_id", userID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("register: success", "email", email, "user_id", userID)
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "registered - you can now log in")
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		slog.Warn("login: parse form failed", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := normalizeEmail(r.PostFormValue("email"))
	password := r.PostFormValue("password")

	slog.Info("login: attempt", "email", email)

	var user *UserRecord
	if err := a.model.View(func(state *AuthState) error {
		user = state.UserByEmail(email)
		return nil
	}); err != nil {
		slog.Error("login: model view failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		a.recordFailedLogin(r, email, "unknown_email")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if user.Status != "active" {
		a.recordFailedLogin(r, email, "account_locked")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	passwordHash, err := a.credentials.Lookup(r.Context(), user.UserID)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			slog.Error("login: credential missing", "user_id", user.UserID, "email", email)
		} else {
			slog.Error("login: credential lookup failed", "user_id", user.UserID, "email", email, "error", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		a.recordFailedLogin(r, email, "bad_credentials")
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := a.sessionManager.RenewToken(r.Context()); err != nil {
		slog.Error("login: renew token failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.sessionManager.Put(r.Context(), "userID", user.UserID)
	a.sessionManager.Put(r.Context(), "email", user.Email)

	if err := a.commitSession(r.Context(), w); err != nil {
		slog.Error("login: commit session failed", "user_id", user.UserID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_, _, err = a.es.DecideAndEvolve(r.Context(), a.model, &rita.Command{
		Type: "RecordSuccessfulLogin",
		Data: &RecordSuccessfulLogin{
			UserID:    user.UserID,
			Email:     email,
			IP:        r.RemoteAddr,
			UserAgent: r.UserAgent(),
		},
	})
	if err != nil {
		slog.Error("login: record success failed", "email", email, "user_id", user.UserID, "error", err)
		a.destroySession(r.Context(), w)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	slog.Info("login: success", "user_id", user.UserID, "email", email)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (a *App) commitSession(ctx context.Context, w http.ResponseWriter) error {
	token, expiry, err := a.sessionManager.Commit(ctx)
	if err != nil {
		return err
	}
	a.sessionManager.WriteSessionCookie(ctx, w, token, expiry)
	return nil
}

func (a *App) destroySession(ctx context.Context, w http.ResponseWriter) {
	if err := a.sessionManager.Destroy(ctx); err != nil {
		slog.Error("session: destroy failed", "error", err)
		return
	}
	a.sessionManager.WriteSessionCookie(ctx, w, "", time.Time{})
}

func (a *App) recordFailedLogin(r *http.Request, email, reason string) {
	slog.Warn("login: failed", "email", email, "reason", reason)
	if _, _, err := a.es.DecideAndEvolve(r.Context(), a.model, &rita.Command{
		Type: "RecordFailedLogin",
		Data: &RecordFailedLogin{
			Email:     email,
			IP:        r.RemoteAddr,
			UserAgent: r.UserAgent(),
			Reason:    reason,
		},
	}); err != nil {
		slog.Error("login: record failed", "email", email, "error", err)
	}
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	userID := a.sessionManager.GetString(r.Context(), "userID")

	if userID == "" {
		slog.Warn("logout: no session", "remote", r.RemoteAddr)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if err := a.sessionManager.Destroy(r.Context()); err != nil {
		slog.Error("logout: destroy session failed", "user_id", userID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if _, _, err := a.es.DecideAndEvolve(r.Context(), a.model, &rita.Command{
		Type: "RecordLogout",
		Data: &RecordLogout{UserID: userID},
	}); err != nil {
		slog.Error("logout: record failed", "user_id", userID, "error", err)
	}

	slog.Info("logout: success", "user_id", userID)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(ctxUser).(*UserRecord)
	fmt.Fprintf(w, "welcome %s (id: %s)\n", user.Email, user.UserID)
}

func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "POST /login with email= and password=")
}

func (a *App) handleMyLogins(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value(ctxUser).(*UserRecord)

	var attempts []LoginAttempt
	if err := a.model.View(func(state *AuthState) error {
		attempts = state.LoginAttemptsByEmail(user.Email)
		return nil
	}); err != nil {
		slog.Error("my logins: model view failed", "user_id", user.UserID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(attempts)
	if err != nil {
		slog.Error("my logins: marshal failed", "user_id", user.UserID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration", time.Since(start),
			"remote", r.RemoteAddr,
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := a.sessionManager.GetString(r.Context(), "userID")
		if userID == "" {
			slog.Warn("auth: no session", "path", r.URL.Path)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		var user *UserRecord
		if err := a.model.View(func(state *AuthState) error {
			user = state.UserByID(userID)
			return nil
		}); err != nil {
			slog.Error("auth: model view failed", "user_id", userID, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if user == nil {
			slog.Warn("auth: user not in aggregate", "user_id", userID)
			_ = a.sessionManager.Destroy(r.Context())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if user.Status != "active" {
			slog.Warn("auth: account not active", "user_id", userID, "status", user.Status)
			_ = a.sessionManager.Destroy(r.Context())
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		slog.Debug("auth: passed", "user_id", userID)
		ctx := context.WithValue(r.Context(), ctxUser, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
