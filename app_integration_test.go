package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/synadia-labs/rita"
)

type testEnv struct {
	ctx         context.Context
	cancel      context.CancelFunc
	ns          *natsserver.Server
	nc          *nats.Conn
	js          jetstream.JetStream
	es          *rita.EventStore
	emailIndex  *KVEmailIndex
	credentials *KVCredentialStore
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	opts := &natsserver.Options{
		JetStream: true,
		StoreDir:  t.TempDir(),
		Port:      -1,
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}

	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}

	reg, err := newRegistry()
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := rita.New(nc, rita.WithRegistry(reg))
	if err != nil {
		t.Fatal(err)
	}

	es, err := mgr.CreateEventStore(ctx, rita.EventStoreConfig{Name: "auth"})
	if err != nil {
		t.Fatal(err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}

	emailIndexKV, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "email_index"})
	if err != nil {
		t.Fatal(err)
	}
	credentialKV, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: "credentials"})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		cancel()
		nc.Close()
		ns.Shutdown()
	})

	return &testEnv{
		ctx:         ctx,
		cancel:      cancel,
		ns:          ns,
		nc:          nc,
		js:          js,
		es:          es,
		emailIndex:  &KVEmailIndex{kv: emailIndexKV},
		credentials: &KVCredentialStore{kv: credentialKV},
	}
}

func (e *testEnv) newApp(store scs.Store) *App {
	sessionManager := scs.New()
	if store == nil {
		store = memstore.NewWithCleanupInterval(0)
	}
	sessionManager.Store = store
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode

	return &App{
		es:             e.es,
		model:          rita.NewModel(NewAuthState()),
		emailIndex:     e.emailIndex,
		credentials:    e.credentials,
		sessionManager: sessionManager,
	}
}

func appHandler(app *App) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", app.handleRegister)
	mux.HandleFunc("POST /login", app.handleLogin)
	mux.Handle("GET /me/logins", app.requireAuth(http.HandlerFunc(app.handleMyLogins)))
	return app.sessionManager.LoadAndSave(mux)
}

func performFormRequest(t *testing.T, handler http.Handler, method, target string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, bytes.NewBufferString(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

type eventCollector struct {
	events []*rita.Event
}

func (c *eventCollector) Evolve(evt *rita.Event) error {
	c.events = append(c.events, evt)
	return nil
}

func (e *testEnv) allEvents(t *testing.T) []*rita.Event {
	t.Helper()

	collector := &eventCollector{}
	if _, err := e.es.Evolve(e.ctx, collector); err != nil {
		t.Fatal(err)
	}
	return collector.events
}

type failingSessionStore struct {
	scs.Store
	failCommits int
}

func (s *failingSessionStore) Commit(token string, b []byte, expiry time.Time) error {
	if s.failCommits > 0 {
		s.failCommits--
		return context.DeadlineExceeded
	}
	return s.Store.Commit(token, b, expiry)
}

func TestHandleRegister_DuplicateAcrossIndependentModelsReturnsConflict(t *testing.T) {
	env := newTestEnv(t)
	app1 := env.newApp(nil)
	app2 := env.newApp(nil)

	values := url.Values{
		"email":    {"Dan@example.com"},
		"password": {"secret"},
	}

	resp1 := performFormRequest(t, appHandler(app1), http.MethodPost, "/register", values)
	if resp1.Code != http.StatusCreated {
		t.Fatalf("expected first registration to succeed, got %d", resp1.Code)
	}

	resp2 := performFormRequest(t, appHandler(app2), http.MethodPost, "/register", values)
	if resp2.Code != http.StatusConflict {
		t.Fatalf("expected second registration to conflict, got %d", resp2.Code)
	}
}

func TestHandleLogin_DoesNotRecordSuccessWhenSessionCommitFails(t *testing.T) {
	env := newTestEnv(t)
	app := env.newApp(&failingSessionStore{Store: memstore.NewWithCleanupInterval(0), failCommits: 1})
	handler := appHandler(app)

	registerResp := performFormRequest(t, handler, http.MethodPost, "/register", url.Values{
		"email":    {"dan@example.com"},
		"password": {"secret"},
	})
	if registerResp.Code != http.StatusCreated {
		t.Fatalf("expected registration to succeed, got %d", registerResp.Code)
	}

	loginResp := performFormRequest(t, handler, http.MethodPost, "/login", url.Values{
		"email":    {"dan@example.com"},
		"password": {"secret"},
	})
	if loginResp.Code != http.StatusInternalServerError {
		t.Fatalf("expected login to fail when session commit fails, got %d", loginResp.Code)
	}

	events := env.allEvents(t)
	if len(events) != 1 {
		t.Fatalf("expected only registration event, got %d events", len(events))
	}
	if events[0].Type != "UserRegistered" {
		t.Fatalf("expected only UserRegistered event, got %s", events[0].Type)
	}
}

func TestHandleMyLogins_ReturnsProjectedLoginHistory(t *testing.T) {
	env := newTestEnv(t)
	app := env.newApp(nil)
	handler := appHandler(app)

	creds := url.Values{
		"email":    {"dan@example.com"},
		"password": {"secret"},
	}
	if resp := performFormRequest(t, handler, http.MethodPost, "/register", creds); resp.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.Code)
	}

	wrong := url.Values{
		"email":    {"dan@example.com"},
		"password": {"nope"},
	}
	if resp := performFormRequest(t, handler, http.MethodPost, "/login", wrong); resp.Code != http.StatusUnauthorized {
		t.Fatalf("login (wrong): expected 401, got %d", resp.Code)
	}

	loginResp := performFormRequest(t, handler, http.MethodPost, "/login", creds)
	if loginResp.Code != http.StatusSeeOther {
		t.Fatalf("login: expected 303, got %d", loginResp.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/me/logins", nil)
	for _, c := range loginResp.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("me/logins: expected 200, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("me/logins: expected Content-Type application/json, got %q", ct)
	}

	var got []LoginAttempt
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("me/logins: decode body: %v\nbody: %s", err, rr.Body.String())
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 login attempts (one failed, one successful), got %d: %+v", len(got), got)
	}
	if got[0].Success {
		t.Fatalf("expected first attempt to be the failed one (Success=false), got %+v", got[0])
	}
	if !got[1].Success {
		t.Fatalf("expected second attempt to be the successful one (Success=true), got %+v", got[1])
	}
}

func TestHandleMyLogins_EmptyHistoryReturnsEmptyArrayNotNull(t *testing.T) {
	env := newTestEnv(t)
	app := env.newApp(nil)
	handler := appHandler(app)

	creds := url.Values{
		"email":    {"fresh@example.com"},
		"password": {"secret"},
	}
	if resp := performFormRequest(t, handler, http.MethodPost, "/register", creds); resp.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d", resp.Code)
	}

	loginResp := performFormRequest(t, handler, http.MethodPost, "/login", creds)
	if loginResp.Code != http.StatusSeeOther {
		t.Fatalf("login: expected 303, got %d", loginResp.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/me/logins", nil)
	for _, c := range loginResp.Result().Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("me/logins: expected 200, got %d", rr.Code)
	}
	if body := bytes.TrimSpace(rr.Body.Bytes()); bytes.Equal(body, []byte("null")) {
		t.Fatalf("me/logins: returned JSON null instead of an array — accessor must return non-nil slice")
	}
}

func TestHandleRegister_EventPayloadDoesNotContainPasswordHash(t *testing.T) {
	env := newTestEnv(t)
	app := env.newApp(nil)

	resp := performFormRequest(t, appHandler(app), http.MethodPost, "/register", url.Values{
		"email":    {"dan@example.com"},
		"password": {"secret"},
	})
	if resp.Code != http.StatusCreated {
		t.Fatalf("expected registration to succeed, got %d", resp.Code)
	}

	stream, err := env.js.Stream(env.ctx, "ES_auth")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := stream.GetMsg(env.ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(msg.Data, []byte("password_hash")) {
		t.Fatalf("expected event payload to exclude password hash, got %s", string(msg.Data))
	}
}
