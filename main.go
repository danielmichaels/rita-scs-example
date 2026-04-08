package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/synadia-labs/rita"

	natsserver "github.com/nats-io/nats-server/v2/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("main", "error", err)
		os.Exit(1)
	}
}
func run() error {
	port := flag.Int("port", 9998, "HTTP listen port")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts, err := natsserver.ProcessConfigFile("nats.conf")
	if err != nil {
		slog.Error("nats config", "error", err)
		return err
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		slog.Error("nats server", "error", err)
		return err
	}
	ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		slog.Error("nats server not ready")
		return fmt.Errorf("nats server not ready")
	}
	defer ns.Shutdown()

	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		slog.Error("nats connect", "error", err)
		return err
	}
	defer nc.Close()

	reg, err := newRegistry()
	if err != nil {
		slog.Error("rita registry", "error", err)
		return err
	}
	mgr, err := rita.New(nc, rita.WithRegistry(reg))
	if err != nil {
		slog.Error("rita manager", "error", err)
		return err
	}

	esName := "auth"
	es, err := mgr.GetEventStore(ctx, esName)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		es, err = mgr.CreateEventStore(ctx, rita.EventStoreConfig{
			Name:        esName,
			Description: "auth events",
		})
	}
	if err != nil {
		slog.Error("event store init", "error", err)
		return err
	}

	authState := NewAuthState()
	model := rita.NewModel(authState)

	watcher, err := es.Watch(ctx, model)
	if err != nil {
		slog.Error("watch event store", "error", err)
		return err
	}
	defer watcher.Stop()

	js, err := jetstream.New(nc)
	if err != nil {
		slog.Error("jetstream", "error", err)
		return err
	}

	// Reactors/ side-effects
	notifier := NewNotifier(os.Getenv("SMTP_HOST"))
	streamName := fmt.Sprintf("ES_%s", esName)

	reactors := []Reactor{
		NewRegistrationReactor(notifier),
		NewLoginReactor(notifier),
	}

	for _, r := range reactors {
		cc, err := startSideEffectConsumer(ctx, js, reg, streamName, r.Config, r.Handler)
		if err != nil {
			slog.Error("reactor consumer", "error", err)
			return err
		}
		defer cc.Stop()
	}

	sessionKV, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "sessions",
		TTL:    24 * time.Hour,
	})
	if err != nil {
		slog.Error("sessions kv", "error", err)
		return err
	}

	emailIndexKV, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "email_index",
	})
	if err != nil {
		slog.Error("email index kv", "error", err)
		return err
	}

	credentialKV, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: "credentials",
	})
	if err != nil {
		slog.Error("credentials kv", "error", err)
		return err
	}

	sessionManager := scs.New()
	sessionManager.Store = &NATSStore{kv: sessionKV}
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode

	app := &App{
		es:             es,
		model:          model,
		emailIndex:     &KVEmailIndex{kv: emailIndexKV},
		credentials:    &KVCredentialStore{kv: credentialKV},
		sessionManager: sessionManager,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /login", app.handleLoginPage)
	mux.HandleFunc("POST /register", app.handleRegister)
	mux.HandleFunc("POST /login", app.handleLogin)
	mux.HandleFunc("POST /logout", app.handleLogout)
	mux.Handle("GET /dashboard", app.requireAuth(http.HandlerFunc(app.handleDashboard)))
	mux.Handle("GET /me/logins", app.requireAuth(http.HandlerFunc(app.handleMyLogins)))

	addr := fmt.Sprintf(":%d", *port)
	srv := &http.Server{
		Addr:    addr,
		Handler: requestLogger(sessionManager.LoadAndSave(mux)),
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutdown: signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown: http", "error", err)
		}
	}()

	slog.Info("listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("http server", "error", err)
		return err
	}

	slog.Info("shutdown: complete")
	return nil
}
