package main

import (
	"context"
	"log/slog"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/synadia-labs/rita"
)

// LoginReactor watches the event stream for login-related events
// and triggers side effects (suspicious activity alerts, audit trail, etc).
type LoginReactor struct {
	Notifier Notifier
}

func NewLoginReactor(n Notifier) Reactor {
	return Reactor{
		Handler: &LoginReactor{Notifier: n},
		Config: SideEffectConsumerConfig{
			DurableName: "reactor_login",
			FilterSubjects: []string{
				"$ES.auth.user.*.UserLoginSucceeded",
				"$ES.auth.loginattempt.*.UserLoginFailed",
			},
			DeliverPolicy: jetstream.DeliverNewPolicy,
			MaxAckPending: 1,
		},
	}
}

// HandleEvent reacts to stored login events with side effects.
// Unlike a Rita projection evolver, it does not rebuild state.
func (r *LoginReactor) HandleEvent(ctx context.Context, evt *rita.Event) error {
	switch e := evt.Data.(type) {
	case *UserLoginSucceeded:
		if err := r.Notifier.Send(ctx, deliveryKey(evt), e.Email, "login succeeded"); err != nil {
			return err
		}
		slog.Info("reactor.login: successful login recorded",
			"user_id", e.UserID,
			"email", e.Email,
			"ip", e.IP,
			"at", evt.Time,
		)
	case *UserLoginFailed:
		if err := r.Notifier.Send(ctx, deliveryKey(evt), e.Email, "login failed"); err != nil {
			return err
		}
		slog.Warn("reactor.login: failed login recorded",
			"email", e.Email,
			"ip", e.IP,
			"reason", e.Reason,
			"at", evt.Time,
		)
	}
	return nil
}
