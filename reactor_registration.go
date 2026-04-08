package main

import (
	"context"
	"log/slog"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/synadia-labs/rita"
)

// RegistrationReactor watches the event stream for registration events
// and triggers side effects (welcome email, audit log, etc).
type RegistrationReactor struct {
	Notifier Notifier
}

func NewRegistrationReactor(n Notifier) Reactor {
	return Reactor{
		Handler: &RegistrationReactor{Notifier: n},
		Config: SideEffectConsumerConfig{
			DurableName:    "reactor_registration",
			FilterSubjects: []string{"$ES.auth.user.*.UserRegistered"},
			DeliverPolicy:  jetstream.DeliverNewPolicy,
			MaxAckPending:  1,
		},
	}
}

// HandleEvent reacts to stored registration events with side effects.
// Unlike a Rita projection evolver, it does not rebuild state.
func (r *RegistrationReactor) HandleEvent(ctx context.Context, evt *rita.Event) error {
	switch e := evt.Data.(type) {
	case *UserRegistered:
		if err := r.Notifier.Send(ctx, deliveryKey(evt), e.Email, "welcome to the platform"); err != nil {
			return err
		}
		slog.Info("reactor.registration: welcome email sent",
			"user_id", e.UserID,
			"email", e.Email,
			"registered_at", evt.Time,
		)
	}
	return nil
}
