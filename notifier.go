package main

import (
	"context"
	"log/slog"
)

type Notifier interface {
	Send(ctx context.Context, deliveryKey, to, msg string) error
}

// NewNotifier returns an EmailNotifier if smtpHost is configured,
// otherwise falls back to a LogNotifier.
func NewNotifier(smtpHost string) Notifier {
	if smtpHost != "" {
		return &EmailNotifier{Host: smtpHost}
	}
	return &LogNotifier{}
}

type LogNotifier struct{}

func (n *LogNotifier) Send(_ context.Context, deliveryKey, to, msg string) error {
	slog.Info("NOTIFIER: noop", "to", to, "msg", msg, "delivery_key", deliveryKey)
	return nil
}

type EmailNotifier struct {
	Host string
}

func (n *EmailNotifier) Send(_ context.Context, deliveryKey, to, msg string) error {
	slog.Info("NOTIFIER: sending email", "to", to, "msg", msg, "smtp_host", n.Host, "delivery_key", deliveryKey)
	return nil
}
