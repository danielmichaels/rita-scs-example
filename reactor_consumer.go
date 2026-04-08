package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/synadia-labs/rita"
	"github.com/synadia-labs/rita/types"
)

// Rita writes these headers on every event message it appends.
// Hardcoded here because rita keeps them as unexported constants in
// eventstore.go.
const (
	headerEntity  = "Rita-Entity"
	headerType    = "Rita-Type"
	headerTime    = "Rita-Time"
	headerMetaPfx = "Rita-Meta-"
)

// EventHandler is the side-effect counterpart to a projection evolver.
// In Rita, Evolve(*rita.Event) usually means "apply this event to state".
type EventHandler interface {
	HandleEvent(context.Context, *rita.Event) error
}

type Reactor struct {
	Handler EventHandler
	Config  SideEffectConsumerConfig
}

// SideEffectConsumerConfig defines one delivery pipeline.
//
// Each pipeline gets its own durable name, delivery policy, and broker-side
// subject filters.
type SideEffectConsumerConfig struct {
	DurableName    string
	FilterSubjects []string
	DeliverPolicy  jetstream.DeliverPolicy
	MaxAckPending  int
}

// startSideEffectConsumer provisions and runs one JetStream durable
// consumer for one side-effect pipeline.
func startSideEffectConsumer(
	ctx context.Context,
	js jetstream.JetStream,
	registry *types.Registry,
	streamName string,
	cfg SideEffectConsumerConfig,
	handler EventHandler,
) (jetstream.ConsumeContext, error) {
	if cfg.DurableName == "" {
		return nil, fmt.Errorf("missing durable name")
	}
	if cfg.MaxAckPending == 0 {
		cfg.MaxAckPending = 1
	}

	cons, err := js.CreateOrUpdateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		Durable:        cfg.DurableName,
		FilterSubjects: cfg.FilterSubjects,
		DeliverPolicy:  cfg.DeliverPolicy,
		AckPolicy:      jetstream.AckExplicitPolicy,
		MaxAckPending:  cfg.MaxAckPending,
	})
	if err != nil {
		return nil, fmt.Errorf("create consumer %q: %w", cfg.DurableName, err)
	}

	return cons.Consume(func(msg jetstream.Msg) {
		evt, err := unpackEvent(msg, registry)
		if err != nil {
			slog.Error("reactor: unpack failed", "durable", cfg.DurableName, "error", err)
			_ = msg.Term() // poison message — don't redeliver
			return
		}
		if err := handler.HandleEvent(ctx, evt); err != nil {
			slog.Error("reactor: handler failed", "durable", cfg.DurableName, "type", evt.Type, "error", err)
			_ = msg.Nak() // transient — broker redelivers
			return
		}
		if err := msg.Ack(); err != nil {
			slog.Error("reactor: ack failed", "durable", cfg.DurableName, "error", err)
		}
	})
}

// unpackEvent reconstructs a rita.Event from a raw JetStream message using
// the same registry rita uses internally.
func unpackEvent(msg jetstream.Msg, registry *types.Registry) (*rita.Event, error) {
	headers := msg.Headers()
	eventType := headers.Get(headerType)
	if eventType == "" {
		return nil, fmt.Errorf("missing header: %s", headerType)
	}

	data, err := registry.UnmarshalType(msg.Data(), eventType)
	if err != nil {
		return nil, fmt.Errorf("unmarshal %s: %w", eventType, err)
	}

	evtTime, err := time.Parse(time.RFC3339Nano, headers.Get(headerTime))
	if err != nil {
		return nil, fmt.Errorf("parse %s header: %w", headerTime, err)
	}

	var meta map[string]string
	for h := range headers {
		if strings.HasPrefix(h, headerMetaPfx) {
			if meta == nil {
				meta = make(map[string]string)
			}
			meta[h[len(headerMetaPfx):]] = headers.Get(h)
		}
	}

	return &rita.Event{
		ID:     headers.Get(nats.MsgIdHdr),
		Entity: headers.Get(headerEntity),
		Type:   eventType,
		Time:   evtTime,
		Data:   data,
		Meta:   meta,
	}, nil
}

func deliveryKey(evt *rita.Event) string {
	if evt.ID != "" {
		return evt.ID
	}
	return fmt.Sprintf("%s:%s:%s", evt.Type, evt.Entity, evt.Time.UTC().Format(time.RFC3339Nano))
}
