// Package kafka provides a Redpanda/Kafka-backed authkit.EventSource and a
// matching Publisher, sharing one JSON wire format so authz (the publisher)
// and every consuming service (via authkit) agree on the message shape
// without either side hand-rolling it independently.
package kafka

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"

	authkit "github.com/Aman-6875/bus2-authkit"
)

// Config connects to a Kafka/Redpanda broker. TLS and SASLMechanism are
// both optional and nil by default, so the same code connects to an
// unauthenticated local Redpanda (nothing set) or an authenticated
// production cluster (both set) — the caller decides which, authkit never
// assumes one or the other.
type Config struct {
	Brokers []string
	Topic   string

	// TLS enables TLS for the broker connection. Leave nil for a plain,
	// unencrypted connection (e.g. local dev).
	TLS *tls.Config

	// SASLMechanism authenticates the connection when set — e.g.
	// plain.Mechanism{Username, Password} or a scram.Mechanism from
	// github.com/segmentio/kafka-go/sasl. Leave nil for brokers that don't
	// require authentication.
	SASLMechanism sasl.Mechanism
}

const dialTimeout = 10 * time.Second

// eventName is the "event" field this package reads and writes. A shared
// topic may carry other event names (see login-service's idp.events
// convention) — a message with a different name is ignored, not treated as
// malformed.
const eventName = "PERMISSIONS_CHANGED"

// envelope matches the event-publishing convention already in use (see
// login-service/ui/app/lib/events.ts): one envelope shape, a "data" payload
// specific to each event name.
type envelope struct {
	ID         string          `json:"id"`
	Event      string          `json:"event"`
	OccurredAt time.Time       `json:"occurred_at"`
	Source     string          `json:"source"`
	Data       json.RawMessage `json:"data"`
}

type eventData struct {
	Type    string `json:"type"`
	Subject string `json:"subject"`
}

func newEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func marshalEnvelope(source string, event authkit.PermissionsChangedEvent) ([]byte, error) {
	data, err := json.Marshal(eventData{Type: string(event.Type), Subject: event.Subject})
	if err != nil {
		return nil, fmt.Errorf("authkit/kafka: marshal event data: %w", err)
	}

	env := envelope{
		ID:         newEventID(),
		Event:      eventName,
		OccurredAt: event.ChangedAt,
		Source:     source,
		Data:       data,
	}

	b, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("authkit/kafka: marshal envelope: %w", err)
	}
	return b, nil
}

// parseEnvelope returns ok=false (no error) for a message this package
// doesn't own (a different "event" name sharing the topic) or one that
// fails to parse — callers should skip it, not fail the whole stream over
// one unrelated or malformed message.
func parseEnvelope(raw []byte) (event authkit.PermissionsChangedEvent, ok bool) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return authkit.PermissionsChangedEvent{}, false
	}
	if env.Event != eventName {
		return authkit.PermissionsChangedEvent{}, false
	}

	var data eventData
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return authkit.PermissionsChangedEvent{}, false
	}

	return authkit.PermissionsChangedEvent{
		Type:      authkit.EventType(data.Type),
		Subject:   data.Subject,
		ChangedAt: env.OccurredAt,
	}, true
}

// Publisher publishes PermissionsChangedEvents to a topic. source identifies
// the publishing service in the shared envelope (e.g. "authz").
type Publisher struct {
	writer *kafkago.Writer
	source string
}

// NewPublisher returns a Publisher for cfg.Topic on cfg.Brokers. source
// identifies the publishing service in the shared envelope (e.g. "authz").
func NewPublisher(cfg Config, source string) *Publisher {
	return &Publisher{
		writer: &kafkago.Writer{
			Addr:     kafkago.TCP(cfg.Brokers...),
			Topic:    cfg.Topic,
			Balancer: &kafkago.LeastBytes{},
			Transport: &kafkago.Transport{
				TLS:  cfg.TLS,
				SASL: cfg.SASLMechanism,
			},
		},
		source: source,
	}
}

// Publish sends event, keyed by its Subject so a partitioned topic keeps
// every change for the same user/role in order.
func (p *Publisher) Publish(ctx context.Context, event authkit.PermissionsChangedEvent) error {
	value, err := marshalEnvelope(p.source, event)
	if err != nil {
		return err
	}
	return p.writer.WriteMessages(ctx, kafkago.Message{
		Key:   []byte(event.Subject),
		Value: value,
	})
}

// Close releases the Publisher's connection.
func (p *Publisher) Close() error {
	return p.writer.Close()
}

type eventSource struct {
	reader *kafkago.Reader
}

// NewEventSource returns an authkit.EventSource backed by topic on brokers.
//
// Deliberately no consumer group: every service instance must see every
// event independently (each keeps its own local cache), rather than having
// events load-balanced across instances the way a work queue would be.
// This also means topic must have exactly one partition — Subscribe only
// ever reads partition 0.
//
// Reading starts from the earliest offset the broker still retains, not
// "latest" — a freshly started instance must still learn about a change
// that happened moments before it started. Set this topic's retention to
// roughly the longest-lived FreshnessChecker/LivePermissions maxAge in use,
// so that backfill is bounded to exactly the window that still matters.
func NewEventSource(cfg Config) authkit.EventSource {
	return &eventSource{
		reader: kafkago.NewReader(kafkago.ReaderConfig{
			Brokers:     cfg.Brokers,
			Topic:       cfg.Topic,
			Partition:   0,
			StartOffset: kafkago.FirstOffset,
			Dialer: &kafkago.Dialer{
				Timeout:       dialTimeout,
				TLS:           cfg.TLS,
				SASLMechanism: cfg.SASLMechanism,
			},
		}),
	}
}

// Subscribe implements authkit.EventSource.
func (s *eventSource) Subscribe(ctx context.Context) (<-chan authkit.PermissionsChangedEvent, error) {
	out := make(chan authkit.PermissionsChangedEvent)

	go func() {
		defer close(out)
		defer s.reader.Close()

		for {
			msg, err := s.reader.ReadMessage(ctx)
			if err != nil {
				return // ctx cancelled, or the reader failed permanently
			}

			event, ok := parseEnvelope(msg.Value)
			if !ok {
				continue
			}

			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, nil
}
