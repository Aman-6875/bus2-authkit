package authkit

import (
	"context"
	"time"
)

// EventType distinguishes a single user's role change from a role
// definition's own permission set changing (which affects every user
// holding that role).
type EventType string

const (
	EventUserChanged EventType = "user"
	EventRoleChanged EventType = "role"
)

// PermissionsChangedEvent signals that something a token's claims depend on
// changed after the token may already have been issued: either Subject is
// a user_id whose roles/memberships changed, or Subject is a role name
// whose own permission set changed.
type PermissionsChangedEvent struct {
	Type      EventType
	Subject   string
	ChangedAt time.Time
}

// EventSource delivers PermissionsChangedEvents. authkit depends on this
// interface rather than any specific message broker — a Kafka/Redpanda
// backed implementation lives in a separate subpackage so services that
// don't need freshness checking never pull in that dependency.
type EventSource interface {
	// Subscribe returns a channel of events, open until ctx is done or the
	// source permanently fails.
	Subscribe(ctx context.Context) (<-chan PermissionsChangedEvent, error)
}
