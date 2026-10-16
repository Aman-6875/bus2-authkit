package authkit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// FreshnessChecker detects that a user's roles, or a role's own permission
// set, changed after a given token was issued. A JWT can't know this by
// itself — it is trusted at face value until it expires — so this closes
// that gap by watching a stream of change events and comparing each
// token's issued-at time against the most recent change for its subject
// and roles.
type FreshnessChecker struct {
	maxAge time.Duration

	mu            sync.Mutex
	userChangedAt map[string]time.Time
	roleChangedAt map[string]time.Time
}

// NewFreshnessChecker subscribes to source and consumes events in the
// background until ctx is done.
//
// maxAge bounds both how long an entry is kept and, implicitly, how stale a
// token can be before it would be rejected for an unrelated reason anyway:
// it should be at least the longest expiry this service's tokens ever
// carry. Entries older than maxAge are swept, since no still-valid token
// could have been issued before them.
func NewFreshnessChecker(ctx context.Context, source EventSource, maxAge time.Duration) (*FreshnessChecker, error) {
	events, err := source.Subscribe(ctx)
	if err != nil {
		return nil, fmt.Errorf("authkit.NewFreshnessChecker: %w", err)
	}

	fc := &FreshnessChecker{
		maxAge:        maxAge,
		userChangedAt: make(map[string]time.Time),
		roleChangedAt: make(map[string]time.Time),
	}

	go fc.consume(ctx, events)
	go fc.janitor(ctx)

	return fc, nil
}

func (fc *FreshnessChecker) consume(ctx context.Context, events <-chan PermissionsChangedEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-events:
			if !ok {
				return
			}
			fc.record(e)
		}
	}
}

func (fc *FreshnessChecker) record(e PermissionsChangedEvent) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	switch e.Type {
	case EventUserChanged:
		fc.userChangedAt[e.Subject] = e.ChangedAt
	case EventRoleChanged:
		fc.roleChangedAt[e.Subject] = e.ChangedAt
	}
}

func (fc *FreshnessChecker) janitor(ctx context.Context) {
	ticker := time.NewTicker(fc.maxAge)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fc.sweep()
		}
	}
}

func (fc *FreshnessChecker) sweep() {
	cutoff := time.Now().Add(-fc.maxAge)

	fc.mu.Lock()
	defer fc.mu.Unlock()

	for subject, changedAt := range fc.userChangedAt {
		if changedAt.Before(cutoff) {
			delete(fc.userChangedAt, subject)
		}
	}
	for role, changedAt := range fc.roleChangedAt {
		if changedAt.Before(cutoff) {
			delete(fc.roleChangedAt, role)
		}
	}
}

// IsStale reports whether claims were issued before a later change to the
// claims' own subject or to any role the claims carry.
func (fc *FreshnessChecker) IsStale(claims Claims) bool {
	if claims.IssuedAt == nil {
		return false // nothing to compare against
	}
	issuedAt := claims.IssuedAt.Time

	fc.mu.Lock()
	defer fc.mu.Unlock()

	if changedAt, ok := fc.userChangedAt[claims.Subject]; ok && issuedAt.Before(changedAt) {
		return true
	}
	for _, role := range claims.Roles {
		if changedAt, ok := fc.roleChangedAt[role]; ok && issuedAt.Before(changedAt) {
			return true
		}
	}
	return false
}
