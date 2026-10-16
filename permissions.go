package authkit

import (
	"context"
	"fmt"
	"sync"
)

// RoleFetcher fetches a role's current permissions from whichever service
// owns that data (authz). LivePermissions depends on this interface rather
// than a concrete HTTP client so it can be tested without a real service,
// and so the transport can change without touching the cache logic.
type RoleFetcher interface {
	Permissions(ctx context.Context, role string) ([]string, error)
}

// LivePermissions is a PermissionResolver backed by a cache that's
// populated lazily from fetcher and invalidated (not repopulated) whenever
// an EventRoleChanged event arrives for a cached role — the next read after
// that fetches fresh data. authz remains the single source of truth; this
// cache only avoids a network round trip on every Can() check.
type LivePermissions struct {
	ctx     context.Context
	fetcher RoleFetcher

	mu    sync.Mutex
	cache map[string][]string
}

// NewLivePermissions subscribes to source and consumes role-changed events
// in the background until ctx is done.
func NewLivePermissions(ctx context.Context, fetcher RoleFetcher, source EventSource) (*LivePermissions, error) {
	events, err := source.Subscribe(ctx)
	if err != nil {
		return nil, fmt.Errorf("authkit.NewLivePermissions: %w", err)
	}

	lp := &LivePermissions{
		ctx:     ctx,
		fetcher: fetcher,
		cache:   make(map[string][]string),
	}

	go lp.consume(ctx, events)

	return lp, nil
}

func (lp *LivePermissions) consume(ctx context.Context, events <-chan PermissionsChangedEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-events:
			if !ok {
				return
			}
			if e.Type == EventRoleChanged {
				lp.invalidate(e.Subject)
			}
		}
	}
}

func (lp *LivePermissions) invalidate(role string) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	delete(lp.cache, role)
}

// Permissions implements PermissionResolver. On a fetch failure it returns
// no permissions rather than propagating the error — Can() has no way to
// surface an error, and denying access is the safe failure mode here,
// not granting it.
func (lp *LivePermissions) Permissions(role string) []string {
	lp.mu.Lock()
	if cached, ok := lp.cache[role]; ok {
		lp.mu.Unlock()
		return cached
	}
	lp.mu.Unlock()

	perms, err := lp.fetcher.Permissions(lp.ctx, role)
	if err != nil {
		return nil
	}

	lp.mu.Lock()
	lp.cache[role] = perms
	lp.mu.Unlock()

	return perms
}
