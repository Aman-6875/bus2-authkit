package authkit_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	authkit "github.com/Aman-6875/bus2-authkit"
)

var _ authkit.PermissionResolver = (*authkit.LivePermissions)(nil)

type fakeRoleFetcher struct {
	mu        sync.Mutex
	calls     int
	responses map[string][]string
	err       error
}

func (f *fakeRoleFetcher) Permissions(ctx context.Context, role string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.responses[role], nil
}

func (f *fakeRoleFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeRoleFetcher) setResponse(role string, perms []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[role] = perms
}

func TestLivePermissions_CachesAfterFirstFetch(t *testing.T) {
	fetcher := &fakeRoleFetcher{responses: map[string][]string{"operator_admin": {"refund_ticket"}}}
	source := newFakeEventSource()

	lp, err := authkit.NewLivePermissions(context.Background(), fetcher, source)
	if err != nil {
		t.Fatalf("NewLivePermissions: %v", err)
	}

	first := lp.Permissions("operator_admin")
	if len(first) != 1 || first[0] != "refund_ticket" {
		t.Fatalf("Permissions() = %v, want [refund_ticket]", first)
	}

	lp.Permissions("operator_admin") // should hit the cache, not the fetcher

	if got := fetcher.callCount(); got != 1 {
		t.Fatalf("fetcher called %d times, want 1 (second call should be served from cache)", got)
	}
}

func TestLivePermissions_InvalidatesOnRoleChangedEvent(t *testing.T) {
	fetcher := &fakeRoleFetcher{responses: map[string][]string{"operator_admin": {"refund_ticket"}}}
	source := newFakeEventSource()

	lp, err := authkit.NewLivePermissions(context.Background(), fetcher, source)
	if err != nil {
		t.Fatalf("NewLivePermissions: %v", err)
	}

	if got := lp.Permissions("operator_admin"); len(got) != 1 || got[0] != "refund_ticket" {
		t.Fatalf("Permissions() = %v, want [refund_ticket]", got)
	}

	// authz's admin edits the role: refund_ticket is replaced by view_reports.
	fetcher.setResponse("operator_admin", []string{"view_reports"})

	source.events <- authkit.PermissionsChangedEvent{
		Type:      authkit.EventRoleChanged,
		Subject:   "operator_admin",
		ChangedAt: time.Now(),
	}

	waitUntil(t, time.Second, func() bool {
		got := lp.Permissions("operator_admin")
		return len(got) == 1 && got[0] == "view_reports"
	})
}

func TestLivePermissions_FetchErrorDeniesByDefault(t *testing.T) {
	fetcher := &fakeRoleFetcher{err: errors.New("authz unreachable")}
	source := newFakeEventSource()

	lp, err := authkit.NewLivePermissions(context.Background(), fetcher, source)
	if err != nil {
		t.Fatalf("NewLivePermissions: %v", err)
	}

	if got := lp.Permissions("operator_admin"); len(got) != 0 {
		t.Fatalf("Permissions() = %v on fetch error, want empty (fail closed, not fail open)", got)
	}
}
