package authkit_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	authkit "github.com/Aman-6875/bus2-authkit"
)

type fakeEventSource struct {
	events chan authkit.PermissionsChangedEvent
}

func newFakeEventSource() *fakeEventSource {
	return &fakeEventSource{events: make(chan authkit.PermissionsChangedEvent, 8)}
}

func (f *fakeEventSource) Subscribe(ctx context.Context) (<-chan authkit.PermissionsChangedEvent, error) {
	return f.events, nil
}

// waitUntil polls cond until it's true or timeout elapses, avoiding a fixed
// sleep racing the FreshnessChecker's background consumer goroutine.
func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func TestFreshnessChecker_UserChanged(t *testing.T) {
	source := newFakeEventSource()
	fc, err := authkit.NewFreshnessChecker(context.Background(), source, time.Hour)
	if err != nil {
		t.Fatalf("NewFreshnessChecker: %v", err)
	}

	issuedAt := time.Now().Add(-time.Minute)
	claims := authkit.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			IssuedAt:  jwt.NewNumericDate(issuedAt),
		},
	}

	if fc.IsStale(claims) {
		t.Fatalf("IsStale() = true before any event, want false")
	}

	source.events <- authkit.PermissionsChangedEvent{
		Type:      authkit.EventUserChanged,
		Subject:   "user-1",
		ChangedAt: issuedAt.Add(time.Second), // changed after the token was issued
	}

	waitUntil(t, time.Second, func() bool { return fc.IsStale(claims) })
}

func TestFreshnessChecker_RoleChanged(t *testing.T) {
	source := newFakeEventSource()
	fc, err := authkit.NewFreshnessChecker(context.Background(), source, time.Hour)
	if err != nil {
		t.Fatalf("NewFreshnessChecker: %v", err)
	}

	issuedAt := time.Now().Add(-time.Minute)
	claims := authkit.Claims{
		Roles: []string{"operator_admin"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "user-1",
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
	}

	source.events <- authkit.PermissionsChangedEvent{
		Type:      authkit.EventRoleChanged,
		Subject:   "operator_admin",
		ChangedAt: issuedAt.Add(time.Second),
	}

	waitUntil(t, time.Second, func() bool { return fc.IsStale(claims) })
}

func TestFreshnessChecker_ChangeBeforeIssuedAtIsNotStale(t *testing.T) {
	source := newFakeEventSource()
	fc, err := authkit.NewFreshnessChecker(context.Background(), source, time.Hour)
	if err != nil {
		t.Fatalf("NewFreshnessChecker: %v", err)
	}

	changedAt := time.Now().Add(-time.Hour)
	issuedAt := changedAt.Add(time.Minute) // token issued AFTER the change — still fresh

	claims := authkit.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "user-1",
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
	}

	source.events <- authkit.PermissionsChangedEvent{
		Type:      authkit.EventUserChanged,
		Subject:   "user-1",
		ChangedAt: changedAt,
	}

	// Give the consumer goroutine a chance to process the event, then
	// confirm it correctly does NOT mark this token stale.
	time.Sleep(50 * time.Millisecond)
	if fc.IsStale(claims) {
		t.Fatalf("IsStale() = true for a token issued after the recorded change, want false")
	}
}

func TestFreshnessChecker_NoIssuedAtNeverStale(t *testing.T) {
	source := newFakeEventSource()
	fc, err := authkit.NewFreshnessChecker(context.Background(), source, time.Hour)
	if err != nil {
		t.Fatalf("NewFreshnessChecker: %v", err)
	}

	claims := authkit.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user-1"}}

	source.events <- authkit.PermissionsChangedEvent{
		Type:      authkit.EventUserChanged,
		Subject:   "user-1",
		ChangedAt: time.Now(),
	}
	time.Sleep(50 * time.Millisecond)

	if fc.IsStale(claims) {
		t.Fatalf("IsStale() = true for claims with no IssuedAt, want false")
	}
}
