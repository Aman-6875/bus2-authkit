package kafka

import (
	"testing"
	"time"

	authkit "github.com/Aman-6875/bus2-authkit"
)

func TestMarshalParseEnvelope_RoundTrip(t *testing.T) {
	want := authkit.PermissionsChangedEvent{
		Type:      authkit.EventUserChanged,
		Subject:   "user-42",
		ChangedAt: time.Now().UTC().Truncate(time.Second), // JSON round-trips to second precision
	}

	raw, err := marshalEnvelope("authz", want)
	if err != nil {
		t.Fatalf("marshalEnvelope: %v", err)
	}

	got, ok := parseEnvelope(raw)
	if !ok {
		t.Fatalf("parseEnvelope: ok = false, want true")
	}
	if got != want {
		t.Fatalf("parseEnvelope() = %+v, want %+v", got, want)
	}
}

func TestParseEnvelope_IgnoresOtherEventNames(t *testing.T) {
	raw := []byte(`{"id":"1","event":"OTP_REQUESTED","occurred_at":"2026-01-01T00:00:00Z","source":"login-service","data":{}}`)

	_, ok := parseEnvelope(raw)
	if ok {
		t.Fatalf("parseEnvelope() ok = true for an unrelated event name, want false")
	}
}

func TestParseEnvelope_IgnoresMalformedJSON(t *testing.T) {
	_, ok := parseEnvelope([]byte("not json"))
	if ok {
		t.Fatalf("parseEnvelope() ok = true for malformed JSON, want false")
	}
}
