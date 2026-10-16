package authkit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	authkit "github.com/Aman-6875/bus2-authkit"
)

func TestHTTPRoleFetcher_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/roles/operator_admin/permissions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"permissions": ["refund_ticket", "view_reports"]}`))
	}))
	defer server.Close()

	fetcher := authkit.HTTPRoleFetcher{
		URL: func(role string) string { return server.URL + "/roles/" + role + "/permissions" },
	}
	got, err := fetcher.Permissions(context.Background(), "operator_admin")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	want := []string{"refund_ticket", "view_reports"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Permissions() = %v, want %v", got, want)
	}
}

// TestHTTPRoleFetcher_ArbitraryURLShape proves authkit imposes no route
// convention of its own — a service with a completely different URL shape
// works exactly the same way, via URL alone.
func TestHTTPRoleFetcher_ArbitraryURLShape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/rbac/operator_admin" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Write([]byte(`{"permissions": ["view_reports"]}`))
	}))
	defer server.Close()

	fetcher := authkit.HTTPRoleFetcher{
		URL: func(role string) string { return server.URL + "/api/v1/rbac/" + role },
	}
	got, err := fetcher.Permissions(context.Background(), "operator_admin")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	if len(got) != 1 || got[0] != "view_reports" {
		t.Fatalf("Permissions() = %v, want [view_reports]", got)
	}
}

func TestHTTPRoleFetcher_MissingURLFunc(t *testing.T) {
	fetcher := authkit.HTTPRoleFetcher{}
	if _, err := fetcher.Permissions(context.Background(), "operator_admin"); err == nil {
		t.Fatalf("Permissions() error = nil, want an error when URL is not set")
	}
}

func TestHTTPRoleFetcher_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	fetcher := authkit.HTTPRoleFetcher{
		URL: func(role string) string { return server.URL + "/roles/" + role + "/permissions" },
	}
	if _, err := fetcher.Permissions(context.Background(), "unknown_role"); err == nil {
		t.Fatalf("Permissions() error = nil, want an error for a non-200 response")
	}
}

func TestHTTPRoleFetcher_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	fetcher := authkit.HTTPRoleFetcher{
		URL: func(role string) string { return server.URL + "/roles/" + role + "/permissions" },
	}
	if _, err := fetcher.Permissions(context.Background(), "operator_admin"); err == nil {
		t.Fatalf("Permissions() error = nil, want an error for a malformed response body")
	}
}
