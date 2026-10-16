package authkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// HTTPRoleFetcher implements RoleFetcher over plain HTTP GET. It imposes no
// URL shape of its own — URL builds the request URL for role, so the
// service on the other end can expose whatever route convention it already
// uses (e.g. "/roles/operator_admin/permissions", "/api/v1/rbac/roles/operator_admin",
// or anything else). The response must be JSON shaped
// {"permissions": ["...", ...]}.
type HTTPRoleFetcher struct {
	// URL returns the full request URL for role. Required.
	URL func(role string) string

	// Client is optional; http.DefaultClient is used if nil.
	Client *http.Client
}

// Permissions implements RoleFetcher.
func (f HTTPRoleFetcher) Permissions(ctx context.Context, role string) ([]string, error) {
	if f.URL == nil {
		return nil, fmt.Errorf("authkit.HTTPRoleFetcher: URL is required")
	}

	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL(role), nil)
	if err != nil {
		return nil, fmt.Errorf("authkit.HTTPRoleFetcher: build request for role %q: %w", role, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authkit.HTTPRoleFetcher: request role %q: %w", role, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authkit.HTTPRoleFetcher: role %q: unexpected status %d", role, resp.StatusCode)
	}

	var body struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("authkit.HTTPRoleFetcher: decode response for role %q: %w", role, err)
	}

	return body.Permissions, nil
}
