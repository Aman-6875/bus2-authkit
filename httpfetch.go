package authkit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// HTTPRoleFetcher implements RoleFetcher by calling
// "<BaseURL>/roles/<role>/permissions" on the service that owns role data
// (e.g. authz), expecting a JSON body shaped {"permissions": ["...", ...]}.
type HTTPRoleFetcher struct {
	BaseURL string

	// Client is optional; http.DefaultClient is used if nil.
	Client *http.Client
}

// Permissions implements RoleFetcher.
func (f HTTPRoleFetcher) Permissions(ctx context.Context, role string) ([]string, error) {
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}

	endpoint := strings.TrimSuffix(f.BaseURL, "/") + "/roles/" + url.PathEscape(role) + "/permissions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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
