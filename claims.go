// Package authkit verifies Hydra-issued access tokens and checks the
// roles/permissions embedded in them. It has no dependency on Hydra,
// Kratos, or authz's own code — only on the token's public JWKS endpoint
// and the claims shape login-service embeds at consent time.
package authkit

import "github.com/golang-jwt/jwt/v5"

// Claims is the decoded payload of a Hydra-issued access token.
type Claims struct {
	Roles     []string `json:"roles"`
	CompanyID string   `json:"company_id,omitempty"`
	jwt.RegisteredClaims
}

// HasRole reports whether role is among the claims' roles.
func (c Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}
