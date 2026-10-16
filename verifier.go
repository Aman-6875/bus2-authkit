package authkit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Config configures a Verifier.
type Config struct {
	// JWKSURL is the token issuer's public JWKS endpoint, e.g.
	// "http://hydra:4444/.well-known/jwks.json".
	JWKSURL string

	// Issuer is the expected "iss" claim.
	Issuer string

	// Audience is this service's own identifier, checked against the
	// token's "aud" claim so a token minted for a different service is
	// rejected here instead of silently being accepted. Optional: leave
	// empty to skip this check, for services whose tokens don't carry an
	// audience claim yet.
	Audience string

	// JWKSRefreshInterval overrides how often the JWKS is re-fetched in the
	// background (it's also refreshed immediately, rate-limited, on an
	// unrecognized key ID regardless of this setting). Optional: zero uses
	// the underlying library's own default (currently 1 hour).
	JWKSRefreshInterval time.Duration

	// JWKSHTTPTimeout overrides the timeout for each JWKS fetch. Optional:
	// zero uses the underlying library's own default.
	JWKSHTTPTimeout time.Duration
}

// Verifier checks access tokens: signature (against the issuer's JWKS),
// expiry, issuer, and audience.
type Verifier struct {
	keyfunc   keyfunc.Keyfunc
	issuer    string
	audience  string
	freshness *FreshnessChecker
}

// WithFreshnessChecker attaches fc so Verify also rejects tokens whose
// subject or roles changed after the token was issued. Optional — a
// Verifier with no FreshnessChecker attached trusts a token's claims at
// face value until expiry, as it always has. Returns v for chaining.
func (v *Verifier) WithFreshnessChecker(fc *FreshnessChecker) *Verifier {
	v.freshness = fc
	return v
}

// NewVerifier fetches (and keeps refreshed in the background) the issuer's
// JWKS from cfg.JWKSURL.
func NewVerifier(ctx context.Context, cfg Config) (*Verifier, error) {
	kf, err := keyfunc.NewDefaultOverrideCtx(ctx, []string{cfg.JWKSURL}, keyfunc.Override{
		RefreshInterval: cfg.JWKSRefreshInterval,
		HTTPTimeout:     cfg.JWKSHTTPTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("authkit.NewVerifier: %w", err)
	}

	return &Verifier{
		keyfunc:  kf,
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
	}, nil
}

// Verify checks tokenString's signature, expiry, and issuer, and returns its
// claims if every check passes. Audience is checked only when the Verifier
// was constructed with a non-empty Config.Audience — services that haven't
// adopted audience-scoped tokens yet are not broken by this check.
func (v *Verifier) Verify(tokenString string) (Claims, error) {
	opts := []jwt.ParserOption{jwt.WithIssuer(v.issuer)}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	var claims Claims
	_, err := jwt.ParseWithClaims(tokenString, &claims, v.keyfunc.Keyfunc, opts...)

	switch {
	case err == nil:
		if v.freshness != nil && v.freshness.IsStale(claims) {
			return Claims{}, ErrTokenStale
		}
		return claims, nil
	case errors.Is(err, jwt.ErrTokenExpired):
		return Claims{}, fmt.Errorf("%w: %v", ErrTokenExpired, err)
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return Claims{}, fmt.Errorf("%w: %v", ErrIssuerMismatch, err)
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return Claims{}, fmt.Errorf("%w: %v", ErrAudienceMismatch, err)
	default:
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
}
