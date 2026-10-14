package authkit

import "errors"

var (
	// ErrMissingToken means the request carried no bearer token at all.
	ErrMissingToken = errors.New("authkit: missing bearer token")

	// ErrInvalidToken means the token's signature didn't verify, or it was
	// malformed — it was not genuinely issued by the trusted Hydra instance.
	ErrInvalidToken = errors.New("authkit: token invalid")

	// ErrTokenExpired means the signature verified, but the token's "exp"
	// claim is in the past.
	ErrTokenExpired = errors.New("authkit: token expired")

	// ErrIssuerMismatch means the token's "iss" claim doesn't match the
	// Hydra instance this service trusts.
	ErrIssuerMismatch = errors.New("authkit: token issuer mismatch")

	// ErrAudienceMismatch means the token is genuine but wasn't minted for
	// this service — it was meant for a different resource server.
	ErrAudienceMismatch = errors.New("authkit: token not issued for this audience")

	// ErrForbidden means the token is valid, but the caller's roles don't
	// grant the required role or permission.
	ErrForbidden = errors.New("authkit: caller lacks required role or permission")
)
