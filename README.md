# authkit

A shared Go library for BUS 2.0 services to verify Hydra-issued access
tokens and check role/permission claims — so every service enforces
authentication and authorization the same way, instead of each
reimplementing JWT/JWKS handling independently.

See [ROADMAP.md](ROADMAP.md) for what's implemented today versus planned,
version by version.

## Install

This repository is **private**, so Go's public module proxy/checksum
database can't reach it. Set `GOPRIVATE` before `go get` (once per machine,
e.g. in your shell profile, or export it inline):

```
export GOPRIVATE=github.com/Aman-6875/*
go get github.com/Aman-6875/bus2-authkit@v0.1.0
```

This also requires `git` to be able to authenticate to GitHub for this
account (an SSH key, or `gh auth login` / a credential helper) — the module
is fetched by cloning the repo, not through the public proxy.

## What it does

1. **Authentication** — verifies a Hydra-issued access token: signature
   (against Hydra's JWKS, fetched once and auto-refreshed), expiry, issuer,
   and (optionally) audience.
2. **Authorization** — role checks (`Claims.HasRole`, `middleware.RequireRole`)
   and a `Can()`-style ability check (`middleware.RequireCan`), modeled on
   Laravel's `can()`.

## Quick start

```go
ctx := context.Background()
verifier, err := authkit.NewVerifier(ctx, authkit.Config{
	JWKSURL: "http://hydra:4444/.well-known/jwks.json",
	Issuer:  "http://hydra:4444",
	// Audience is optional — see Config.Audience doc below.
})
if err != nil {
	log.Fatal(err)
}

mux := http.NewServeMux()
mux.HandleFunc("POST /companies", middleware.RequireRole(verifier, "super_admin", createCompanyHandler))
```

Where does `JWKSURL`/`Issuer` come from? **Not from this library.** Each
service reads its own environment variables (or config source) and passes
the values in — see "Configuration" below.

## Configuration

| `Config` field | Required? | Notes |
|---|---|---|
| `JWKSURL` | Yes | The trusted Hydra instance's `/.well-known/jwks.json`. Fetched once at startup, refreshed hourly in the background, and refreshed immediately (rate-limited) if a token references an unknown key ID. |
| `Issuer` | Yes | Must match the token's `iss` claim exactly. |
| `Audience` | **No** | Checked against the token's `aud` claim only if non-empty. Leave empty for services whose callers don't request an `audience` at `/oauth2/auth` yet — this is the case for every BUS 2.0 panel as of today, so most services should leave this empty for now. |

`authkit` never reads environment variables itself (no `os.Getenv` anywhere
in this module) — every consuming service owns its own config loading and
passes a plain `Config` struct in. This keeps the library testable without
env-var gymnastics and lets each service name its own env vars.

## Middleware

```go
middleware.RequireAuth(verifier, handler)                          // token must be valid
middleware.RequireRole(verifier, "super_admin", handler)            // + must have this role
middleware.RequireCan(verifier, "refund_ticket", resolver, handler) // + must have this ability
```

Use only what you need — a service that only needs "is this caller logged
in" should use `RequireAuth` alone; it is not forced into role or
permission checks.

Downstream handlers can read the verified claims via:

```go
claims, ok := middleware.ClaimsFromContext(r.Context())
```

## Errors

`Verify` returns one of these sentinel errors (via `errors.Is`), so callers
never need to know which underlying JWT library this module uses:

`ErrMissingToken`, `ErrInvalidToken`, `ErrTokenExpired`, `ErrIssuerMismatch`,
`ErrAudienceMismatch`, `ErrForbidden`.

## Testing

```
go test ./... -v
```

Tests run against a fake, in-process JWKS server (no real Hydra needed) —
see `verifier_test.go`.

## Current limitations

- `RequireCan`/`Can` only works against a `PermissionResolver` you supply
  yourself (e.g. `StaticPermissions`, a fixed map) — there is no live,
  auto-refreshing role→permission cache yet. See ROADMAP.md.
- No token revocation/freshness check — a token is trusted at face value
  until it expires, even if the underlying user's role changed. See
  ROADMAP.md.
- Middleware errors are written as plain text (`http.Error`), not JSON.
  Services needing a JSON error body should wrap the sentinel errors
  themselves for now.
