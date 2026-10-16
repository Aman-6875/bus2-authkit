# authkit

A shared Go library for BUS 2.0 services to verify Hydra-issued access
tokens and check role/permission claims — so every service enforces
authentication and authorization the same way, instead of each
reimplementing JWT/JWKS handling independently.

See [ROADMAP.md](ROADMAP.md) for what's implemented today versus planned,
version by version.

## Install

This repository is public, so a plain `go get` works, same as any other
public Go module — no `GOPRIVATE` or git credentials needed:

```
go get github.com/Aman-6875/bus2-authkit@v0.2.1
```

## What it does

1. **Authentication** — verifies a Hydra-issued access token: signature
   (against Hydra's JWKS, fetched once and auto-refreshed), expiry, issuer,
   and (optionally) audience.
2. **Authorization** — role checks (`Claims.HasRole`, `middleware.RequireRole`)
   and a `Can()`-style ability check (`middleware.RequireCan`), modeled on
   Laravel's `can()`.
3. **Freshness** (optional) — detects that a token's subject or roles
   changed *after* the token was issued, via `FreshnessChecker`, and rejects
   it even though it hasn't expired yet.
4. **Live permissions** (optional) — `LivePermissions` resolves a role's
   abilities from the owning service on demand, caching the result until an
   `EventRoleChanged` event invalidates it.

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
| `JWKSURL` | Yes | The trusted Hydra instance's `/.well-known/jwks.json`. Fetched once at startup, refreshed hourly in the background by default, and refreshed immediately (rate-limited) if a token references an unknown key ID. |
| `Issuer` | Yes | Must match the token's `iss` claim exactly. |
| `Audience` | **No** | Checked against the token's `aud` claim only if non-empty. Leave empty for services whose callers don't request an `audience` at `/oauth2/auth` yet — this is the case for every BUS 2.0 panel as of today, so most services should leave this empty for now. |
| `JWKSRefreshInterval` | **No** | Overrides the hourly default background refresh. |
| `JWKSHTTPTimeout` | **No** | Overrides the default timeout for each JWKS fetch. |

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

## Freshness and live permissions (optional)

Both are opt-in — skip this section entirely if you only need
`RequireAuth`/`RequireRole` against the token's own claims.

```go
source := kafka.NewEventSource(kafka.Config{
	Brokers: []string{"redpanda:9092"},
	Topic:   "authz.permissions-changed",
	// TLS / SASLMechanism: set both for production, leave nil for local dev.
})

freshness, err := authkit.NewFreshnessChecker(ctx, source, time.Hour) // maxAge: longest token TTL this service accepts
verifier.WithFreshnessChecker(freshness)

fetcher := authkit.HTTPRoleFetcher{
	URL: func(role string) string { return "http://authz:8090/roles/" + role + "/permissions" },
}
livePerms, err := authkit.NewLivePermissions(ctx, fetcher, source)
// use livePerms wherever a PermissionResolver is expected, e.g.:
middleware.RequireCan(verifier, "refund_ticket", livePerms, refundHandler)
```

`HTTPRoleFetcher.URL` builds the full request URL for a given role — it
imposes no route convention of its own, so it fits whatever URL shape the
role-owning service already exposes.

Requirements for the Kafka/Redpanda topic backing `source`:
- **Exactly one partition** — `NewEventSource` always reads partition 0; every
  service instance must see every event, so this intentionally isn't a
  load-balanced consumer group.
- **Retention roughly equal to the longest `maxAge`/token TTL in use** —
  `NewEventSource` starts from the earliest retained offset so a freshly
  started instance backfills recent history, not just new events.

`kafka.Config.DialTimeout` overrides the default 10s broker connection
timeout, if a service's network conditions need something different.

The publishing side (e.g. `authz`, whenever it changes a role or membership):

```go
publisher := kafka.NewPublisher(kafka.Config{Brokers: [...], Topic: "authz.permissions-changed"}, "authz")
defer publisher.Close()

publisher.Publish(ctx, authkit.PermissionsChangedEvent{
	Type:      authkit.EventUserChanged, // or EventRoleChanged
	Subject:   userID,                   // or the role name
	ChangedAt: time.Now(),
})
```

## Errors

`Verify` returns one of these sentinel errors (via `errors.Is`), so callers
never need to know which underlying JWT library this module uses:

`ErrMissingToken`, `ErrInvalidToken`, `ErrTokenExpired`, `ErrIssuerMismatch`,
`ErrAudienceMismatch`, `ErrForbidden`, `ErrTokenStale`.

## Testing

```
go test ./... -v
```

Every test runs against a fake JWKS server, a fake `EventSource`, a fake
`RoleFetcher`, or a fake HTTP server — no real Hydra, Kafka, or authz needed.
The `kafka` subpackage's test only covers its JSON wire format (encode then
decode); it doesn't open a real broker connection.

## Current limitations

- Middleware errors are written as plain text (`http.Error`), not JSON.
  Services needing a JSON error body should wrap the sentinel errors
  themselves for now.
- `Config.Audience` is usually left empty in practice — no BUS 2.0 panel
  requests an `audience` parameter at Hydra's `/oauth2/auth` yet.
- No ready-made `fx.Module` — services using `go.uber.org/fx` wire
  `NewVerifier` (and `NewFreshnessChecker`/`NewLivePermissions`, if used)
  into their own DI by hand, the way `authz` does in
  `internal/authmw/module.go`.

See [ROADMAP.md](ROADMAP.md) for the full picture, including what's planned
next.
