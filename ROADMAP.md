# Roadmap

This tracks what each version of `authkit` actually implements, so a
consuming service knows what it's getting — and what changes — when it
bumps its required version. Update this file whenever a version's scope
changes; it is the implementation plan, not just a changelog of the past.

## v0.1.0 — superseded by v0.2.0

Authentication, plus role-level authorization. No live permission data.

- `Verifier.Verify`: signature (via JWKS, auto-refreshed), expiry, issuer,
  optional audience.
- `Claims.HasRole` / `middleware.RequireRole`: role check straight off the
  token's `roles` claim. No external lookup — works today with zero extra
  infrastructure.
- `Can` / `middleware.RequireCan`: ability check against a
  `PermissionResolver` the caller supplies. Only implementation provided is
  `StaticPermissions` (a fixed, in-memory map) — fine for a first integration
  or a service with few, rarely-changing roles; **not** backed by any cache
  or live data source yet.
- Sentinel errors for every failure mode (`ErrTokenExpired`,
  `ErrAudienceMismatch`, etc.), so callers don't need to know this module
  uses `golang-jwt` underneath.

**Known gap — no revocation/freshness check.** A token is trusted exactly as
issued until it expires. If a user's role is changed or revoked mid-session,
`Verify` has no way to notice — the old token keeps working until it
naturally expires. Every service on v0.1.0 inherits this limitation.

**Known gap — `Audience` is usually empty in practice.** As of this version,
no BUS 2.0 panel requests an `audience` parameter at Hydra's `/oauth2/auth`,
so issued tokens carry no `aud` claim. Services should leave `Config.Audience`
empty until the panels are updated — this is a separate, not-yet-scheduled
piece of work, tracked here so it isn't lost.

## v0.2.0 — current

Closes the freshness gap and makes `Can` production-usable at scale.
Everything here is additive over v0.1.0 — a service using only
`RequireRole`/`RequireAuth` needs no code change to upgrade.

- **`FreshnessChecker`** (`freshness.go`): detects that a user's
  subject or roles changed *after* their current token was issued, and
  `Verify` rejects the token (`ErrTokenStale`) before it expires naturally.
  Backed by a TTL-bounded local cache (`userChangedAt`/`roleChangedAt`
  maps), kept fresh by consuming `PermissionsChangedEvent`s in the
  background — not a per-request network call. Opt in via
  `Verifier.WithFreshnessChecker`; a `Verifier` with none attached behaves
  exactly as it did on v0.1.0.
- **`LivePermissions`** (`permissions.go`): a `PermissionResolver` backed by
  a lazy, event-invalidated cache in front of a `RoleFetcher`. On a fetch
  failure it denies (returns no permissions) rather than failing open. The
  `PermissionResolver` interface itself is unchanged from v0.1.0 — this is
  just a second implementation of it, alongside `StaticPermissions`.
- **`authkit/kafka`**: the reference transport for both of the above — a
  Redpanda/Kafka-backed `EventSource` (consumer) and `Publisher` (producer),
  sharing one JSON envelope (matching `login-service`'s existing
  `idp.events` convention) so neither side has to hand-roll the wire format.
  TLS and a SASL mechanism are both optional `Config` fields — nil connects
  unauthenticated (local dev); setting both authenticates (production). The
  backing topic must have exactly one partition (no consumer group — every
  instance needs to see every event) and a retention period roughly equal
  to the longest `maxAge`/token TTL in use (reading starts from the
  earliest retained offset, so a freshly started instance backfills recent
  history).
- **`HTTPRoleFetcher`** (`httpfetch.go`): the reference `RoleFetcher` —
  calls `GET <BaseURL>/roles/<role>/permissions`, expecting
  `{"permissions": [...]}`.

**Still open — nothing publishes to the event topic yet.** This version
gives every service the *consumer* side (`FreshnessChecker`,
`LivePermissions`, `kafka.NewEventSource`) and the *tooling* to publish
(`kafka.NewPublisher`), but no BUS 2.0 service calls `Publisher.Publish` on
a role/membership change yet. Until some service does, `FreshnessChecker`
and `LivePermissions` run with an always-empty event stream — harmless, but
also not yet providing their real benefit. Wiring that into `authz` (whose
`internal/rbac/membership` package owns the data that changes) is the next
piece of work, outside this repo.

## Unscheduled / under discussion

Noted here so they aren't lost, not committed to a version yet:

- JSON-formatted middleware error responses (currently plain text via
  `http.Error`).
- Audience rollout across the panels (`admin-panel`, `operator-panel`,
  `shohoz-panel`) so `Config.Audience` becomes meaningful fleet-wide.
- Packaging a ready-made `fx.Module` for services already using
  `go.uber.org/fx` (today each service wires `NewVerifier` into its own DI
  by hand, as `authz` does in `internal/authmw/module.go`).
