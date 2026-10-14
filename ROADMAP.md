# Roadmap

This tracks what each version of `authkit` actually implements, so a
consuming service knows what it's getting — and what changes — when it
bumps its required version. Update this file whenever a version's scope
changes; it is the implementation plan, not just a changelog of the past.

## v0.1.0 — current

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

## v0.2.0 — planned, not started

Closes the freshness gap and makes `Can` production-usable at scale.

- **`FreshnessChecker`**: a new mechanism so `Verify` (or a wrapper around
  it) can detect that a user's role/permissions changed *after* their
  current token was issued, and reject the stale token before it expires
  naturally. Backed by an event (Kafka/Redpanda) published by whichever
  service owns role/membership data, consumed into a small, TTL-bounded
  local cache in each service running authkit — not a per-request network
  call. Applies to both role checks and permission checks equally.
- **Live `PermissionResolver`**: a role→permission cache kept fresh the same
  way, replacing the need for `StaticPermissions` in most services. The
  `PermissionResolver` interface itself does not change — this is a new
  implementation of it, not a breaking change to `Can`'s signature.
- Impact on services already on v0.1.0: upgrading is additive. A service
  using only `RequireRole`/`RequireAuth` sees no required code change.  A
  service wanting the freshness guarantee or a live resolver opts in by
  wiring the new pieces; nothing is forced on every consumer.

## Unscheduled / under discussion

Noted here so they aren't lost, not committed to a version yet:

- JSON-formatted middleware error responses (currently plain text via
  `http.Error`).
- Audience rollout across the panels (`admin-panel`, `operator-panel`,
  `shohoz-panel`) so `Config.Audience` becomes meaningful fleet-wide.
- Packaging a ready-made `fx.Module` for services already using
  `go.uber.org/fx` (today each service wires `NewVerifier` into its own DI
  by hand, as `authz` does in `internal/authmw/module.go`).
