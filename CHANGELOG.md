# Changelog

All notable changes to auth-kit. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [semantic versioning](https://semver.org/).

## Unreleased

### Added

- Design document (`docs/design.md`).
- Package scaffold: TypeScript, ESLint with the anti-slop preset, Vitest, CI on the runner pool, MIT licence.
- The fixed sign-in policies as exported constants.
- Core extracted from Tercer Tiempo (`JavierCervilla/tercer-tiempo@916d207`): `createAuth` on better-auth 1.7.10 with
  guests, the magic link and the 6-digit email code in the same email; sessions without IP address or user agent;
  telemetry off; origin check always on; option and environment validation that never repeats a value.
- Generic guest-to-account hooks: `guardGuestToAccount` refuses before the link or code is consumed, and
  `onGuestToAccount` moves the guest's data in one transaction before better-auth deletes the guest, with the race
  safety net (rolls back, deletes the new session, puts the guest's cookie back).
- Usage limits on fixed-window Postgres counters keyed by an HMAC derived from the auth secret, each with one 429:
  sign-in emails (5 per hour per email, 20 per hour per IP), email-code checks (10 per day per email, 30 per hour per
  IP, spent before the code is looked at) and guest sign-ups (30 per hour per IP, 1000 per hour in total, on every
  path that creates a guest). The defaults are `DEFAULT_LIMITS`; `createAuth` takes a `limits` option and
  `limitsFromEnv` reads Tercer Tiempo's `RATE_LIMIT_*` variables.
- Route allowlist in `auth.handler`: only `GET /get-session` and, with mail on, the three sign-in email routes reach
  better-auth; every other path, including the guest sign-up route and routes a future better-auth adds, is 404.
- `@universelle/auth-kit/schema` (`authTables`: user, session, account, verification, rate_limit_counter) and
  `@universelle/auth-kit/mail` (`Mailer` and `resendSmtpMailer` over port 587 with STARTTLS).
- Unit tests and integration tests against PGlite (`npm run test:int`), also in CI.
