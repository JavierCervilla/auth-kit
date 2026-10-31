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
- Send limit in front of the sign-in email (5 per hour per email, 20 per hour per IP) on fixed-window Postgres counters
  keyed by an HMAC derived from the auth secret.
- `@universelle/auth-kit/schema` (`authTables`: user, session, account, verification, rate_limit_counter) and
  `@universelle/auth-kit/mail` (`Mailer` and `resendSmtpMailer` over port 587 with STARTTLS).
- Unit tests and integration tests against PGlite (`npm run test:int`), also in CI.
