# auth-kit

Optional sign-in for web games and apps: play as a guest at once, and keep your identity with a magic link (or the
6-digit code in the same email) when you want to. Built on [better-auth](https://www.better-auth.com) with Postgres
and Drizzle, with adapters for Hono and Next.

**Status: pre-release.** The design is in [`docs/design.md`](docs/design.md); the code is being extracted from
production use in Tercer Tiempo. Nothing is tagged yet.

## Install

auth-kit is installed straight from this repository, pinned to a tag. npm compiles it on install.

```json
{
  "dependencies": {
    "@universelle/auth-kit": "github:JavierCervilla/auth-kit#v0.1.0"
  }
}
```

## What it guarantees

These are fixed, not options:

- A magic link works once and expires in 10 minutes; only its hash is stored.
- The email code has 6 digits, the same expiry and 3 attempts.
- A session lasts 180 days from its last use; no IP address or user agent is stored with it.
- At most 5 sign-in emails per hour per address and 20 per hour per IP, with the same answer whether the address
  exists or not.
- No log line contains an email address.

## Provenance

Extracted from [JavierCervilla/tercer-tiempo@916d207](https://github.com/JavierCervilla/tercer-tiempo/tree/916d207)
(`src/auth`, `src/mail`, `src/rate-limit`), same author. The comments were translated to English and the
team-specific link logic was replaced by the generic guest-to-account hooks.

## Security

See [`SECURITY.md`](SECURITY.md) to report a vulnerability.

## Licence

[MIT](LICENSE), © 2026 Universelle.
