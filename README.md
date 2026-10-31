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
- Only better-auth routes the package uses are reachable over HTTP; every other path answers 404. Guests are created
  only on the server, with `signInAnonymously`.
- Every usage limit answers the same 429 whether the address exists or not, before better-auth runs.
- No log line contains an email address.

## Limits

The usage limits are configurable. Pass `limits` to `createAuth` (merged over the defaults), or read them from the
environment with `limitsFromEnv(process.env)`. An unset variable means the default; a blank, non-integer, zero or
negative value stops the start with an error naming the variable.

| Limit | Variable | Default |
|---|---|---|
| Sign-in emails per address per hour | `RATE_LIMIT_MAGIC_LINK_EMAIL_PER_HOUR` | 5 |
| Sign-in emails per IP per hour | `RATE_LIMIT_MAGIC_LINK_IP_PER_HOUR` | 20 |
| Email-code checks per address per day | `RATE_LIMIT_OTP_VERIFY_EMAIL_PER_DAY` | 10 |
| Email-code checks per IP per hour | `RATE_LIMIT_OTP_VERIFY_IP_PER_HOUR` | 30 |
| Guest sign-ups per IP per hour | `RATE_LIMIT_ANON_SIGNUP_PER_HOUR` | 30 |
| Guest sign-ups per hour in total | `RATE_LIMIT_ANON_SIGNUP_GLOBAL_PER_HOUR` | 1000 |

## Deploying it safely

- **Proxy in front.** `trustedProxyHops` (default 1) says how many proxies in front of the app append the client's
  address to `X-Forwarded-For`; the limiter takes the address that many hops from the right. With no proxy, set it to
  0, or a client can write that header and dodge the per-IP limits (the per-email and global limits still hold).
- **No permissive CORS with credentials.** The sign-in routes rely on browsers refusing cross-site JSON without a
  CORS preflight. Do not answer that preflight for other sites with `Access-Control-Allow-Credentials: true` on the
  auth routes.
- **Sign-out** is not exposed over HTTP; call `auth.api.signOut` from your own route if the app offers it.

## Provenance

Extracted from [JavierCervilla/tercer-tiempo@916d207](https://github.com/JavierCervilla/tercer-tiempo/tree/916d207)
(`src/auth`, `src/mail`, `src/rate-limit`), same author. The comments were translated to English and the
team-specific link logic was replaced by the generic guest-to-account hooks.

## Security

See [`SECURITY.md`](SECURITY.md) to report a vulnerability.

## Licence

[MIT](LICENSE), © 2026 Universelle.
