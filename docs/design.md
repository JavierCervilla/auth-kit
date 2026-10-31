# auth-kit · Design

Status: draft for review (MOON-5). Owner: the Mooner project. Consumers: Mooner first, Ventana Lunar after the
15 Nov 2026 hackathon freeze, Tercer Tiempo in its own migration trajectory.

## What it is

A small, public TypeScript package for **optional sign-in**: play as a guest at once, and keep your identity with a
magic link (or the 6-digit code in the same email) when you want to. Built on [better-auth](https://www.better-auth.com)
1.7.10, extracted from Tercer Tiempo (`JavierCervilla/tercer-tiempo@916d207`: `src/auth`, `src/mail`,
`src/rate-limit`), where it runs in production.

It does not know about teams, games or sites. Each project brings its database, its email text and what happens when a
guest becomes an account.

## Decisions

| Topic | Decision | Why |
|---|---|---|
| Visibility | Public repo | Installs anywhere without tokens; no secret lives in the code |
| Distribution | Git dependency pinned to a tag: `"@universelle/auth-kit": "github:JavierCervilla/auth-kit#v0.1.0"` | No registry, no cost; a tag is the version |
| Build on install | `prepare` script compiles TypeScript when npm installs the git dependency | No generated files in git |
| Package manager | npm | Mooner and Ventana Lunar use npm workspaces; the package works the same under pnpm |
| Database | Postgres with Drizzle | What Tercer Tiempo runs; the package exports its tables so each project adds them to its own migrations |
| Mail | Resend over SMTP, port 587 with STARTTLS (nodemailer), behind a `Mailer` interface | Hetzner blocks outbound 25 and 465; a project can swap the relay |
| Web frameworks | Thin adapters: `@universelle/auth-kit/hono` and `@universelle/auth-kit/next` | Mooner and Ventana run Hono, Tercer Tiempo runs Next |
| Language | Code, comments, docs and errors in English | Public package; the comments ported from Tercer Tiempo are translated |

## Fixed policies

These are the privacy and security choices proven in Tercer Tiempo. They are constants of the package, not options,
so no consumer weakens them by accident:

- Magic link: single use, expires in 10 minutes, only its SHA-256 hash is stored.
- Email code: 6 digits, same expiry as the link, 3 attempts, single use, a new request invalidates the previous one,
  stored hashed. It is only ever sent together with the link; the standalone send route stays closed.
- Session: 180 days from last use, renewed at most once a day; cookie `httpOnly`, `sameSite=lax`, `secure` outside
  local development.
- No IP address or user agent is stored with a session; better-auth telemetry is off.
- Route allowlist: over HTTP only `GET /get-session` and, with mail on, asking for the sign-in email, opening the link
  and checking the code reach better-auth. Every other path answers 404, including the guest sign-up route (guests are
  created only on the server) and any route a future better-auth adds.
- Usage limits are counted before better-auth runs, with the same 429 whether the email exists or not and whichever
  quota ran out. Counters are fixed-window rows in Postgres keyed by an HMAC of the subject derived from the auth
  secret, spent outside any transaction so a rollback never refunds an attempt.
- A failed send answers the same 503 whether the email exists or not; no log line contains an email address.

The amounts of the usage limits are the one thing a project may tune. Defaults are Tercer Tiempo's values, overridable
with the `limits` option of `createAuth` or with `limitsFromEnv(env)`, which reads the same variables as Tercer Tiempo
and refuses a blank, non-integer, zero or negative value at start-up, naming the variable:

| Limit | Variable | Default |
|---|---|---|
| Sign-in emails per email per hour | `RATE_LIMIT_MAGIC_LINK_EMAIL_PER_HOUR` | 5 |
| Sign-in emails per IP per hour | `RATE_LIMIT_MAGIC_LINK_IP_PER_HOUR` | 20 |
| Code checks per email per day (spent right code or not) | `RATE_LIMIT_OTP_VERIFY_EMAIL_PER_DAY` | 10 |
| Code checks per IP per hour | `RATE_LIMIT_OTP_VERIFY_IP_PER_HOUR` | 30 |
| Guest sign-ups per IP per hour | `RATE_LIMIT_ANON_SIGNUP_PER_HOUR` | 30 |
| Guest sign-ups per hour in total | `RATE_LIMIT_ANON_SIGNUP_GLOBAL_PER_HOUR` | 1000 |

## Public API (sketch)

```ts
import { createAuth } from "@universelle/auth-kit";
import { authTables } from "@universelle/auth-kit/schema";
import { resendSmtpMailer } from "@universelle/auth-kit/mail";
import { mountAuth } from "@universelle/auth-kit/hono";

const auth = createAuth({
  db,                          // a Drizzle Postgres database that includes authTables
  baseURL, secret,             // from the environment; secret is never logged
  trustedOrigins,              // extra origins allowed to call the auth routes
  mailer: resendSmtpMailer(env),     // or any Mailer; unconfigured = sign-in by email is off, guests still work
  email: { render: (link, code, locale) => ({ subject, html, text }) },  // each project writes its own email
  onGuestToAccount: async (tx, { guestUserId, accountUserId }) => { /* move the guest's data */ },
  guardGuestToAccount: async ({ guestUserId, email }) => null,   // optional: refuse a link before any side effect
});

mountAuth(app, auth);          // Hono: routes under /api/auth
const user = await auth.currentUser(request.headers);   // guest, account or null
```

`onGuestToAccount` runs inside one transaction before better-auth deletes the guest user. `guardGuestToAccount` runs
before the magic link or the code is consumed, so a refusal leaves no session, no cookie and an unused token. This is the
behaviour Tercer Tiempo pinned with integration tests (owner conflict, the race between the guard and the move); the
tests move with the code.

## Layout

```
src/
  core/        createAuth, fixed policies, guest-to-account hooks, current user
  schema/      Drizzle tables (user, session, account, verification, rate_limit_counter)
  mail/        Mailer interface, Resend SMTP mailer
  rate-limit/  send limits and client IP
  adapters/    hono.ts, next.ts
tests/
  unit/        no database, no network
  integration/ against a real Postgres engine (see Quality gates)
```

## Quality gates

- TypeScript strict, ESLint with the anti-slop preset, Vitest unit and integration tests.
- CI on GitHub-hosted runners, free for a public repository, with the account's Actions budget at 0 so nothing can
  bill. The self-hosted pool (`vars.CI_RUNNER`) is a manual fallback when GitHub's runners fail: run the CI workflow
  by hand with `runner: pool`, which needs write access. The repo requires approval for every external
  contributor's workflow run, because a fork can edit its own workflow file and name the pool's label; before
  approving one, check that its diff does not touch `.github/`.
  The integration tests do not use a Postgres service container either, so the same suite runs in any consumer's CI
  and on the Docker-less pool. They run against PGlite (Postgres compiled to WebAssembly, in
  process) through Drizzle's PGlite driver; whether better-auth's adapter and the send-limit SQL (`INSERT … ON
  CONFLICT … RETURNING`, `skip locked`) behave the same there is the first thing the extraction proves. If they do
  not, the fallback is a Postgres installed on the runner host.
- Security ladder (gitleaks, semgrep, osv-scanner, npm audit), English gate.
- Public repo hygiene: `LICENSE`, `README.md` with install and usage, `SECURITY.md` with how to report a vulnerability
  privately, no real keys in tests or examples.

## Versioning

Semantic versioning with git tags. `v0.x` while Mooner is the only consumer; `v1.0.0` when a second project adopts it.
A change to a fixed policy or to the tables is a breaking change and comes with a migration note.

## Build order

1. This design (review).
2. Scaffold: package, tooling, CI, licence, README, SECURITY.
3. Extract core, schema, mail and rate limit from Tercer Tiempo with their tests, translated to English.
4. Hono adapter and a first integration in Mooner; tag `v0.1.0`.
5. Next adapter, for Tercer Tiempo's migration.

## Settled after review

- Licence: MIT, © 2026 Universelle (Tercer Tiempo had none; its author chose).
- `CHANGELOG.md` and `ROADMAP.md` are in English: the package is public and its readers are global. This is a
  deliberate exception to the framework's Spanish default.
