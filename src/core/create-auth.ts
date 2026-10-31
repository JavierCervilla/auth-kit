/**
 * better-auth with guests (`anonymous`) and, with the mailer on, the magic link and the email code, on Drizzle.
 *
 * - Session: expires 180 days after last use and is renewed when used if older than a day; the cookie carries the same
 *   `Max-Age`, is `httpOnly`, `sameSite=lax` and `secure` outside local development (settings.ts).
 * - No IP address or user agent in `session` (session-privacy.ts); telemetry off in writing, and the environment cannot
 *   turn it back on (settings.ts).
 * - `disableDeleteAnonymousUser` stays `false`, the default: when a guest becomes an account the plugin deletes the
 *   guest `user`, after `onGuestToAccount` has moved its data (guest-link.ts).
 * - Origins: better-auth accepts HTTP requests whose `Origin` is the base URL's or is in `trustedOrigins`. It turns
 *   that check off by itself under NODE_ENV=test; here it stays on always, so tests prove what runs in production.
 * - Creating the instance reads nothing from the network: the database is first touched by the first request.
 */
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { anonymous } from "better-auth/plugins/anonymous";

import { createSendLimiter } from "../rate-limit/limiter.js";
import { account, session, user, verification } from "../schema/auth-tables.js";

import { assertClosedCodeBody, closedCodePaths, sameCodeErrorStatus, unifyCodeErrors } from "./email-code-route.js";
import { guardGuestLink, onLinkAccount } from "./guest-link.js";
import { SESSION } from "./policies.js";
import { AUTH_BASE_PATH, EMAIL_CODE_VERIFY_PATH, SEND_SIGN_IN_EMAIL_PATH } from "./routes.js";
import { limitSend } from "./send-limit.js";
import { withoutClientData } from "./session-privacy.js";
import { resolveSettings, type Env } from "./settings.js";
import { signInEmailPlugins, type CreateSignInCode } from "./sign-in-email.js";
import type { AuthDatabase, AuthKitOptions, SessionUser } from "./types.js";

const DEFAULT_TRUSTED_PROXY_HOPS = 1;

function trustedProxyHops(value: number | undefined): number {
  const hops = value ?? DEFAULT_TRUSTED_PROXY_HOPS;
  if (!Number.isSafeInteger(hops) || hops < 1) throw new Error("auth-kit: trustedProxyHops must be a positive integer");
  return hops;
}

function emailPlugins<TDb extends AuthDatabase>(options: AuthKitOptions<TDb>, createSignInCode: CreateSignInCode) {
  if (!options.mailer?.configured) return [];
  return signInEmailPlugins(options.mailer, options.email, createSignInCode);
}

function requestHooks<TDb extends AuthDatabase>(
  options: AuthKitOptions<TDb>,
  secret: string,
  closedPaths: ReadonlySet<string>,
) {
  const log = options.log ?? ((line: string) => console.warn(line));
  const hops = trustedProxyHops(options.trustedProxyHops);
  const limiter = createSendLimiter({ db: options.db, secret, trustedProxyHops: hops, log });
  const guard = options.guardGuestToAccount;
  return {
    before: createAuthMiddleware(async (ctx) => {
      if (ctx.path === SEND_SIGN_IN_EMAIL_PATH) return limitSend(limiter, ctx);
      if (ctx.request && closedPaths.has(ctx.path)) throw new APIError("NOT_FOUND");
      if (ctx.path === EMAIL_CODE_VERIFY_PATH) assertClosedCodeBody(ctx);
      if (guard) await guardGuestLink(ctx, guard);
    }),
    after: createAuthMiddleware((ctx) => {
      if (ctx.path === EMAIL_CODE_VERIFY_PATH) unifyCodeErrors(ctx.context.returned);
      return Promise.resolve();
    }),
  };
}

function buildBetterAuth<TDb extends AuthDatabase>(options: AuthKitOptions<TDb>, env: Env) {
  const settings = resolveSettings({ ...options, env });
  // `sendMagicLink` needs the instance to create the code; it is plugged in as soon as the instance exists.
  let createSignInCode: CreateSignInCode = () => Promise.reject(new Error("better-auth is not mounted yet"));
  const plugins = emailPlugins(options, (email) => createSignInCode(email));
  const closedPaths = closedCodePaths(plugins[0]?.endpoints ?? {});
  const auth = betterAuth({
    secret: options.secret,
    baseURL: options.baseURL,
    trustedOrigins: settings.trustedOrigins,
    basePath: AUTH_BASE_PATH,
    database: drizzleAdapter(options.db, { provider: "pg", schema: { user, session, account, verification } }),
    emailAndPassword: { enabled: false },
    session: { expiresIn: SESSION.expiresInSeconds, updateAge: SESSION.updateAgeSeconds },
    advanced: {
      useSecureCookies: settings.secureCookies,
      ipAddress: { disableIpTracking: true },
      disableOriginCheck: false,
      disableCSRFCheck: false,
    },
    databaseHooks: {
      session: { create: { before: withoutClientData }, update: { before: withoutClientData } },
    },
    telemetry: { enabled: false },
    // The code's row does not keep the email in clear; the magic link's keeps only the token's hash.
    verification: { storeIdentifier: { default: "plain", overrides: { "sign-in-otp-": "hashed" } } },
    hooks: requestHooks(options, options.secret, closedPaths),
    plugins: [anonymous({ onLinkAccount: onLinkAccount(options.db, options.onGuestToAccount) }), ...plugins],
  });
  createSignInCode = (email) => auth.api.createVerificationOTP({ body: { email, type: "sign-in" } });
  return auth;
}

/** The better-auth instance `createAuth` builds. */
export type BetterAuthInstance = ReturnType<typeof buildBetterAuth>;

export interface AuthKit {
  /** better-auth's server API, for what the package does not wrap. */
  readonly api: BetterAuthInstance["api"];
  /** better-auth's fetch handler for the routes under `/api/auth`. */
  readonly handler: (request: Request) => Promise<Response>;
  /** The session's user from those headers, or null without a cookie, with an invalid one or after expiry. */
  currentUser(headers: Headers): Promise<SessionUser | null>;
  /**
   * Creates a guest and its session; the cookie comes back in `headers` (`Set-Cookie`) for whoever answers. Put any
   * sign-up limit in front of this call.
   */
  signInAnonymously(headers: Headers): Promise<{ user: SessionUser; headers: Headers }>;
}

/** Builds the auth instance; throws, without repeating any value, if an option or the environment is unsafe. */
export function createAuth<TDb extends AuthDatabase>(options: AuthKitOptions<TDb>): AuthKit {
  const auth = buildBetterAuth(options, options.env ?? process.env);
  return {
    api: auth.api,
    handler: async (request) => sameCodeErrorStatus(request, await auth.handler(request)),
    async currentUser(headers) {
      const result = await auth.api.getSession({ headers });
      if (!result) return null;
      return { id: result.user.id, isAnonymous: result.user.isAnonymous === true };
    },
    async signInAnonymously(headers) {
      const result = await auth.api.signInAnonymous({ headers, returnHeaders: true });
      return { user: { id: result.response.user.id, isAnonymous: true }, headers: result.headers };
    },
  };
}
