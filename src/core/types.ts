/** The public option and hook types of `createAuth`. */
import type { MailContent, Mailer } from "../mail/mailer.js";
import type { SqlExecutor } from "../rate-limit/limiter.js";

import type { Env } from "./settings.js";

/** A Drizzle Postgres database (postgres-js, node-postgres or PGlite) that includes `authTables`. */
export interface AuthDatabase extends SqlExecutor {
  transaction<T>(run: (tx: unknown) => Promise<T>): Promise<T>;
}

/** The transaction type of that database, as its `transaction` callback receives it. */
export type TransactionOf<TDb extends AuthDatabase> = Parameters<Parameters<TDb["transaction"]>[0]>[0];

/**
 * Why a guest cannot become that account. The magic link redirects to the page's `errorCallbackURL` (or `callbackURL`,
 * if it is the app's own) with `error=<code>` and each detail as a query parameter; the email code answers 409 with
 * `{ code, message, ...details }`.
 */
export interface GuestToAccountRefusal {
  code: string;
  message?: string;
  details?: Readonly<Record<string, string>>;
}

/** A guest whose email has just been proven, before anything happens. `accountUserId` is null for a new email. */
export interface GuestToAccountRequest {
  guestUserId: string;
  email: string;
  accountUserId: string | null;
}

/** The guest and the account it is becoming, once better-auth has opened the account's session. */
export interface GuestToAccount {
  guestUserId: string;
  accountUserId: string;
}

/** The project's sign-in email: the 6-digit code and the link go in the same email. */
export interface SignInEmail {
  /** `locale` is the first tag of the request's `Accept-Language`, or null. */
  render(link: string, code: string, locale: string | null): MailContent;
}

export interface AuthKitOptions<TDb extends AuthDatabase> {
  db: TDb;
  /** Exactly the app's origin (scheme://host[:port]). */
  baseURL: string;
  /** At least 32 characters, from the environment; never logged. Also keys the send-limit counters. */
  secret: string;
  /** Extra origins allowed to call the auth routes, each exactly an origin, no wildcards. */
  trustedOrigins?: readonly string[];
  /** Off or absent: sign-in by email is off and guests still work. */
  mailer?: Mailer;
  email: SignInEmail;
  /**
   * Moves the guest's data to the account, inside one transaction, before better-auth deletes the guest user. Returning
   * a refusal rolls the transaction back, deletes the account's new session and puts the guest's cookie back.
   */
  onGuestToAccount: (tx: TransactionOf<TDb>, link: GuestToAccount) => Promise<GuestToAccountRefusal | void>;
  /**
   * Optional: refuses a link before the magic link or the code is consumed, so a refusal leaves no session, no cookie
   * and an unused token. Return null to let it through.
   */
  guardGuestToAccount?: (request: GuestToAccountRequest) => Promise<GuestToAccountRefusal | null>;
  /** Trusted reverse proxies in front of the app (default 1): the client is that `X-Forwarded-For` entry from the right. */
  trustedProxyHops?: number;
  /** The environment better-auth also reads (NODE_ENV, BETTER_AUTH_TELEMETRY, …); default `process.env`. */
  env?: Env;
  /** Where operational lines go (default `console.warn`); they never carry an email address. */
  log?: (line: string) => void;
}

/** The user of a session: a guest (`isAnonymous`) or an account. */
export interface SessionUser {
  id: string;
  isAnonymous: boolean;
}
