/**
 * The send limit: fixed-window counters in `rate_limit_counter`, with no worker.
 *
 * - Each attempt is ONE atomic statement (`INSERT … ON CONFLICT … DO UPDATE SET hits = hits + 1 RETURNING hits`), with
 *   the window taken from the database's `now()`; it passes while `hits` does not exceed the limit. The same statement
 *   purges at most 100 rows of windows that started more than 3 days ago (the longest window is one hour). `skip
 *   locked`: two purges at once neither wait for nor deadlock each other.
 * - It runs on its own statement, outside any transaction of the caller, so a rollback can never take an attempt back.
 * - A check spends ALL its quotas before deciding, and throws the same `RateLimitedError` whichever one ran out: the
 *   429 does not depend on the email or on which quota it was.
 * - The key is an HMAC-SHA256 of the subject (the normalised IP address of client-ip.ts, or the email) with a key
 *   derived from the auth secret and a fixed label (no new secret), truncated to 16 bytes.
 */
import { createHmac } from "node:crypto";

import { sql, type SQLWrapper } from "drizzle-orm";

import { SEND_LIMITS } from "../core/policies.js";
import { RATE_LIMIT_KEY_BYTES, type RateLimitScope } from "../schema/rate-limit-counter.js";

import { clientIpSubject, NO_IP } from "./client-ip.js";

/** Derivation label: changing it invalidates every counter, not any secret. */
const KEY_LABEL = "auth-kit/rate-limit/v1";

/** Anything that runs a raw statement: a Drizzle Postgres database (postgres-js, node-postgres or PGlite). */
export interface SqlExecutor {
  execute(query: SQLWrapper): PromiseLike<unknown>;
}

/** The 429: the same message and properties whichever quota ran out. Carries how long to wait and nothing else. */
export class RateLimitedError extends Error {
  readonly status = 429;

  constructor(readonly retryAfterSeconds: number) {
    super("too many attempts");
    this.name = "RateLimitedError";
  }
}

/** The stored key of a subject: HMAC-SHA256 with the derived key, truncated to 16 bytes. */
export function rateLimitKey(secret: string, subject: string): Buffer {
  const derived = createHmac("sha256", secret).update(KEY_LABEL).digest();
  return createHmac("sha256", derived).update(subject).digest().subarray(0, RATE_LIMIT_KEY_BYTES);
}

interface Attempt {
  scope: RateLimitScope;
  subject: string;
  limit: number;
  windowSeconds: number;
}

interface CounterRow {
  hits: number;
  retry_after: number;
}

/** postgres-js returns the rows as an array; node-postgres and PGlite wrap them in `{ rows }`. */
function firstRow(result: unknown): CounterRow | undefined {
  const rows = Array.isArray(result) ? result : (result as { rows?: unknown[] } | null)?.rows;
  return rows?.[0] as CounterRow | undefined;
}

export interface SendLimiterOptions {
  db: SqlExecutor;
  secret: string;
  /** How many trusted proxies sit in front: the client is the n-th `X-Forwarded-For` entry from the right. */
  trustedProxyHops: number;
  log: (line: string) => void;
}

export interface SendLimiter {
  /**
   * Spends the send quotas: per email (already normalised; `null` if it could not be read, then only the IP counts)
   * and per IP. Throws `RateLimitedError` if any is exhausted.
   */
  beforeMagicLinkSend(headers: Headers, email: string | null): Promise<void>;
}

export function createSendLimiter(options: SendLimiterOptions): SendLimiter {
  /** Counts one attempt and says whether it passes; if not, how many seconds until the next window. */
  async function hit(attempt: Attempt): Promise<{ allowed: boolean; retryAfterSeconds: number }> {
    const window = sql.raw(`interval '${attempt.windowSeconds} seconds'`);
    const key = rateLimitKey(options.secret, attempt.subject);
    const result = await options.db.execute(sql`
      with purged as (
        delete from rate_limit_counter where ctid in (
          select ctid from rate_limit_counter where window_start < now() - interval '3 days'
          limit 100 for update skip locked)
      ), counted as (
        insert into rate_limit_counter (scope, key, window_start, hits)
        values (${attempt.scope}, ${key}, date_bin(${window}, now(), timestamptz 'epoch'), 1)
        on conflict (scope, key, window_start) do update set hits = rate_limit_counter.hits + 1
        returning hits, window_start
      )
      select hits, greatest(1, ceil(extract(epoch from (window_start + ${window} - now()))))::int as retry_after
      from counted`);
    const row = firstRow(result);
    if (!row) throw new Error("rate limit: the counter returned no row");
    return { allowed: row.hits <= attempt.limit, retryAfterSeconds: row.retry_after };
  }

  /** Spends every attempt, in order and one by one, and throws if any went over its limit. */
  async function spend(attempts: readonly Attempt[]): Promise<void> {
    let retryAfterSeconds = 0;
    for (const attempt of attempts) {
      const result = await hit(attempt);
      if (!result.allowed) retryAfterSeconds = Math.max(retryAfterSeconds, result.retryAfterSeconds);
    }
    if (retryAfterSeconds > 0) throw new RateLimitedError(retryAfterSeconds);
  }

  function ipSubject(headers: Headers): string {
    const subject = clientIpSubject(headers, options.trustedProxyHops);
    // Neither the address nor any piece of the header goes to the log.
    if (subject === NO_IP) options.log("rate limit: X-Forwarded-For missing or unreadable; counted in the shared no-ip bucket");
    return subject;
  }

  return {
    beforeMagicLinkSend(headers, email) {
      const byIp: Attempt = {
        scope: "magic_link_ip",
        subject: ipSubject(headers),
        limit: SEND_LIMITS.perIp.hits,
        windowSeconds: SEND_LIMITS.perIp.windowSeconds,
      };
      if (email === null) return spend([byIp]);
      const byEmail: Attempt = {
        scope: "magic_link_email",
        subject: `email:${email}`,
        limit: SEND_LIMITS.perEmail.hits,
        windowSeconds: SEND_LIMITS.perEmail.windowSeconds,
      };
      return spend([byEmail, byIp]);
    },
  };
}
