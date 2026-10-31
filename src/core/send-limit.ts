/**
 * The limits in front of better-auth, counted before it looks at anything, each with one 429 whatever the email and
 * whichever quota ran out (defaults in DEFAULT_LIMITS):
 * - the sign-in email: per email and per IP, per hour;
 * - checking the email code: per email per day and per IP per hour, right code or not;
 * - creating a guest: per IP and in total, per hour.
 */
import { APIError } from "better-auth/api";

import { RateLimitedError, type SendLimiter } from "../rate-limit/limiter.js";

interface LimitedRequest {
  headers?: Headers | undefined;
  body?: unknown;
}

/** The body's email, lower case and trimmed, or null if there is none to read. */
function normalisedEmail(body: unknown): string | null {
  const raw = (body as { email?: unknown } | undefined)?.email;
  return typeof raw === "string" && raw.trim() ? raw.trim().toLowerCase() : null;
}

/** The 429 with `Retry-After`: one body for every case. */
export function rateLimitedError(retryAfterSeconds: number): APIError {
  return new APIError(
    "TOO_MANY_REQUESTS",
    { code: "TOO_MANY_REQUESTS", message: "Too many attempts; try again later." },
    { "Retry-After": String(retryAfterSeconds), "Cache-Control": "no-store" },
  );
}

async function spendOr429(spend: () => Promise<void>): Promise<void> {
  try {
    await spend();
  } catch (error) {
    if (error instanceof RateLimitedError) throw rateLimitedError(error.retryAfterSeconds);
    throw error;
  }
}

/** Spends the send quotas; throws the 429 if any is exhausted. */
export function limitSend(limiter: SendLimiter, request: LimitedRequest): Promise<void> {
  return spendOr429(() => limiter.beforeMagicLinkSend(request.headers ?? new Headers(), normalisedEmail(request.body)));
}

/** Spends the code-check quotas; the closed body (email-code-route.ts) has already guaranteed an email. */
export function limitCodeCheck(limiter: SendLimiter, request: LimitedRequest): Promise<void> {
  const email = normalisedEmail(request.body) ?? "";
  return spendOr429(() => limiter.beforeCodeCheck(request.headers ?? new Headers(), email));
}

/** Spends the guest sign-up quotas; throws the 429 before any guest user exists. */
export function limitGuestSignUp(limiter: SendLimiter, request: LimitedRequest): Promise<void> {
  return spendOr429(() => limiter.beforeGuestSignUp(request.headers ?? new Headers()));
}
