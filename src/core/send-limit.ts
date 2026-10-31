/**
 * The send limit in front of the sign-in email: 5 per hour per email and 20 per hour per IP (SEND_LIMITS), counted
 * before better-auth looks at the email, with the same 429 whether the email exists or not and whichever quota ran out.
 */
import { APIError } from "better-auth/api";

import { RateLimitedError, type SendLimiter } from "../rate-limit/limiter.js";

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

/** Spends the send quotas; throws the 429 if any is exhausted. */
export async function limitSend(
  limiter: SendLimiter,
  request: { headers?: Headers | undefined; body?: unknown },
): Promise<void> {
  try {
    await limiter.beforeMagicLinkSend(request.headers ?? new Headers(), normalisedEmail(request.body));
  } catch (error) {
    if (error instanceof RateLimitedError) throw rateLimitedError(error.retryAfterSeconds);
    throw error;
  }
}
