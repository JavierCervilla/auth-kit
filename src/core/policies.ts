/**
 * The fixed sign-in policies. They are constants, not options, so no consumer weakens them by accident
 * (docs/design.md, «Fixed policies»). Values proven in production in Tercer Tiempo.
 */

const MINUTE_SECONDS = 60;
const HOUR_SECONDS = 60 * MINUTE_SECONDS;
const DAY_SECONDS = 24 * HOUR_SECONDS;

/** A magic link is valid for 10 minutes and can be used once. */
export const MAGIC_LINK_EXPIRES_IN_SECONDS = 10 * MINUTE_SECONDS;

/** The email code: 6 digits, the same expiry as the link, 3 attempts. */
export const EMAIL_CODE = {
  length: 6,
  expiresInSeconds: MAGIC_LINK_EXPIRES_IN_SECONDS,
  allowedAttempts: 3,
} as const;

/** A session lasts 180 days from its last use and is renewed at most once a day. */
export const SESSION = {
  expiresInSeconds: 180 * DAY_SECONDS,
  updateAgeSeconds: DAY_SECONDS,
} as const;

/** Sends of the sign-in email: 5 per hour per email address and 20 per hour per IP address. */
export const SEND_LIMITS = {
  perEmail: { hits: 5, windowSeconds: HOUR_SECONDS },
  perIp: { hits: 20, windowSeconds: HOUR_SECONDS },
} as const;
