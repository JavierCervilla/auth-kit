/**
 * The fixed sign-in guarantees. They are constants, not options, so no consumer weakens them by accident
 * (docs/design.md, «Fixed policies»), plus the usage limits' defaults, which are configurable. Values proven in
 * production in Tercer Tiempo.
 */

const MINUTE_SECONDS = 60;
const HOUR_SECONDS = 60 * MINUTE_SECONDS;
const DAY_SECONDS = 24 * HOUR_SECONDS;

/** The limiter's windows (rate-limit/limiter.ts): the limits count per hour or per day. */
export const LIMIT_WINDOWS = { hourSeconds: HOUR_SECONDS, daySeconds: DAY_SECONDS } as const;

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

/**
 * The usage limits' defaults (Tercer Tiempo's values). Unlike the guarantees above they are configurable: `createAuth`
 * takes `limits` (merged over these) and `limitsFromEnv` reads them from RATE_LIMIT_* variables. Windows are fixed.
 */
export const DEFAULT_LIMITS = {
  /** Sends of the sign-in email per email address per hour. */
  sendPerEmailPerHour: 5,
  /** Sends of the sign-in email per IP address per hour. */
  sendPerIpPerHour: 20,
  /** Checks of the email code per email address per day, spent whether the code is right or not. */
  codeCheckPerEmailPerDay: 10,
  /** Checks of the email code per IP address per hour. */
  codeCheckPerIpPerHour: 30,
  /** Guest sign-ups per IP address per hour. */
  guestSignUpPerIpPerHour: 30,
  /** Guest sign-ups per hour in total. */
  guestSignUpGlobalPerHour: 1000,
} as const satisfies Record<string, number>;

/** The usage limits, as `createAuth` uses them. */
export type Limits = { readonly [K in keyof typeof DEFAULT_LIMITS]: number };
