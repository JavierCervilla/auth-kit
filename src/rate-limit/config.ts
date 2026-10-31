/**
 * The usage limits: Tercer Tiempo's defaults (DEFAULT_LIMITS), overridable by option or by environment. Each value
 * must be a positive integer; anything else is a start-up error that names the setting and never echoes the value.
 */
import { DEFAULT_LIMITS, type Limits } from "../core/policies.js";

type Env = Readonly<Record<string, string | undefined>>;

/** The environment variable of each limit: the same names as Tercer Tiempo. */
export const LIMIT_VARIABLES = {
  sendPerEmailPerHour: "RATE_LIMIT_MAGIC_LINK_EMAIL_PER_HOUR",
  sendPerIpPerHour: "RATE_LIMIT_MAGIC_LINK_IP_PER_HOUR",
  codeCheckPerEmailPerDay: "RATE_LIMIT_OTP_VERIFY_EMAIL_PER_DAY",
  codeCheckPerIpPerHour: "RATE_LIMIT_OTP_VERIFY_IP_PER_HOUR",
  guestSignUpPerIpPerHour: "RATE_LIMIT_ANON_SIGNUP_PER_HOUR",
  guestSignUpGlobalPerHour: "RATE_LIMIT_ANON_SIGNUP_GLOBAL_PER_HOUR",
} as const satisfies Record<keyof Limits, string>;

const LIMIT_NAMES = Object.keys(DEFAULT_LIMITS) as (keyof Limits)[];

function positiveInteger(raw: string, name: string): number {
  const value = Number(raw);
  if (!/^[1-9]\d*$/.test(raw) || !Number.isSafeInteger(value)) {
    throw new Error(`auth-kit: ${name} must be a positive integer`);
  }
  return value;
}

/** Reads the RATE_LIMIT_* variables; unset means the default. Throws naming the variable that is invalid. */
export function limitsFromEnv(env: Env): Limits {
  const limits: Record<string, number> = { ...DEFAULT_LIMITS };
  for (const name of LIMIT_NAMES) {
    const raw = env[LIMIT_VARIABLES[name]];
    if (raw !== undefined) limits[name] = positiveInteger(raw, LIMIT_VARIABLES[name]);
  }
  return limits as Limits;
}

/** The `limits` option merged over the defaults; throws naming the limit that is not a positive integer. */
export function resolveLimits(overrides: Partial<Limits> | undefined): Limits {
  const limits = { ...DEFAULT_LIMITS, ...overrides };
  for (const name of LIMIT_NAMES) {
    if (!Number.isSafeInteger(limits[name]) || limits[name] < 1) {
      throw new Error(`auth-kit: limits.${name} must be a positive integer`);
    }
  }
  return limits;
}
