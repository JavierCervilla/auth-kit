/**
 * Validation of what `createAuth` is given: the secret, the base URL and the extra trusted origins, plus the two
 * environment variables better-auth reads on its own. Every error names the option, never its value: a secret or a
 * credential in a URL must not reach a log.
 */

/** The environment as a plain map, injected so the checks are testable. */
export type Env = Readonly<Record<string, string | undefined>>;

/** What `createAuth` derives from the validated options. */
export interface AuthSettings {
  secureCookies: boolean;
  /** Origins accepted besides the base URL's own, without duplicates and without the base URL's origin. */
  trustedOrigins: string[];
}

/** Minimum secret length: 32 characters (`openssl rand -base64 32` gives 44). */
export const MIN_SECRET_LENGTH = 32;

function assertSecret(secret: string): void {
  if (!secret) throw new Error("auth-kit: secret is empty");
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error(`auth-kit: secret is shorter than ${MIN_SECRET_LENGTH} characters`);
  }
}

function parseHttpUrl(raw: string, name: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`auth-kit: ${name} is not a valid URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error(`auth-kit: ${name} must be http(s)`);
  return url;
}

/**
 * The base URL as WRITTEN must be exactly the origin, with or without the trailing slash. A path would leak into every
 * URL better-auth builds; credentials would end up in links; a space or upper case is fixed by `new URL` here but not by
 * better-auth; a trailing DNS dot breaks redirects between hosts.
 */
export function parseBaseURL(raw: string): URL {
  const url = parseHttpUrl(raw, "baseURL");
  if ((raw !== url.origin && raw !== `${url.origin}/`) || url.hostname.endsWith(".")) {
    throw new Error(
      "auth-kit: baseURL must be just the origin (scheme://host[:port]), written as is: no path, query, fragment, " +
        "credentials, spaces, upper case or trailing dot",
    );
  }
  return url;
}

/**
 * Each entry, as written, must be exactly one origin. better-auth also takes `*` and `?` as wildcards, so a wildcard
 * host is refused outright: every trusted origin is spelled out.
 */
function parseTrustedOrigin(entry: string, label: string): string {
  const url = parseHttpUrl(entry, label);
  if (url.hostname.includes("*")) throw new Error(`auth-kit: ${label} cannot have a wildcard in the host`);
  if (entry !== url.origin) throw new Error(`auth-kit: ${label} must be just the origin (scheme://host[:port])`);
  return url.origin;
}

function uniqueOrigins(entries: readonly string[], baseOrigin: string, name: string): string[] {
  const origins = new Set<string>();
  entries.forEach((entry, index) => {
    const origin = parseTrustedOrigin(entry, `${name} entry ${index + 1}`);
    if (origin !== baseOrigin) origins.add(origin);
  });
  return [...origins];
}

/**
 * better-auth 1.7.10 turns telemetry on when BETTER_AUTH_TELEMETRY is anything but empty, `0` or `false`, even with
 * `telemetry.enabled: false`. Only unset, empty or `0` are accepted, so the rule is one and does not depend on how the
 * library parses it.
 */
export function assertTelemetryOff(env: Env): void {
  const value = env.BETTER_AUTH_TELEMETRY;
  if (value === undefined || value === "" || value === "0") return;
  throw new Error("auth-kit: BETTER_AUTH_TELEMETRY must be unset, empty or 0: better-auth telemetry stays off");
}

/**
 * better-auth also reads BETTER_AUTH_TRUSTED_ORIGINS by itself, raw (no trimming, wildcards honoured). If it is set,
 * it must pass the same rules as the `trustedOrigins` option.
 */
function assertEnvTrustedOrigins(env: Env, baseOrigin: string): void {
  const raw = env.BETTER_AUTH_TRUSTED_ORIGINS;
  if (raw === undefined || raw.trim() === "") return;
  uniqueOrigins(raw.split(","), baseOrigin, "BETTER_AUTH_TRUSTED_ORIGINS");
}

export interface SettingsInput {
  secret: string;
  baseURL: string;
  trustedOrigins?: readonly string[] | undefined;
  env: Env;
}

/**
 * Validates the options and the environment better-auth reads; throws without repeating any value. The session cookie is
 * `secure` in production always, and elsewhere when the base URL is https (local development over http://localhost,
 * where some browsers would not keep a Secure cookie).
 */
export function resolveSettings(input: SettingsInput): AuthSettings {
  assertTelemetryOff(input.env);
  assertSecret(input.secret);
  const url = parseBaseURL(input.baseURL);
  assertEnvTrustedOrigins(input.env, url.origin);
  return {
    secureCookies: input.env.NODE_ENV === "production" || url.protocol === "https:",
    trustedOrigins: uniqueOrigins(input.trustedOrigins ?? [], url.origin, "trustedOrigins"),
  };
}
