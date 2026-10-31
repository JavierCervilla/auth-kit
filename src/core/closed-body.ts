/**
 * Closed request bodies for the two routes that create users. Whatever better-auth would accept beyond them (`name`,
 * `image`, `metadata`, any extra field) never reaches it: a third party must not choose what is written on the user
 * created when the email's owner opens the link or types the code. Checked before any limit, so a refused body spends
 * no quota.
 */
import { APIError } from "better-auth/api";

const NO_STORE = { "Cache-Control": "no-store" };

/** Fields of `POST /sign-in/magic-link`: the email, required, and the callback URLs better-auth validates itself. */
const SEND_REQUIRED = ["email"] as const;
const SEND_OPTIONAL = ["callbackURL", "errorCallbackURL", "newUserCallbackURL"] as const;

/** Fields of `POST /sign-in/email-otp`, both required. */
const CODE_REQUIRED = ["email", "otp"] as const;

interface ClosedBodyRequest {
  request?: Request | undefined;
  body?: unknown;
}

/** True for `application/json`, with or without parameters, and nothing that merely contains the words. */
function isJson(request: Request | undefined): boolean {
  const type = request?.headers.get("content-type") ?? "application/json";
  return (type.split(";")[0] ?? "").trim().toLowerCase() === "application/json";
}

function hasOnly(body: unknown, required: readonly string[], optional: readonly string[]): boolean {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return false;
  const fields = body as Record<string, unknown>;
  const allowed = new Set([...required, ...optional]);
  if (Object.keys(fields).some((key) => !allowed.has(key))) return false;
  if (required.some((key) => !(key in fields))) return false;
  return Object.values(fields).every((value) => typeof value === "string");
}

function assertClosed(ctx: ClosedBodyRequest, required: readonly string[], optional: readonly string[]): void {
  if (isJson(ctx.request) && hasOnly(ctx.body, required, optional)) return;
  throw new APIError("BAD_REQUEST", { code: "BAD_REQUEST", message: "Invalid body." }, NO_STORE);
}

/** Throws the 400 unless the request is JSON with `email` and, optionally, the callback URLs, all strings. */
export function assertClosedSendBody(ctx: ClosedBodyRequest): void {
  assertClosed(ctx, SEND_REQUIRED, SEND_OPTIONAL);
}

/** Throws the 400 unless the request is JSON with exactly `{ email: string, otp: string }`. */
export function assertClosedCodeBody(ctx: ClosedBodyRequest): void {
  assertClosed(ctx, CODE_REQUIRED, []);
}
