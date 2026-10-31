/**
 * Around `POST /sign-in/email-otp`, the only `emailOTP` route left open:
 * - in front, a closed body (closed-body.ts): exactly `email` and `otp`, both strings;
 * - behind, one error: wrong (`INVALID_OTP`), expired (`OTP_EXPIRED`) or exhausted (`TOO_MANY_ATTEMPTS`) all answer
 *   the same 400 with the same body, so the answer does not say whether a code was requested, expired or ran out.
 * Every other `emailOTP` route answers 404 over HTTP (route-allowlist.ts): the code is only sent with the magic link.
 * Neither the code nor the email is written to any log.
 */
import { APIError } from "better-auth/api";

import { EMAIL_CODE_VERIFY_PATH } from "./routes.js";

/** The single error of checking the code. */
export const CODE_NOT_VALID = "OTP_NOT_VALID";

const UNIFIED = new Set(["INVALID_OTP", "OTP_EXPIRED", "TOO_MANY_ATTEMPTS"]);
const NO_STORE = { "Cache-Control": "no-store" };

function errorCode(returned: unknown): string | undefined {
  if (!(returned instanceof APIError)) return undefined;
  const code: unknown = returned.body?.code;
  return typeof code === "string" ? code : undefined;
}

/**
 * Rewrites the three code errors into one; anything else goes through untouched. An after hook can replace the body but
 * not the status better-auth already chose (403 for an exhausted code), so `sameCodeErrorStatus` finishes the job on
 * the HTTP response.
 */
export function unifyCodeErrors(returned: unknown): void {
  const code = errorCode(returned);
  if (code === undefined || !UNIFIED.has(code)) return;
  throw new APIError("BAD_REQUEST", { code: CODE_NOT_VALID }, NO_STORE);
}

const isCodeRoute = (request: Request) => new URL(request.url).pathname.endsWith(EMAIL_CODE_VERIFY_PATH);

/** The HTTP answer of a unified code error, always 400 with the same body. */
export async function sameCodeErrorStatus(request: Request, response: Response): Promise<Response> {
  if (response.status !== 403 || !isCodeRoute(request)) return response;
  let code: unknown;
  try {
    code = ((await response.clone().json()) as { code?: unknown } | null)?.code;
  } catch {
    return response;
  }
  if (code !== CODE_NOT_VALID) return response;
  return Response.json({ code: CODE_NOT_VALID }, { status: 400, headers: NO_STORE });
}

