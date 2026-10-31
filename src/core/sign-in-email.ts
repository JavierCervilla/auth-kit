/**
 * Sign-in by email, only with the mailer on: one email carrying the 6-digit code (`emailOTP`) and the magic link.
 * - Magic link: single use (the plugin consumes the token atomically), 10 minutes, and only the token's hash in
 *   `verification`. A failed send is a typed 503, «could not send», whether the email exists or not (the plugin does not
 *   look the email up when sending), and without the email in any log.
 * - Code: created by the same send, same expiry constant as the link, 3 attempts, single use; asking again invalidates
 *   the previous one. Stored as its hash (the same function, which the guard recomputes), and its identifier hashed too
 *   (`storeIdentifier` in create-auth.ts). Its own send route stays closed (email-code-route.ts): `sendVerificationOTP`
 *   exists only because the plugin requires it, and fails if anything reaches it.
 */
import { APIError } from "better-auth/api";
import { emailOTP } from "better-auth/plugins/email-otp";
import { magicLink } from "better-auth/plugins/magic-link";

import type { Mailer } from "../mail/mailer.js";

import { EMAIL_CODE, MAGIC_LINK_EXPIRES_IN_SECONDS } from "./policies.js";
import { hashToken } from "./token-hash.js";
import type { SignInEmail } from "./types.js";

/** Creates the email's code for that address (`createVerificationOTP`, server only) and returns it. */
export type CreateSignInCode = (email: string) => Promise<string>;

/** The first language tag of `Accept-Language`, or null. */
export function localeOf(headers: Headers | undefined): string | null {
  const tag = headers?.get("accept-language")?.split(",")[0]?.split(";")[0]?.trim();
  return tag ? tag : null;
}

const notSent = () =>
  new APIError("SERVICE_UNAVAILABLE", {
    code: "MAGIC_LINK_NOT_SENT",
    message: "The sign-in email could not be sent; try again later.",
  });

export function signInEmailPlugins(mailer: Mailer, email: SignInEmail, createSignInCode: CreateSignInCode) {
  return [
    emailOTP({
      otpLength: EMAIL_CODE.length,
      expiresIn: EMAIL_CODE.expiresInSeconds,
      allowedAttempts: EMAIL_CODE.allowedAttempts,
      storeOTP: { hash: (otp) => Promise.resolve(hashToken(otp)) },
      disableSignUp: false,
      sendVerificationOTP: () => Promise.reject(new Error("the code is only sent together with the magic link")),
    }),
    magicLink({
      expiresIn: MAGIC_LINK_EXPIRES_IN_SECONDS,
      // The same SHA-256 as its "hashed" option, computed here so the guest-to-account guard finds the row.
      storeToken: { type: "custom-hasher", hash: (token) => Promise.resolve(hashToken(token)) },
      sendMagicLink: async ({ email: to, url }, ctx) => {
        const code = await createSignInCode(to);
        const result = await mailer.send({ to, ...email.render(url, code, localeOf(ctx?.headers)) });
        if (!result.ok) throw notSent();
      },
    }),
  ];
}
