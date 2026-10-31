/** The better-auth paths the package acts on, relative to the auth base path. */
export const AUTH_BASE_PATH = "/api/auth";

/** Ask for the sign-in email (magic link and code); the send limit runs in front of it. */
export const SEND_SIGN_IN_EMAIL_PATH = "/sign-in/magic-link";

/** Open the magic link. */
export const MAGIC_LINK_VERIFY_PATH = "/magic-link/verify";

/** Check the code from the same email: the only `emailOTP` route that stays open. */
export const EMAIL_CODE_VERIFY_PATH = "/sign-in/email-otp";
