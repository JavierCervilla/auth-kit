export { createAuth, type AuthKit, type BetterAuthInstance } from "./core/create-auth.js";
export { CODE_NOT_VALID } from "./core/email-code-route.js";
export { EMAIL_CODE, MAGIC_LINK_EXPIRES_IN_SECONDS, SEND_LIMITS, SESSION } from "./core/policies.js";
export {
  AUTH_BASE_PATH,
  EMAIL_CODE_VERIFY_PATH,
  MAGIC_LINK_VERIFY_PATH,
  SEND_SIGN_IN_EMAIL_PATH,
} from "./core/routes.js";
export { MIN_SECRET_LENGTH, type Env } from "./core/settings.js";
export type {
  AuthDatabase,
  AuthKitOptions,
  GuestToAccount,
  GuestToAccountRefusal,
  GuestToAccountRequest,
  SessionUser,
  SignInEmail,
  TransactionOf,
} from "./core/types.js";
export type { MailContent, Mailer, OutgoingMail, SendResult } from "./mail/mailer.js";
