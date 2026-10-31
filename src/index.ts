export { createAuth, type AuthKit, type BetterAuthInstance } from "./core/create-auth.js";
export { CODE_NOT_VALID } from "./core/email-code-route.js";
export {
  DEFAULT_LIMITS,
  EMAIL_CODE,
  MAGIC_LINK_EXPIRES_IN_SECONDS,
  SESSION,
  type Limits,
} from "./core/policies.js";
export { ALWAYS_OPEN_ROUTES, EMAIL_ROUTES, type AuthRoute } from "./core/route-allowlist.js";
export {
  AUTH_BASE_PATH,
  EMAIL_CODE_VERIFY_PATH,
  GUEST_SIGN_UP_PATH,
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
export { LIMIT_VARIABLES, limitsFromEnv } from "./rate-limit/config.js";
export type { MailContent, Mailer, OutgoingMail, SendResult } from "./mail/mailer.js";
