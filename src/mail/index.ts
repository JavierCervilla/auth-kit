export type { MailContent, Mailer, OutgoingMail, SendResult } from "./mailer.js";
export {
  describeMailConfig,
  mailConfigFromEnv,
  resendSmtpMailer,
  type MailConfig,
  type MailerDeps,
  type MailMessage,
  type MailTransport,
  type SmtpOptions,
} from "./resend-smtp.js";
