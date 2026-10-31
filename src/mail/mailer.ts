/** The mail seam: `createAuth` sends the sign-in email through any `Mailer`. */

/** One email, already rendered. */
export interface MailContent {
  subject: string;
  text: string;
  html: string;
}

export interface OutgoingMail extends MailContent {
  to: string;
}

export type SendResult = { ok: true } | { ok: false; reason: "not_configured" | "send_failed" };

export interface Mailer {
  /** Off means sign-in by email is off: `createAuth` registers neither the magic link nor the email code. */
  readonly configured: boolean;
  /** Never throws; a failure is a typed result. Implementations must not log the recipient or the content. */
  send(mail: OutgoingMail): Promise<SendResult>;
}
