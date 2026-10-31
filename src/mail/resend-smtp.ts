/**
 * The Resend relay over SMTP with nodemailer: `smtp.resend.com`, port 587 with mandatory STARTTLS, user `resend` and the
 * Resend API key as password. Changing relay is changing variables. 587 and not 465: Hetzner blocks outbound 25 and 465
 * by default, and over 465 the link never left.
 *
 * On if and only if SMTP_PASS and MAIL_FROM have a value (an empty `SMTP_PASS=`, as hosting panels pre-fill it, is
 * off). Off is not an error: nothing is sent, sending does not throw and answers `not_configured`, and creating the
 * mailer logs one line with the NAME of what is missing, never a value. A failed send answers `send_failed` without
 * throwing. No log line carries an email address. The variables are read once, when the mailer is created.
 */
import nodemailer from "nodemailer";

import type { Mailer, OutgoingMail } from "./mailer.js";

type Env = Readonly<Record<string, string | undefined>>;

export type MailConfig =
  | { configured: true; host: string; port: number; user: string; pass: string; from: string }
  | { configured: false; missing: readonly string[] };

const RESEND = { host: "smtp.resend.com", port: 587, user: "resend" } as const;
const MAX_PORT = 65_535;
const IMPLICIT_TLS_PORT = 465;

/** A value with more than spaces, or `undefined`. */
function filled(raw: string | undefined): string | undefined {
  const trimmed = raw?.trim();
  return trimmed ? trimmed : undefined;
}

function parsePort(raw: string | undefined): number | null {
  const text = filled(raw);
  if (text === undefined) return RESEND.port;
  if (!/^\d{1,5}$/.test(text)) return null;
  const port = Number(text);
  return port >= 1 && port <= MAX_PORT ? port : null;
}

export function mailConfigFromEnv(env: Env): MailConfig {
  const pass = filled(env.SMTP_PASS);
  const from = filled(env.MAIL_FROM);
  const port = parsePort(env.SMTP_PORT);
  const missing = [
    ...(pass === undefined ? ["SMTP_PASS"] : []),
    ...(from === undefined ? ["MAIL_FROM"] : []),
    // A port that is not a number turns mail off instead of failing the start: mail is optional.
    ...(port === null ? ["SMTP_PORT"] : []),
  ];
  if (pass === undefined || from === undefined || port === null) return { configured: false, missing };
  return {
    configured: true,
    host: filled(env.SMTP_HOST) ?? RESEND.host,
    port,
    user: filled(env.SMTP_USER) ?? RESEND.user,
    pass,
    from,
  };
}

/** The start-up line: what is missing, by name. Never a value. */
export function describeMailConfig(config: MailConfig): string {
  if (config.configured) return "mail: on (sign-in email over SMTP)";
  return `mail: off, missing or invalid ${config.missing.join(", ")}; sign-in by email is not offered`;
}

export interface SmtpOptions {
  host: string;
  port: number;
  /** Implicit TLS (465). */
  secure: boolean;
  /** On any other port, mandatory STARTTLS: never in clear. */
  requireTLS: boolean;
  auth: { user: string; pass: string };
}

export interface MailMessage extends OutgoingMail {
  from: string;
}

export interface MailTransport {
  sendMail(message: MailMessage): Promise<unknown>;
}

export interface MailerDeps {
  /** For tests: no network. */
  createTransport?: (options: SmtpOptions) => MailTransport;
  log?: (line: string) => void;
}

const nodemailerTransport = (options: SmtpOptions): MailTransport => nodemailer.createTransport(options);

function offMailer(log: (line: string) => void): Mailer {
  return {
    configured: false,
    send: () => {
      log("mail: off, sign-in email not sent");
      return Promise.resolve({ ok: false, reason: "not_configured" });
    },
  };
}

/** The Resend SMTP mailer from the environment (SMTP_PASS, MAIL_FROM; optional SMTP_HOST, SMTP_PORT, SMTP_USER). */
export function resendSmtpMailer(env: Env, deps: MailerDeps = {}): Mailer {
  const log = deps.log ?? ((line: string) => console.warn(line));
  const config = mailConfigFromEnv(env);
  log(describeMailConfig(config));
  if (!config.configured) return offMailer(log);

  const transport = (deps.createTransport ?? nodemailerTransport)({
    host: config.host,
    port: config.port,
    secure: config.port === IMPLICIT_TLS_PORT,
    requireTLS: true,
    auth: { user: config.user, pass: config.pass },
  });
  return {
    configured: true,
    send: async (mail) => {
      try {
        await transport.sendMail({ from: config.from, ...mail });
        return { ok: true };
      } catch (error) {
        // The relay's message may carry the recipient: only the error's type.
        log(`mail: sending the sign-in email failed (${error instanceof Error ? error.name : "unknown"})`);
        return { ok: false, reason: "send_failed" };
      }
    },
  };
}
