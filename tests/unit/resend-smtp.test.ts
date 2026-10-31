// Mail over Resend's SMTP, degrading to off. No network: the transport is injected and a real one is never created.
import { describe, expect, it } from "vitest";

import {
  describeMailConfig,
  mailConfigFromEnv,
  resendSmtpMailer,
  type MailMessage,
  type SmtpOptions,
} from "../../src/mail/index.js";

const PASS = "re_test-key-0123";
const FULL = { SMTP_PASS: PASS, MAIL_FROM: "no-reply@example.test" };
const LINK = "https://app.example/api/auth/magic-link/verify?token=secret-token-123";
const TO = "someone@example.test";
const CODE = "482913";
const MAIL = { to: TO, subject: `${CODE} is your code`, text: `${CODE}\n${LINK}`, html: `<a href="${LINK}">${CODE}</a>` };

function harness(env: Record<string, string | undefined>) {
  const lines: string[] = [];
  const sent: MailMessage[] = [];
  const created: SmtpOptions[] = [];
  let fail = false;
  const mailer = resendSmtpMailer(env, {
    log: (line) => lines.push(line),
    createTransport: (options) => {
      created.push(options);
      return {
        sendMail: (message) => {
          if (fail) return Promise.reject(new Error(`550 rejected for ${message.to}`));
          sent.push(message);
          return Promise.resolve({});
        },
      };
    },
  });
  return { mailer, lines, sent, created, failNext: () => (fail = true) };
}

const expectNoSecrets = (lines: readonly string[]) => {
  const all = lines.join("\n");
  for (const secret of [TO, "secret-token-123", CODE, PASS]) expect(all).not.toContain(secret);
};

describe("mailConfigFromEnv: on if and only if SMTP_PASS and MAIL_FROM have a value", () => {
  it("nothing: off, and says what is missing", () => {
    expect(mailConfigFromEnv({})).toEqual({ configured: false, missing: ["SMTP_PASS", "MAIL_FROM"] });
  });

  it("an empty SMTP_PASS, as hosting panels pre-fill it, counts as not configured", () => {
    expect(mailConfigFromEnv({ ...FULL, SMTP_PASS: "" })).toEqual({ configured: false, missing: ["SMTP_PASS"] });
    expect(mailConfigFromEnv({ ...FULL, SMTP_PASS: "   " })).toEqual({ configured: false, missing: ["SMTP_PASS"] });
  });

  // 587 (STARTTLS) by default: Hetzner blocks outbound 25 and 465, and over 465 the link never left.
  it("with SMTP_PASS and MAIL_FROM, Resend's defaults on 587", () => {
    expect(mailConfigFromEnv(FULL)).toEqual({
      configured: true,
      host: "smtp.resend.com",
      port: 587,
      user: "resend",
      pass: PASS,
      from: "no-reply@example.test",
    });
  });

  it("SMTP_HOST, SMTP_PORT and SMTP_USER change the relay without touching code", () => {
    const config = mailConfigFromEnv({ ...FULL, SMTP_HOST: "smtp.other.test", SMTP_PORT: "2587", SMTP_USER: "u" });
    expect(config).toMatchObject({ configured: true, host: "smtp.other.test", port: 2587, user: "u" });
  });

  it.each(["abc", "0", "70000", "465x"])("SMTP_PORT=%s is invalid: off, without throwing", (port) => {
    expect(mailConfigFromEnv({ ...FULL, SMTP_PORT: port })).toEqual({ configured: false, missing: ["SMTP_PORT"] });
  });
});

describe("describeMailConfig: the start-up line names what is missing and no value", () => {
  it("off", () => {
    const line = describeMailConfig(mailConfigFromEnv({ SMTP_USER: "odd-user", MAIL_FROM: "x@example.test" }));
    expect(line).toContain("SMTP_PASS");
    expect(line).not.toContain("odd-user");
    expect(line).not.toContain("x@example.test");
  });

  it("on: without the key or the sender", () => {
    const line = describeMailConfig(mailConfigFromEnv(FULL));
    expect(line).not.toBe("");
    expect(line).not.toContain(PASS);
    expect(line).not.toContain(FULL.MAIL_FROM);
  });
});

describe("without a key: nothing is sent and nothing fails", () => {
  it("configured is false, no transport is created and sending does not throw", async () => {
    const h = harness({ SMTP_PASS: "" });
    expect(h.mailer.configured).toBe(false);
    await expect(h.mailer.send(MAIL)).resolves.toEqual({ ok: false, reason: "not_configured" });
    expect(h.created).toHaveLength(0);
    expect(h.sent).toHaveLength(0);
  });

  it("logs one line on creation with what is missing, and no email, link or code when asked to send", async () => {
    const h = harness({});
    expect(h.lines).toHaveLength(1);
    expect(h.lines[0]).toContain("SMTP_PASS");
    await h.mailer.send(MAIL);
    expectNoSecrets(h.lines);
  });
});

describe("with everything: Resend's transport, with TLS", () => {
  it("by default, 587 with mandatory STARTTLS and the key as password", () => {
    const h = harness(FULL);
    expect(h.mailer.configured).toBe(true);
    expect(h.created).toEqual([
      { host: "smtp.resend.com", port: 587, secure: false, requireTLS: true, auth: { user: "resend", pass: PASS } },
    ]);
  });

  it("port 465: implicit TLS", () => {
    expect(harness({ ...FULL, SMTP_PORT: "465" }).created[0]).toMatchObject({ port: 465, secure: true, requireTLS: true });
  });

  it("another port: mandatory STARTTLS, never in clear", () => {
    expect(harness({ ...FULL, SMTP_PORT: "2587" }).created[0]).toMatchObject({ port: 2587, secure: false, requireTLS: true });
  });

  it("sends the rendered email from MAIL_FROM to the recipient", async () => {
    const h = harness(FULL);
    await expect(h.mailer.send(MAIL)).resolves.toEqual({ ok: true });
    expect(h.sent).toEqual([{ from: FULL.MAIL_FROM, ...MAIL }]);
  });

  it("a failed send gives the typed result, does not throw, and the log has no email, link or code", async () => {
    const h = harness(FULL);
    h.failNext();
    await expect(h.mailer.send(MAIL)).resolves.toEqual({ ok: false, reason: "send_failed" });
    expectNoSecrets(h.lines);
  });

  it("the log of a good send has no email, link or code", async () => {
    const h = harness(FULL);
    await h.mailer.send(MAIL);
    expectNoSecrets(h.lines);
  });
});
