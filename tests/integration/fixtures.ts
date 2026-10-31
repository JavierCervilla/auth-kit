// Shared fixtures: a recording mailer, a plain email renderer and the auth instance the tests build.
import { createAuth, type AuthKitOptions } from "../../src/index.js";
import type { Mailer, OutgoingMail, SendResult } from "../../src/mail/index.js";

import { ORIGIN, SECRET, type TestDatabase } from "./harness.js";

export interface SentMail extends OutgoingMail {
  url: string;
  code: string;
}

/** A mailer that records what it would have sent; the renderer below puts the link and the code in the text. */
export function recordingMailer(result: SendResult = { ok: true }): Mailer & { sent: SentMail[] } {
  const sent: SentMail[] = [];
  return {
    configured: true,
    sent,
    send: (mail) => {
      const [url = "", code = ""] = mail.text.split("\n");
      sent.push({ ...mail, url, code });
      return Promise.resolve(result);
    },
  };
}

export const plainEmail = {
  render: (link: string, code: string) => ({ subject: `${code} is your code`, text: `${link}\n${code}`, html: "<p></p>" }),
};

export type TestOptions = Partial<AuthKitOptions<TestDatabase>>;

/** `createAuth` on the test database, with no guest-data move unless one is given and an empty environment. */
export function testAuth(db: TestDatabase, options: TestOptions = {}) {
  return createAuth<TestDatabase>({
    db,
    baseURL: ORIGIN,
    secret: SECRET,
    email: plainEmail,
    onGuestToAccount: () => Promise.resolve(),
    env: {},
    log: () => {},
    ...options,
  });
}

/** A request to the auth routes from the app's origin. */
export function authRequest(path: string, init: { body?: unknown; headers?: Record<string, string> } = {}): Request {
  const method = init.body === undefined ? "GET" : "POST";
  return new Request(`${ORIGIN}/api/auth${path}`, {
    method,
    headers: { origin: ORIGIN, "content-type": "application/json", ...init.headers },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
}
