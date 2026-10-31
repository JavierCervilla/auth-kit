// Extra trusted origins (a second domain). better-auth checks `Origin` only on HTTP requests through its `handler`
// (with no `ctx.request` it checks nothing), so:
// - guest sign-up does not depend on the domain: the server makes it with `signInAnonymously()`, with no request;
// - what an untrusted domain cannot do is ask for the sign-in email: a 403 INVALID_ORIGIN, and nothing is sent.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import type { AuthKit } from "../../src/index.js";

import { recordingMailer, testAuth } from "./fixtures.js";
import { openDatabase, ORIGIN, resetDatabase, sessionSetCookie, type TestDatabase } from "./harness.js";

const SECOND = "https://second.example";

let db: TestDatabase;

function setup(trustedOrigins: string[]) {
  const mailer = recordingMailer();
  const auth = testAuth(db, { mailer, trustedOrigins });
  return { auth, mailer };
}

/** What «keep my profile» sends from `origin`: the email and a relative way back. */
function magicLinkRequest(origin: string, cookie?: string): Request {
  return new Request(`${origin}/api/auth/sign-in/magic-link`, {
    method: "POST",
    headers: { origin, "content-type": "application/json", ...(cookie ? { cookie } : {}) },
    body: JSON.stringify({ email: "new@example.test", callbackURL: "/me", errorCallbackURL: "/me/keep" }),
  });
}

async function guestCookie(auth: AuthKit): Promise<string> {
  const { headers } = await auth.signInAnonymously(new Headers({ origin: SECOND }));
  return sessionSetCookie(headers).split(";")[0] ?? "";
}

beforeAll(async () => {
  db = await openDatabase();
});

beforeEach(async () => {
  await resetDatabase(db);
});

afterAll(async () => {
  await db.$client.close();
});

describe("guest sign-up does not depend on the domain", () => {
  it("with the second domain's Origin, trusted or not, the server makes it all the same", async () => {
    for (const trusted of [[SECOND], []]) {
      expect(await guestCookie(setup(trusted).auth), String(trusted)).toMatch(/^__Secure-better-auth\.session_token=/);
    }
  });
});

describe("asking for the sign-in email from the second domain", () => {
  it("trusted: accepted and sent, also with the guest's cookie", async () => {
    const { auth, mailer } = setup([SECOND]);
    const cookie = await guestCookie(auth);
    expect((await auth.handler(magicLinkRequest(SECOND))).status).toBe(200);
    expect((await auth.handler(magicLinkRequest(SECOND, cookie))).status).toBe(200);
    expect(mailer.sent).toHaveLength(2);
  });

  it("not on the list: 403 INVALID_ORIGIN and nothing sent, with or without a cookie", async () => {
    const { auth, mailer } = setup([]);
    const cookie = await guestCookie(auth);
    for (const res of [await auth.handler(magicLinkRequest(SECOND)), await auth.handler(magicLinkRequest(SECOND, cookie))]) {
      expect(res.status).toBe(403);
      expect(((await res.json()) as { code?: string }).code).toBe("INVALID_ORIGIN");
    }
    expect(mailer.sent).toEqual([]);
  });

  it("the canonical domain is still accepted with the list set", async () => {
    const { auth, mailer } = setup([SECOND]);
    expect((await auth.handler(magicLinkRequest(ORIGIN))).status).toBe(200);
    expect(mailer.sent).toHaveLength(1);
  });

  it("a BETTER_AUTH_TRUSTED_ORIGINS that better-auth would read raw must pass the same rules", () => {
    expect(() => testAuth(db, { env: { BETTER_AUTH_TRUSTED_ORIGINS: "https://*.second.example" } })).toThrow(
      /BETTER_AUTH_TRUSTED_ORIGINS/,
    );
  });
});
