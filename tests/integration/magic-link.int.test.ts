// The magic link against a real Postgres engine. No network: the mailer records what it would have sent.
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { MAGIC_LINK_EXPIRES_IN_SECONDS } from "../../src/index.js";
import type { Mailer } from "../../src/mail/index.js";

import { authRequest, recordingMailer, testAuth } from "./fixtures.js";
import { openDatabase, resetDatabase, rows, SESSION_COOKIE, type TestDatabase } from "./harness.js";

let db: TestDatabase;

function setup(mailer: Mailer | undefined) {
  const auth = testAuth(db, mailer ? { mailer } : {});
  const send = (email: string, ip?: string) =>
    auth.handler(
      authRequest("/sign-in/magic-link", {
        body: { email, callbackURL: "/" },
        headers: ip ? { "x-forwarded-for": ip } : {},
      }),
    );
  return { auth, send };
}

beforeAll(async () => {
  db = await openDatabase();
});

beforeEach(async () => {
  await resetDatabase(db);
  await db.execute(sql`
    insert into "user" (id, name, email, email_verified) values ('existing', '', 'existing@example.test', true)`);
});

afterAll(async () => {
  await db.$client.close();
});

describe("asking for the link", () => {
  it("answers the same for an email with an account and one without, and both get their link", async () => {
    const mailer = recordingMailer();
    const { send } = setup(mailer);
    const known = await send("existing@example.test");
    const unknown = await send("new@example.test");
    expect(known.status).toBe(200);
    expect(unknown.status).toBe(known.status);
    expect(await unknown.text()).toBe(await known.text());
    expect(mailer.sent.map((m) => m.to)).toEqual(["existing@example.test", "new@example.test"]);
  });

  it("stores only the token's hash, with 10 minutes to live", async () => {
    const mailer = recordingMailer();
    await setup(mailer).send("new@example.test");
    const token = new URL(mailer.sent[0]?.url ?? "").searchParams.get("token") ?? "";
    expect(token.length).toBeGreaterThanOrEqual(32);
    const stored = await rows<{ identifier: string; value: string; ttl: number }>(
      db,
      sql`select identifier, value, extract(epoch from expires_at - created_at)::int as ttl from verification
        where identifier like 'magic-link:%'`,
    );
    expect(stored).toHaveLength(1);
    expect(stored[0]?.identifier).not.toContain(token);
    expect(stored[0]?.value).not.toContain(token);
    expect(Math.abs((stored[0]?.ttl ?? 0) - MAGIC_LINK_EXPIRES_IN_SECONDS)).toBeLessThanOrEqual(2);
  });

  it("the project's renderer writes the email, with the request's locale", async () => {
    const seen: (string | null)[] = [];
    const mailer = recordingMailer();
    const auth = testAuth(db, {
      mailer,
      email: {
        render: (link, code, locale) => {
          seen.push(locale);
          return { subject: "s", text: `${link}\n${code}`, html: "<p></p>" };
        },
      },
    });
    await auth.handler(
      authRequest("/sign-in/magic-link", {
        body: { email: "new@example.test" },
        headers: { "accept-language": "es-ES,es;q=0.9,en;q=0.8" },
      }),
    );
    await auth.handler(authRequest("/sign-in/magic-link", { body: { email: "other@example.test" } }));
    expect(seen).toEqual(["es-ES", null]);
    expect(mailer.sent[0]?.code).toMatch(/^\d{6}$/);
  });

  it("if the send fails: a typed 503, never a 500, the same for an email with an account and one without", async () => {
    const { send } = setup(recordingMailer({ ok: false, reason: "send_failed" }));
    const known = await send("existing@example.test");
    const unknown = await send("new@example.test");
    expect(known.status).toBe(503);
    expect(unknown.status).toBe(503);
    const body = (await known.json()) as { code: string };
    expect(body.code).toBe("MAGIC_LINK_NOT_SENT");
    expect(await unknown.json()).toEqual(body);
  });

  it("refuses a body with anything beyond the email and the callback URLs: 400, no email, no quota spent", async () => {
    // A third party must not choose the name (or metadata) of the user created when the victim opens the link.
    const mailer = recordingMailer();
    const { auth } = setup(mailer);
    const extras = [{ name: "Call +1-555 support" }, { metadata: { role: "admin" } }, { image: "https://x.test/a.png" }];
    for (const extra of extras) {
      const res = await auth.handler(
        authRequest("/sign-in/magic-link", { body: { email: "victim@example.test", callbackURL: "/", ...extra } }),
      );
      expect(res.status).toBe(400);
    }
    expect(mailer.sent).toHaveLength(0);
    expect(await rows(db, sql`select 1 from verification`)).toHaveLength(0);
    expect(await rows(db, sql`select 1 from rate_limit_counter`)).toHaveLength(0);
  });

  it("accepts the callback URLs better-auth knows", async () => {
    const mailer = recordingMailer();
    const { auth } = setup(mailer);
    const res = await auth.handler(
      authRequest("/sign-in/magic-link", {
        body: { email: "new@example.test", callbackURL: "/", errorCallbackURL: "/", newUserCallbackURL: "/" },
      }),
    );
    expect(res.status).toBe(200);
    expect(mailer.sent).toHaveLength(1);
  });

  it("without a mailer, or with one that is off: 404 and nothing in the database", async () => {
    const off: Mailer = { configured: false, send: () => Promise.resolve({ ok: false, reason: "not_configured" }) };
    for (const mailer of [undefined, off]) {
      const res = await setup(mailer).send("new@example.test");
      expect(res.status).toBe(404);
    }
    expect(await rows(db, sql`select 1 from verification`)).toHaveLength(0);
  });
});

describe("opening the link", () => {
  it("opens a session of that email's user; used again, it opens nothing (single use)", async () => {
    const mailer = recordingMailer();
    const { auth, send } = setup(mailer);
    await send("existing@example.test");
    const url = mailer.sent[0]?.url ?? "";
    expect(new URL(url).pathname).toBe("/api/auth/magic-link/verify");
    const first = await auth.handler(new Request(url));
    expect(first.status).toBe(302);
    expect(first.headers.getSetCookie().some((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBe(true);
    expect(await rows(db, sql`select user_id from session`)).toEqual([{ user_id: "existing" }]);

    const again = await auth.handler(new Request(url));
    expect(again.status).toBe(302);
    expect(again.headers.get("location")).toContain("error=INVALID_TOKEN");
    expect(again.headers.getSetCookie().some((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBe(false);
    expect(await rows(db, sql`select 1 from session`)).toHaveLength(1);
  });
});
