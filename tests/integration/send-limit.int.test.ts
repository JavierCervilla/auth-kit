// The send limit: 5 per hour per email and 20 per hour per IP, counted before better-auth, with the same 429 whether the
// email exists or not; and the limiter's single statement (INSERT … ON CONFLICT … RETURNING, purge with skip locked).
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { SEND_LIMITS } from "../../src/index.js";
import { createSendLimiter, rateLimitKey, RateLimitedError } from "../../src/rate-limit/limiter.js";

import { authRequest, recordingMailer, testAuth } from "./fixtures.js";
import { openDatabase, resetDatabase, rows, SECRET, type TestDatabase } from "./harness.js";
import { HOUR_WINDOW_SECONDS, untilWindowHasRoom, WINDOW_TEST_TIMEOUT_MS } from "./rate-limit-window.js";

let db: TestDatabase;

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

function setup() {
  const mailer = recordingMailer();
  const auth = testAuth(db, { mailer });
  const send = (email: string, ip: string) =>
    auth.handler(authRequest("/sign-in/magic-link", { body: { email, callbackURL: "/" }, headers: { "x-forwarded-for": ip } }));
  return { mailer, send };
}

/** What the caller sees when the limit stops it, without the seconds left (they move with the clock). */
async function limitedView(res: Response) {
  const retryAfter = res.headers.get("retry-after") ?? "";
  expect(retryAfter).toMatch(/^[1-9]\d*$/);
  expect(Number(retryAfter)).toBeLessThanOrEqual(HOUR_WINDOW_SECONDS);
  return { status: res.status, cache: res.headers.get("cache-control"), body: await res.text() };
}

describe("over HTTP", () => {
  it("the sixth send to the same email in the hour → 429 with Retry-After and no email, even from another IP", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    const { mailer, send } = setup();
    for (let i = 0; i < SEND_LIMITS.perEmail.hits; i++) {
      expect((await send("new@example.test", `198.51.100.${i + 1}`)).status).toBe(200);
    }
    const sixth = await send("New@Example.TEST", "198.51.100.99");
    expect(sixth.status).toBe(429);
    await limitedView(sixth);
    expect(mailer.sent).toHaveLength(SEND_LIMITS.perEmail.hits);
  }, WINDOW_TEST_TIMEOUT_MS);

  it("the 429 is the same for an email with an account and one without", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    const { send } = setup();
    const exhaust = async (email: string, ip: string) => {
      for (let i = 0; i < SEND_LIMITS.perEmail.hits; i++) await send(email, ip);
      return send(email, ip);
    };
    const known = await limitedView(await exhaust("existing@example.test", "203.0.113.1"));
    const unknown = await limitedView(await exhaust("nobody@example.test", "203.0.113.2"));
    expect(known.status).toBe(429);
    expect(unknown).toEqual(known);
  }, WINDOW_TEST_TIMEOUT_MS);

  it("send 21 from the same IP in the hour → 429, with different emails; another IP still can", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    const { mailer, send } = setup();
    for (let i = 0; i < SEND_LIMITS.perIp.hits; i++) {
      expect((await send(`person${i}@example.test`, "192.0.2.10")).status).toBe(200);
    }
    const blocked = await send("other@example.test", "192.0.2.10");
    expect(blocked.status).toBe(429);
    await limitedView(blocked);
    expect((await send("other@example.test", "192.0.2.11")).status).toBe(200);
    expect(mailer.sent).toHaveLength(SEND_LIMITS.perIp.hits + 1);
  }, WINDOW_TEST_TIMEOUT_MS);
});

describe("the counters", () => {
  const limiter = () => createSendLimiter({ db, secret: SECRET, trustedProxyHops: 1, log: () => {} });
  const ip = (address: string) => new Headers({ "x-forwarded-for": address });

  it("one row per scope and subject, keyed by a 16-byte HMAC, with neither the email nor the IP in clear", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    await limiter().beforeMagicLinkSend(ip("203.0.113.5"), "someone@example.test");
    await limiter().beforeMagicLinkSend(ip("203.0.113.5"), "someone@example.test");
    const counters = await rows<{ scope: string; key: Buffer | Uint8Array; hits: number }>(
      db,
      sql`select scope, key, hits from rate_limit_counter order by scope`,
    );
    expect(counters.map((c) => [c.scope, c.hits])).toEqual([
      ["magic_link_email", 2],
      ["magic_link_ip", 2],
    ]);
    const keys = counters.map((c) => Buffer.from(c.key));
    expect(keys[0]).toEqual(rateLimitKey(SECRET, "email:someone@example.test"));
    expect(keys[1]).toEqual(rateLimitKey(SECRET, "ip:v4:203.0.113.5"));
    for (const key of keys) {
      expect(key).toHaveLength(16);
      expect(key.toString("latin1")).not.toContain("someone");
    }
  }, WINDOW_TEST_TIMEOUT_MS);

  it("a different secret gives different keys", () => {
    expect(rateLimitKey(SECRET, "ip:v4:203.0.113.5")).not.toEqual(rateLimitKey(`${SECRET}y`, "ip:v4:203.0.113.5"));
  });

  it("spends every quota before deciding: an exhausted email still counts the IP", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    for (let i = 0; i < SEND_LIMITS.perEmail.hits; i++) {
      await limiter().beforeMagicLinkSend(ip(`198.51.100.${i + 1}`), "full@example.test");
    }
    await expect(limiter().beforeMagicLinkSend(ip("198.51.100.200"), "full@example.test")).rejects.toBeInstanceOf(
      RateLimitedError,
    );
    const counted = await rows<{ n: number }>(db, sql`select count(*)::int as n from rate_limit_counter where scope = 'magic_link_ip'`);
    expect(counted[0]?.n).toBe(SEND_LIMITS.perEmail.hits + 1);
  }, WINDOW_TEST_TIMEOUT_MS);

  it("without a readable IP, every request shares one bucket and the log line carries no address", async () => {
    const lines: string[] = [];
    const logged = createSendLimiter({ db, secret: SECRET, trustedProxyHops: 1, log: (line) => lines.push(line) });
    await logged.beforeMagicLinkSend(new Headers({ "x-forwarded-for": "203.0.113.9, garbage" }), null);
    await logged.beforeMagicLinkSend(new Headers(), null);
    expect(await rows(db, sql`select hits from rate_limit_counter`)).toEqual([{ hits: 2 }]);
    expect(lines).toHaveLength(2);
    expect(lines.join("\n")).not.toContain("203.0.113.9");
  });

  it("the same statement purges windows that started more than 3 days ago", async () => {
    const stale = rateLimitKey(SECRET, "ip:v4:192.0.2.1");
    const recent = rateLimitKey(SECRET, "ip:v4:192.0.2.2");
    await db.execute(sql`insert into rate_limit_counter (scope, key, window_start, hits) values
      ('magic_link_ip', ${stale}, now() - interval '4 days', 3),
      ('magic_link_ip', ${recent}, now() - interval '2 days', 3)`);
    await limiter().beforeMagicLinkSend(ip("192.0.2.3"), null);
    const left = await rows<{ key: Uint8Array }>(db, sql`select key from rate_limit_counter order by window_start`);
    expect(left.map((r) => Buffer.from(r.key))).toEqual([recent, rateLimitKey(SECRET, "ip:v4:192.0.2.3")]);
  });

  it("the table refuses a scope outside the catalogue and a key that is not 16 bytes", async () => {
    await expect(
      db.execute(sql`insert into rate_limit_counter (scope, key, window_start, hits)
        values ('other', ${Buffer.alloc(16)}, now(), 1)`),
    ).rejects.toThrow();
    await expect(
      db.execute(sql`insert into rate_limit_counter (scope, key, window_start, hits)
        values ('magic_link_ip', ${Buffer.alloc(8)}, now(), 1)`),
    ).rejects.toThrow();
  });
});
