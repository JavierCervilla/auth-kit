// The email-code check limits: per email per day and per IP per hour, spent on every POST whether the code is right or
// not, before better-auth looks at the code, outside any transaction, with one 429 whatever quota ran out.
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { DEFAULT_LIMITS, type AuthKit } from "../../src/index.js";

import { authRequest, recordingMailer, testAuth } from "./fixtures.js";
import { lastSessionCookie, openDatabase, resetDatabase, rows, type TestDatabase } from "./harness.js";
import {
  DAY_WINDOW_SECONDS,
  HOUR_WINDOW_SECONDS,
  untilWindowHasRoom,
  WINDOW_TEST_TIMEOUT_MS,
} from "./rate-limit-window.js";

const EXISTING = { id: "existing-account", email: "existing@example.test" };
const LIMITED_BODY = { code: "TOO_MANY_REQUESTS", message: "Too many attempts; try again later." };

let db: TestDatabase;
let auth: AuthKit;
const mailer = recordingMailer();

async function ask(email: string): Promise<string> {
  const res = await auth.handler(authRequest("/sign-in/magic-link", { body: { email, callbackURL: "/" } }));
  expect(res.status).toBe(200);
  return mailer.sent.at(-1)?.code ?? "";
}

const verify = (email: string, otp: string, ip: string, kit: AuthKit = auth) =>
  kit.handler(authRequest("/sign-in/email-otp", { body: { email, otp }, headers: { "x-forwarded-for": ip } }));

const wrong = (code: string, n = 1) => String((Number(code) + n) % 1_000_000).padStart(6, "0");

async function limitedView(res: Response, windowSeconds: number) {
  const retryAfter = res.headers.get("retry-after") ?? "";
  expect(retryAfter).toMatch(/^[1-9]\d*$/);
  expect(Number(retryAfter)).toBeLessThanOrEqual(windowSeconds);
  return { status: res.status, cache: res.headers.get("cache-control"), body: await res.text() };
}

beforeAll(async () => {
  db = await openDatabase();
  auth = testAuth(db, { mailer });
});

beforeEach(async () => {
  await resetDatabase(db);
  mailer.sent.length = 0;
  await db.execute(sql`
    insert into "user" (id, name, email, email_verified) values (${EXISTING.id}, '', ${EXISTING.email}, true)`);
});

afterAll(async () => {
  await db.$client.close();
});

describe("per email per day and per IP per hour", () => {
  it("the 11th POST of the day for an email → 429, even from another IP with the right code; the same for an unknown email", async () => {
    await untilWindowHasRoom(db, DAY_WINDOW_SECONDS);
    const code = await ask(EXISTING.email);
    for (let i = 0; i < DEFAULT_LIMITS.codeCheckPerEmailPerDay; i++) {
      expect((await verify(EXISTING.email, wrong(code, i + 1), `198.51.100.${i + 1}`)).status, `check ${i + 1}`).toBe(400);
    }
    const goodButLimited = await verify(EXISTING.email, code, "198.51.100.99");
    expect(goodButLimited.status).toBe(429);
    const known = await limitedView(goodButLimited, DAY_WINDOW_SECONDS);
    expect(JSON.parse(known.body)).toEqual(LIMITED_BODY);

    for (let i = 0; i < DEFAULT_LIMITS.codeCheckPerEmailPerDay; i++) {
      await verify("nobody@example.test", "123456", `203.0.113.${i + 1}`);
    }
    const unknown = await limitedView(await verify("Nobody@Example.TEST", "654321", "203.0.113.99"), DAY_WINDOW_SECONDS);
    expect(unknown).toEqual(known);
    expect(await rows(db, sql`select 1 from session`)).toHaveLength(0);
  }, WINDOW_TEST_TIMEOUT_MS);

  it("POST 31 of the hour from one IP → 429, with different emails; another IP still can", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    for (let i = 0; i < DEFAULT_LIMITS.codeCheckPerIpPerHour; i++) {
      expect((await verify(`person${i}@example.test`, "123456", "192.0.2.10")).status).toBe(400);
    }
    const blocked = await verify("other@example.test", "123456", "192.0.2.10");
    expect(blocked.status).toBe(429);
    expect(JSON.parse((await limitedView(blocked, HOUR_WINDOW_SECONDS)).body)).toEqual(LIMITED_BODY);
    expect((await verify("other@example.test", "123456", "192.0.2.11")).status).toBe(400);
  }, WINDOW_TEST_TIMEOUT_MS);

  it("the 429 does not reach better-auth: the right code is neither spent nor counted as an attempt", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    const code = await ask(EXISTING.email);
    for (let i = 0; i < DEFAULT_LIMITS.codeCheckPerIpPerHour; i++) await verify(`person${i}@example.test`, "123456", "192.0.2.20");
    for (let i = 0; i < 3; i++) expect((await verify(EXISTING.email, code, "192.0.2.20")).status).toBe(429);
    const elsewhere = await verify(EXISTING.email, code, "192.0.2.21");
    expect(elsewhere.status).toBe(200);
    expect(lastSessionCookie(elsewhere)).toBeDefined();
  }, WINDOW_TEST_TIMEOUT_MS);

  it("a failed check still spends both quotas (counters in the database)", async () => {
    await verify(EXISTING.email, "123456", "192.0.2.77");
    const counts = await rows<{ scope: string; hits: number }>(
      db,
      sql`select scope, hits from rate_limit_counter where scope like 'otp_verify_%' order by scope`,
    );
    expect(counts.map((r) => [r.scope, r.hits])).toEqual([
      ["otp_verify_email", 1],
      ["otp_verify_ip", 1],
    ]);
  });

  it("a malformed body is refused before it spends anything", async () => {
    const res = await auth.handler(authRequest("/sign-in/email-otp", { body: { email: EXISTING.email } }));
    expect(res.status).toBe(400);
    expect(await rows(db, sql`select 1 from rate_limit_counter where scope like 'otp_verify_%'`)).toHaveLength(0);
  });
});

describe("a lowered limit from the `limits` option", () => {
  it("with 2 checks per email per day, the third → 429", async () => {
    await untilWindowHasRoom(db, DAY_WINDOW_SECONDS);
    const strict = testAuth(db, { mailer, limits: { codeCheckPerEmailPerDay: 2 } });
    expect((await verify(EXISTING.email, "123456", "192.0.2.30", strict)).status).toBe(400);
    expect((await verify(EXISTING.email, "123456", "192.0.2.31", strict)).status).toBe(400);
    expect((await verify(EXISTING.email, "123456", "192.0.2.32", strict)).status).toBe(429);
  }, WINDOW_TEST_TIMEOUT_MS);
});
