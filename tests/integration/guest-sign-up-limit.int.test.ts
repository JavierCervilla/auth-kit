// The guest sign-up limits: per IP per hour and in total per hour, spent before any guest user is created, on every
// path that creates one (`signInAnonymously`, better-auth's server API); the HTTP route itself is closed.
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { DEFAULT_LIMITS, type AuthKit } from "../../src/index.js";
import { rateLimitKey } from "../../src/rate-limit/limiter.js";

import { authRequest, testAuth } from "./fixtures.js";
import { openDatabase, resetDatabase, rows, SECRET, type TestDatabase } from "./harness.js";
import { HOUR_WINDOW_SECONDS, untilWindowHasRoom, WINDOW_TEST_TIMEOUT_MS } from "./rate-limit-window.js";

let db: TestDatabase;
let auth: AuthKit;

const from = (ip: string) => new Headers({ "x-forwarded-for": ip });
const users = async () => (await rows<{ n: number }>(db, sql`select count(*)::int as n from "user"`))[0]?.n;

/** What a refused sign-up throws: the 429 APIError with Retry-After. */
async function refusal(run: Promise<unknown>) {
  const error = (await run.then(
    () => undefined,
    (e: unknown) => e,
  )) as { statusCode?: number; headers?: HeadersInit; body?: unknown } | undefined;
  expect(error?.statusCode).toBe(429);
  expect(new Headers(error?.headers).get("retry-after")).toMatch(/^[1-9]\d*$/);
  return error?.body;
}

beforeAll(async () => {
  db = await openDatabase();
  auth = testAuth(db);
});

beforeEach(async () => {
  await resetDatabase(db);
});

afterAll(async () => {
  await db.$client.close();
});

describe("per IP", () => {
  it("sign-up 31 of the hour from one IP → 429 and no user created; another IP still can", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    for (let i = 0; i < DEFAULT_LIMITS.guestSignUpPerIpPerHour; i++) await auth.signInAnonymously(from("198.51.100.7"));
    expect(await users()).toBe(DEFAULT_LIMITS.guestSignUpPerIpPerHour);
    await refusal(auth.signInAnonymously(from("198.51.100.7")));
    expect(await users()).toBe(DEFAULT_LIMITS.guestSignUpPerIpPerHour);
    expect((await auth.signInAnonymously(from("198.51.100.8"))).user.isAnonymous).toBe(true);
  }, WINDOW_TEST_TIMEOUT_MS);

  it("better-auth's own server API is limited too: there is no way around it", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    const strict = testAuth(db, { limits: { guestSignUpPerIpPerHour: 1 } });
    await strict.api.signInAnonymous({ headers: from("198.51.100.9") });
    await refusal(strict.api.signInAnonymous({ headers: from("198.51.100.9") }));
    expect(await users()).toBe(1);
  }, WINDOW_TEST_TIMEOUT_MS);
});

describe("in total", () => {
  it("with the global hour already at its limit, a sign-up from a fresh IP → the same 429 and no user", async () => {
    await untilWindowHasRoom(db, HOUR_WINDOW_SECONDS);
    await auth.signInAnonymously(from("203.0.113.1"));
    const perIpBody = await (async () => {
      const strict = testAuth(db, { limits: { guestSignUpPerIpPerHour: 1 } });
      return refusal(strict.signInAnonymously(from("203.0.113.1")));
    })();
    await db.execute(sql`
      update rate_limit_counter set hits = ${DEFAULT_LIMITS.guestSignUpGlobalPerHour}
      where scope = 'anon_signup_global' and key = ${rateLimitKey(SECRET, "global")}`);
    const before = await users();
    expect(await refusal(auth.signInAnonymously(from("203.0.113.200")))).toEqual(perIpBody);
    expect(await users()).toBe(before);
  }, WINDOW_TEST_TIMEOUT_MS);
});

describe("over HTTP", () => {
  it("POST /sign-in/anonymous is 404 and creates nobody", async () => {
    const res = await auth.handler(authRequest("/sign-in/anonymous", { body: {} }));
    expect(res.status).toBe(404);
    expect(await users()).toBe(0);
  });
});
