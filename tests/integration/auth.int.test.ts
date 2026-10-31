// better-auth with guests against a real Postgres engine: cookie flags, same cookie → same session and same user, no
// cookie or a tampered one → nobody, guest sign-up creates a `user` with `is_anonymous`, no IP or user agent stored,
// and sessions of 180 days renewed at most daily.
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { createAuth, SESSION, type AuthKit } from "../../src/index.js";
import { session } from "../../src/schema/index.js";

import { plainEmail, testAuth } from "./fixtures.js";
import {
  cookieHeader,
  openDatabase,
  ORIGIN,
  resetDatabase,
  rows,
  SECRET,
  SESSION_COOKIE,
  sessionSetCookie,
  type TestDatabase,
} from "./harness.js";

const DAY_MS = 24 * 60 * 60 * 1000;

let db: TestDatabase;
let auth: AuthKit;

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

const attributesOf = (setCookie: string) => setCookie.split(";").map((a) => a.trim().toLowerCase());

describe("guest sign-up (server only)", () => {
  it("creates a user with is_anonymous and its session in the database", async () => {
    const { user } = await auth.signInAnonymously(new Headers());
    expect(user.isAnonymous).toBe(true);
    expect(await rows(db, sql`select id, is_anonymous from "user"`)).toEqual([{ id: user.id, is_anonymous: true }]);
    expect(await rows(db, sql`select user_id from session`)).toEqual([{ user_id: user.id }]);
  });

  it("the session cookie is HttpOnly, Secure and SameSite=Lax", async () => {
    const { headers } = await auth.signInAnonymously(new Headers());
    const attrs = attributesOf(sessionSetCookie(headers));
    expect(attrs).toContain("httponly");
    expect(attrs).toContain("secure");
    expect(attrs).toContain("samesite=lax");
    expect(attrs).toContain("path=/");
  });

  it("the cookie lasts as long as the session: 180 days", async () => {
    const { headers } = await auth.signInAnonymously(new Headers());
    const maxAge = attributesOf(sessionSetCookie(headers)).find((a) => a.startsWith("max-age="));
    expect(maxAge).toBe(`max-age=${SESSION.expiresInSeconds}`);
  });

  it("in local development over http the cookie has no Secure (nor the __Secure- prefix)", async () => {
    const local = testAuth(db, { baseURL: "http://localhost:3000" });
    const { headers } = await local.signInAnonymously(new Headers());
    const cookie = headers.getSetCookie().find((c) => c.startsWith("better-auth.session_token="));
    expect(cookie).toBeDefined();
    const attrs = attributesOf(cookie ?? "");
    expect(attrs).toContain("httponly");
    expect(attrs).toContain("samesite=lax");
    expect(attrs).not.toContain("secure");
  });

  it("in production the cookie is Secure even over http", async () => {
    const production = testAuth(db, { baseURL: "http://localhost:3000", env: { NODE_ENV: "production" } });
    const { headers } = await production.signInAnonymously(new Headers());
    expect(attributesOf(sessionSetCookie(headers))).toContain("secure");
  });
});

describe("current user or nobody", () => {
  it("the same cookie gives the same session and the same user, twice", async () => {
    const { user, headers } = await auth.signInAnonymously(new Headers());
    const cookie = cookieHeader(sessionSetCookie(headers));
    const first = await auth.currentUser(cookie);
    expect(first).toEqual({ id: user.id, isAnonymous: true });
    expect(await auth.currentUser(cookie)).toEqual(first);
    expect(await rows(db, sql`select count(*)::int as n from session`)).toEqual([{ n: 1 }]);
  });

  it("no cookie, no user", async () => {
    await auth.signInAnonymously(new Headers());
    expect(await auth.currentUser(new Headers())).toBeNull();
  });

  it("a tampered cookie gives no user: changed signature, changed token, unsigned token or garbage", async () => {
    const { headers } = await auth.signInAnonymously(new Headers());
    const value = sessionSetCookie(headers).split(";")[0]?.slice(SESSION_COOKIE.length + 1) ?? "";
    const [token, signature] = decodeURIComponent(value).split(".");
    expect(token && signature).toBeTruthy();
    const flip = (s: string) => (s.startsWith("A") ? `B${s.slice(1)}` : `A${s.slice(1)}`);
    const forged = [`${token}.${flip(signature ?? "")}`, `${flip(token ?? "")}.${signature}`, `${token}`, "garbage", ""];
    for (const candidate of forged) {
      const cookie = new Headers({ cookie: `${SESSION_COOKIE}=${encodeURIComponent(candidate)}` });
      expect(await auth.currentUser(cookie), candidate).toBeNull();
    }
  });

  it("a session expired in the database gives no user", async () => {
    const { headers } = await auth.signInAnonymously(new Headers());
    await db.execute(sql`update session set expires_at = now() - interval '1 minute'`);
    expect(await auth.currentUser(cookieHeader(sessionSetCookie(headers)))).toBeNull();
  });

  it("two guest sign-ups are two different users", async () => {
    const a = await auth.signInAnonymously(new Headers());
    const b = await auth.signInAnonymously(new Headers());
    expect(a.user.id).not.toBe(b.user.id);
    expect(await auth.currentUser(cookieHeader(sessionSetCookie(a.headers)))).toEqual(a.user);
    expect(await auth.currentUser(cookieHeader(sessionSetCookie(b.headers)))).toEqual(b.user);
  });

  it("GET /get-session over HTTP: with the cookie, the same user; without it, null", async () => {
    const { user, headers } = await auth.signInAnonymously(new Headers());
    const cookie = sessionSetCookie(headers).split(";")[0] ?? "";
    const withCookie = await auth.handler(new Request(`${ORIGIN}/api/auth/get-session`, { headers: { cookie } }));
    expect(withCookie.status).toBe(200);
    const body = (await withCookie.json()) as { user: { id: string; isAnonymous: boolean } } | null;
    expect(body?.user).toMatchObject({ id: user.id, isAnonymous: true });

    const without = await auth.handler(new Request(`${ORIGIN}/api/auth/get-session`));
    expect(without.status).toBe(200);
    expect(await without.json()).toBeNull();
  });
});

const KNOWN_IP = "203.0.113.77";
const KNOWN_UA = "AuthKit-Test/9.9 (known browser)";

function knownClientHeaders(cookie?: string): Headers {
  const headers = new Headers({ "x-forwarded-for": KNOWN_IP, "user-agent": KNOWN_UA });
  if (cookie) headers.set("cookie", cookie);
  return headers;
}

interface SessionRow extends Record<string, unknown> {
  ip_address: string | null;
  user_agent: string | null;
  expires_at: string;
  updated_at: string;
}

const sessionRows = () =>
  rows<SessionRow>(
    db,
    sql`select ip_address, user_agent, expires_at::text as expires_at, updated_at::text as updated_at from session`,
  );

/** Moves the session `ms` back, as if it had been written that long ago. */
async function ageSession(ms: number): Promise<void> {
  const interval = `${ms} milliseconds`;
  await db.execute(sql`
    update session set expires_at = expires_at - ${interval}::interval, updated_at = updated_at - ${interval}::interval`);
}

describe("the session stores no IP address and no user agent", () => {
  it("a sign-up with known X-Forwarded-For and User-Agent leaves both columns null, also on renewal", async () => {
    const { headers } = await auth.signInAnonymously(knownClientHeaders());
    expect(await sessionRows()).toMatchObject([{ ip_address: null, user_agent: null }]);

    await ageSession(DAY_MS + 60_000);
    const before = (await sessionRows())[0];
    const cookie = sessionSetCookie(headers).split(";")[0] ?? "";
    expect(await auth.currentUser(knownClientHeaders(cookie))).not.toBeNull();
    const after = (await sessionRows())[0];
    expect(after?.updated_at).not.toBe(before?.updated_at);
    expect(after).toMatchObject({ ip_address: null, user_agent: null });
  });

  it("no text column of user, session, account or verification holds that IP address or user agent", async () => {
    const { headers } = await auth.signInAnonymously(knownClientHeaders());
    await ageSession(DAY_MS + 60_000);
    await auth.currentUser(knownClientHeaders(sessionSetCookie(headers).split(";")[0]));

    const columns = await rows<{ table_name: string; column_name: string }>(
      db,
      sql`select table_name, column_name from information_schema.columns
        where table_schema = 'public' and table_name in ('user', 'session', 'account', 'verification')
          and data_type in ('text', 'character varying', 'character')`,
    );
    expect(columns.length).toBeGreaterThan(0);
    for (const { table_name, column_name } of columns) {
      const hits = await rows<{ n: number }>(
        db,
        sql`select count(*)::int as n from ${sql.identifier(table_name)}
          where strpos(${sql.identifier(column_name)}, ${KNOWN_IP}) > 0
             or strpos(${sql.identifier(column_name)}, ${KNOWN_UA}) > 0`,
      );
      expect(hits[0]?.n, `${table_name}.${column_name}`).toBe(0);
    }
  });
});

describe("the session lasts 180 days from its last use", () => {
  it("on creation it expires in 180 days", async () => {
    const start = Date.now();
    const { headers } = await auth.signInAnonymously(new Headers());
    const result = await auth.api.getSession({ headers: cookieHeader(sessionSetCookie(headers)) });
    const expires = result?.session.expiresAt.getTime() ?? 0;
    expect(expires).toBeGreaterThanOrEqual(start + 180 * DAY_MS - 1000);
    expect(expires).toBeLessThanOrEqual(Date.now() + 180 * DAY_MS + 1000);
  });

  it("a session older than a day is renewed on use: 180 days again, with Set-Cookie", async () => {
    const { headers } = await auth.signInAnonymously(new Headers());
    await ageSession(DAY_MS + 60_000);
    const start = Date.now();
    const renewed = await auth.api.getSession({ headers: cookieHeader(sessionSetCookie(headers)), returnHeaders: true });
    expect(renewed.response?.session.expiresAt.getTime() ?? 0).toBeGreaterThanOrEqual(start + 180 * DAY_MS - 1000);
    expect(sessionSetCookie(renewed.headers)).toContain(`Max-Age=${SESSION.expiresInSeconds}`);
  });

  it("a session younger than a day is not rewritten on use", async () => {
    const { headers } = await auth.signInAnonymously(new Headers());
    await ageSession(DAY_MS - 60 * 60_000);
    const before = await sessionRows();
    expect(await auth.currentUser(cookieHeader(sessionSetCookie(headers)))).not.toBeNull();
    expect(await sessionRows()).toEqual(before);
  });
});

describe("timestamps in UTC", () => {
  it("session.expires_at (a timestamp without time zone) reads back as written, to the millisecond", async () => {
    const { headers } = await auth.signInAnonymously(new Headers());
    // At 179.5 days: inside the 180 and with no renewal (1 day), so reading does not rewrite it.
    const written = new Date(Math.floor((Date.now() + 179.5 * DAY_MS) / 1000) * 1000 + 678);
    await db.update(session).set({ expiresAt: written });

    const result = await auth.api.getSession({ headers: cookieHeader(sessionSetCookie(headers)) });
    expect(result?.session.expiresAt.toISOString()).toBe(written.toISOString());
    const raw = await rows<{ v: string; diff: number }>(
      db,
      sql`select expires_at::text as v, extract(epoch from (expires_at - localtimestamp)) * 1000 as diff from session`,
    );
    expect(raw[0]?.v).toBe(written.toISOString().replace("T", " ").replace("Z", ""));
    // `localtimestamp` is in the database session's time zone: if it were not UTC, the difference would be hours off.
    expect(Math.abs(Number(raw[0]?.diff) - (written.getTime() - Date.now()))).toBeLessThan(60_000);
  });
});

describe("building the instance", () => {
  it("does not touch the database until it is used", () => {
    const untouchable = {
      execute: () => Promise.reject(new Error("touched")),
      transaction: () => Promise.reject(new Error("touched")),
    };
    expect(() =>
      createAuth({
        db: untouchable,
        baseURL: ORIGIN,
        secret: SECRET,
        email: plainEmail,
        onGuestToAccount: () => Promise.resolve(),
        env: {},
      }),
    ).not.toThrow();
  });

  it("refuses an unsafe option without repeating its value", () => {
    expect(() => testAuth(db, { secret: "short-secret-value" })).toThrow(/secret/);
    expect(() => testAuth(db, { secret: "short-secret-value" })).not.toThrow(/short-secret-value/);
    expect(() => testAuth(db, { env: { BETTER_AUTH_TELEMETRY: "1" } })).toThrow(/BETTER_AUTH_TELEMETRY/);
    expect(() => testAuth(db, { trustedProxyHops: 0 })).toThrow(/trustedProxyHops/);
  });
});
