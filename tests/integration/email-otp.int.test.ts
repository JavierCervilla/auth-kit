// The code in the sign-in email, against real better-auth and a real Postgres engine. The code is created by the same
// send as the magic link and checked at `POST /sign-in/email-otp`, with a closed body in front and one error behind.
import { randomUUID } from "node:crypto";

import { sql } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { EMAIL_CODE, type AuthKit, type GuestToAccountRefusal } from "../../src/index.js";
import type { Mailer } from "../../src/mail/index.js";

import { authRequest, recordingMailer, testAuth, type TestOptions } from "./fixtures.js";
import { lastSessionCookie, openDatabase, resetDatabase, rows, SESSION_COOKIE, type TestDatabase } from "./harness.js";

const EXISTING = { id: "existing-account", email: "existing@example.test" };
const REFUSAL: GuestToAccountRefusal = { code: "EMAIL_HAS_OTHER_PROFILE", message: "Refused.", details: { world: "w-1" } };
const NOT_VALID = { status: 400, cache: "no-store", body: JSON.stringify({ code: "OTP_NOT_VALID" }) };

let db: TestDatabase;
const mailer = recordingMailer();
let guardAnswer: GuestToAccountRefusal | null = null;
let moveAnswer: GuestToAccountRefusal | null = null;
let auth: AuthKit;
let handler: ReturnType<typeof vi.fn<(request: Request) => Promise<Response>>>;

const options: TestOptions = {
  mailer,
  guardGuestToAccount: () => Promise.resolve(guardAnswer),
  onGuestToAccount: async (tx, { guestUserId, accountUserId }) => {
    await tx.execute(sql`update game_save set user_id = ${accountUserId} where user_id = ${guestUserId}`);
    return moveAnswer ?? undefined;
  },
};

interface From {
  cookie?: string;
}

/** Asks for the email (code and link) as the page does, and returns the code that arrived. */
async function ask(email: string, from: From = {}): Promise<string> {
  const res = await handler(
    authRequest("/sign-in/magic-link", {
      body: { email, callbackURL: "/", errorCallbackURL: "/sign-in" },
      headers: from.cookie ? { cookie: from.cookie } : {},
    }),
  );
  expect(res.status).toBe(200);
  const last = mailer.sent.at(-1);
  expect(last?.to).toBe(email);
  return last?.code ?? "";
}

/** Types the code on the page: `POST /sign-in/email-otp` with `{ email, otp }`. */
function verify(email: string, otp: string, from: From = {}): Promise<Response> {
  return handler(
    authRequest("/sign-in/email-otp", { body: { email, otp }, headers: from.cookie ? { cookie: from.cookie } : {} }),
  );
}

/** A 6-digit code that is not `code`. */
const wrong = (code: string, n = 1) => String((Number(code) + n) % 1_000_000).padStart(6, "0");

async function guest(): Promise<{ userId: string; cookie: string }> {
  const { user, headers } = await auth.signInAnonymously(new Headers());
  const setCookie = headers.getSetCookie().find((c) => c.startsWith(`${SESSION_COOKIE}=`)) ?? "";
  return { userId: user.id, cookie: setCookie.split(";")[0] ?? "" };
}

async function save(userId: string): Promise<string> {
  const id = randomUUID();
  await db.execute(sql`insert into game_save (id, user_id) values (${id}, ${userId})`);
  return id;
}

async function ownerOf(saveId: string): Promise<string | undefined> {
  return (await rows<{ user_id: string }>(db, sql`select user_id from game_save where id = ${saveId}`))[0]?.user_id;
}

const userExists = async (id: string) => (await rows(db, sql`select 1 from "user" where id = ${id}`)).length === 1;
const userIdByEmail = async (email: string) =>
  (await rows<{ id: string }>(db, sql`select id from "user" where email = ${email}`))[0]?.id ?? null;
const sessionUser = async (cookie: string) => (await auth.currentUser(new Headers({ cookie })))?.id ?? null;
const sessionsOf = async (userId: string) => rows(db, sql`select 1 from session where user_id = ${userId}`);

/** What the caller sees of an error: status, cache and body, byte for byte. */
async function errorView(res: Response) {
  return { status: res.status, cache: res.headers.get("cache-control"), body: await res.text() };
}

const pastExpiry = () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(Date.now() + EMAIL_CODE.expiresInSeconds * 1000 + 1000);
};

beforeAll(async () => {
  db = await openDatabase();
  await db.execute(sql`create table game_save (id text primary key, user_id text not null references "user"(id))`);
  auth = testAuth(db, options);
  handler = vi.fn((request: Request) => auth.handler(request));
});

beforeEach(async () => {
  await db.execute(sql`truncate game_save`);
  await resetDatabase(db);
  mailer.sent.length = 0;
  guardAnswer = null;
  moveAnswer = null;
  handler.mockClear();
  await db.execute(sql`
    insert into "user" (id, name, email, email_verified) values (${EXISTING.id}, '', ${EXISTING.email}, true)`);
});

afterEach(() => {
  vi.useRealTimers();
});

afterAll(async () => {
  await db.$client.close();
});

describe("a guest becomes an account by code", () => {
  it("with a new email: every row moves to the new account and the guest disappears", async () => {
    const anon = await guest();
    const [first, second] = [await save(anon.userId), await save(anon.userId)];
    const code = await ask("new@example.test", anon);
    expect(code).toMatch(/^\d{6}$/);
    const res = await verify("new@example.test", code, anon);
    expect(res.status).toBe(200);
    const account = await userIdByEmail("new@example.test");
    expect(account).not.toBeNull();
    expect(account).not.toBe(anon.userId);
    expect([await ownerOf(first), await ownerOf(second)]).toEqual([account, account]);
    expect(await userExists(anon.userId)).toBe(false);
    expect(await sessionUser(lastSessionCookie(res) ?? "")).toBe(account);
  });

  it("with an email that already had an account: opens THAT account (no new one) and takes the rows", async () => {
    const anon = await guest();
    const mine = await save(anon.userId);
    const res = await verify(EXISTING.email, await ask(EXISTING.email, anon), anon);
    expect(res.status).toBe(200);
    expect(await ownerOf(mine)).toBe(EXISTING.id);
    expect(await userExists(anon.userId)).toBe(false);
    expect(await sessionUser(lastSessionCookie(res) ?? "")).toBe(EXISTING.id);
    expect(await rows(db, sql`select 1 from "user" where email = ${EXISTING.email}`)).toHaveLength(1);
  });

  it("without a guest session (signing in on another device): opens the account and moves nothing", async () => {
    const other = await guest();
    const theirs = await save(other.userId);
    const res = await verify(EXISTING.email, await ask(EXISTING.email));
    expect(res.status).toBe(200);
    expect(await sessionUser(lastSessionCookie(res) ?? "")).toBe(EXISTING.id);
    expect(await ownerOf(theirs)).toBe(other.userId);
    expect(await userExists(other.userId)).toBe(true);
  });
});

describe("a refused link", () => {
  async function guestWithRows() {
    const anon = await guest();
    return { anon, mine: await save(anon.userId), theirs: await save(EXISTING.id) };
  }

  async function expectNothingMoved(c: Awaited<ReturnType<typeof guestWithRows>>) {
    expect(await ownerOf(c.mine)).toBe(c.anon.userId);
    expect(await ownerOf(c.theirs)).toBe(EXISTING.id);
    expect(await userExists(c.anon.userId)).toBe(true);
    expect(await sessionUser(c.anon.cookie)).toBe(c.anon.userId);
  }

  it("with the right code: 409 with the refusal, nothing moves, the guest keeps its session, the code is unspent", async () => {
    guardAnswer = REFUSAL;
    const c = await guestWithRows();
    const code = await ask(EXISTING.email, c.anon);
    const res = await verify(EXISTING.email, code, c.anon);
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ code: REFUSAL.code, message: REFUSAL.message, world: "w-1" });
    expect(lastSessionCookie(res)).toBeUndefined();
    expect(await sessionsOf(EXISTING.id)).toHaveLength(0);
    await expectNothingMoved(c);
    // Unspent: the same code still works, e.g. to sign in from another browser, without the guest.
    expect((await verify(EXISTING.email, code)).status).toBe(200);
  });

  it("the race between the guard and the move leaves the same, and the cookie left is the guest's", async () => {
    moveAnswer = REFUSAL;
    const c = await guestWithRows();
    const res = await verify(EXISTING.email, await ask(EXISTING.email, c.anon), c.anon);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ code: REFUSAL.code, world: "w-1" });
    expect(await sessionUser(lastSessionCookie(res) ?? "")).toBe(c.anon.userId);
    expect(await sessionsOf(EXISTING.id)).toHaveLength(0);
    await expectNothingMoved(c);
  });

  it("with a wrong code the answer is the single error and nothing about the refusal", async () => {
    guardAnswer = REFUSAL;
    const c = await guestWithRows();
    const code = await ask(EXISTING.email, c.anon);
    expect(await errorView(await verify(EXISTING.email, wrong(code), c.anon))).toEqual(NOT_VALID);
    await expectNothingMoved(c);
  });

  // The guard only speaks for a code the plugin would accept (live and with attempts left).
  it("with the right code but expired, the answer is the single error, not the 409", async () => {
    guardAnswer = REFUSAL;
    const c = await guestWithRows();
    const code = await ask(EXISTING.email, c.anon);
    pastExpiry();
    expect(await errorView(await verify(EXISTING.email, code, c.anon))).toEqual(NOT_VALID);
    vi.useRealTimers();
    await expectNothingMoved(c);
  });

  it("after 3 failures, the right code gets the single error, not the 409", async () => {
    guardAnswer = REFUSAL;
    const c = await guestWithRows();
    const code = await ask(EXISTING.email, c.anon);
    for (let i = 1; i <= EMAIL_CODE.allowedAttempts; i++) {
      expect(await errorView(await verify(EXISTING.email, wrong(code, i), c.anon))).toEqual(NOT_VALID);
    }
    expect(await errorView(await verify(EXISTING.email, code, c.anon))).toEqual(NOT_VALID);
    await expectNothingMoved(c);
  });
});

describe("single use, the latest only, 3 attempts, 10 minutes", () => {
  it("two POSTs at once with the right code: one signs in and the other gets the single error", async () => {
    const code = await ask(EXISTING.email);
    const both = await Promise.all([verify(EXISTING.email, code), verify(EXISTING.email, code)]);
    expect(both.map((r) => r.status).sort((x, y) => x - y)).toEqual([200, 400]);
    expect(await errorView(both.find((r) => r.status === 400) ?? new Response())).toEqual(NOT_VALID);
    expect(await sessionsOf(EXISTING.id)).toHaveLength(1);
  });

  it("after asking for a second code, the first gets the single error and the second works", async () => {
    const first = await ask(EXISTING.email);
    let second = await ask(EXISTING.email);
    while (second === first) second = await ask(EXISTING.email);
    expect(await errorView(await verify(EXISTING.email, first))).toEqual(NOT_VALID);
    expect((await verify(EXISTING.email, second)).status).toBe(200);
  });

  it("three failures and then the right code gets the single error", async () => {
    const code = await ask(EXISTING.email);
    for (let i = 1; i <= EMAIL_CODE.allowedAttempts; i++) {
      expect(await errorView(await verify(EXISTING.email, wrong(code, i)))).toEqual(NOT_VALID);
    }
    expect(await errorView(await verify(EXISTING.email, code))).toEqual(NOT_VALID);
    expect(await rows(db, sql`select 1 from session`)).toHaveLength(0);
  });

  it("two failures and the right code still works", async () => {
    const code = await ask(EXISTING.email);
    for (let i = 1; i <= 2; i++) await verify(EXISTING.email, wrong(code, i));
    expect((await verify(EXISTING.email, code)).status).toBe(200);
  });

  it("after 10 minutes by the server's clock, the right code gets the single error", async () => {
    const code = await ask(EXISTING.email);
    const ttl = await rows<{ ttl: number }>(
      db,
      sql`select extract(epoch from expires_at - created_at)::int as ttl from verification
        where identifier not like 'magic-link:%'`,
    );
    expect(ttl).toHaveLength(1);
    expect(Math.abs((ttl[0]?.ttl ?? 0) - EMAIL_CODE.expiresInSeconds)).toBeLessThanOrEqual(2);
    pastExpiry();
    expect(await errorView(await verify(EXISTING.email, code))).toEqual(NOT_VALID);
    expect(await rows(db, sql`select 1 from session`)).toHaveLength(0);
  });
});

describe("one error answer", () => {
  it("wrong, expired, exhausted and never requested: the same status and body, byte for byte", async () => {
    const badlyCode = await ask("wrong@example.test");
    const badly = await errorView(await verify("wrong@example.test", wrong(badlyCode)));

    const spentCode = await ask("spent@example.test");
    for (let i = 1; i <= EMAIL_CODE.allowedAttempts; i++) await verify("spent@example.test", wrong(spentCode, i));
    const exhausted = await errorView(await verify("spent@example.test", spentCode));

    const none = await errorView(await verify("no-code@example.test", "123456"));

    const lateCode = await ask("late@example.test");
    pastExpiry();
    const expired = await errorView(await verify("late@example.test", lateCode));

    expect(badly).toEqual(NOT_VALID);
    expect(exhausted).toEqual(badly);
    expect(expired).toEqual(badly);
    expect(none).toEqual(badly);
  });
});

describe("the closed body", () => {
  it.each([
    ["name", { email: "new@example.test", otp: "123456", name: "Intruder" }],
    ["image", { email: "new@example.test", otp: "123456", image: "https://bad.example/x.png" }],
    ["another field", { email: "new@example.test", otp: "123456", isAnonymous: true }],
    ["no otp", { email: "new@example.test" }],
    ["otp as a number", { email: "new@example.test", otp: 123456 }],
  ])("with %s → 400 and no user created", async (_case, body) => {
    const before = (await rows(db, sql`select 1 from "user"`)).length;
    const res = await handler(authRequest("/sign-in/email-otp", { body }));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { code?: string }).code).not.toBe("OTP_NOT_VALID");
    expect((await rows(db, sql`select 1 from "user"`)).length).toBe(before);
  });

  it("a body that is not JSON (a form) is refused before better-auth reads it", async () => {
    const res = await handler(
      new Request("https://app.example/api/auth/sign-in/email-otp", {
        method: "POST",
        headers: { origin: "https://app.example", "content-type": "application/x-www-form-urlencoded" },
        body: "email=a%40example.test&otp=123456",
      }),
    );
    expect(res.status).toBe(415);
    expect(await rows(db, sql`select 1 from "user"`)).toHaveLength(1);
  });

  it("with mail off, POST /sign-in/email-otp → 404", async () => {
    const off: Mailer = { configured: false, send: () => Promise.resolve({ ok: false, reason: "not_configured" }) };
    const res = await testAuth(db, { mailer: off }).handler(
      authRequest("/sign-in/email-otp", { body: { email: EXISTING.email, otp: "123456" } }),
    );
    expect(res.status).toBe(404);
  });
});

describe("the code is only sent with the magic link", () => {
  it("the standalone send route and the other code routes answer 404 over HTTP, and nothing is sent", async () => {
    for (const path of ["/email-otp/send-verification-otp", "/forget-password/email-otp", "/email-otp/check-verification-otp"]) {
      const res = await handler(authRequest(path, { body: { email: EXISTING.email, type: "sign-in" } }));
      expect(res.status, path).toBe(404);
    }
    expect(mailer.sent).toEqual([]);
    expect(await rows(db, sql`select 1 from verification`)).toHaveLength(0);
  });

  it("better-auth registers /sign-in/email-otp on the instance", () => {
    const paths = Object.values(auth.api as Record<string, { path?: string }>).map((e) => e.path);
    expect(paths).toContain("/sign-in/email-otp");
  });
});

describe("nothing in clear", () => {
  it("a send and four checks (right, wrong, expired, exhausted) leave neither the code nor the email in any log", async () => {
    const lines: string[] = [];
    const capture = (...args: unknown[]) => {
      lines.push(args.map((a) => (a instanceof Error ? `${a.message} ${a.stack ?? ""}` : String(a))).join(" "));
    };
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation(capture),
    );
    const emails = ["right@example.test", "wrong@example.test", "spent@example.test", "late@example.test"] as const;
    try {
      const codes = [await ask(emails[0]), await ask(emails[1]), await ask(emails[2]), await ask(emails[3])];
      expect((await verify(emails[0], codes[0] ?? "")).status).toBe(200);
      await verify(emails[1], wrong(codes[1] ?? ""));
      for (let i = 1; i <= EMAIL_CODE.allowedAttempts; i++) await verify(emails[2], wrong(codes[2] ?? "", i));
      await verify(emails[2], codes[2] ?? "");
      pastExpiry();
      await verify(emails[3], codes[3] ?? "");
      const all = lines.join("\n");
      for (const secret of [...codes, ...emails]) expect(all).not.toContain(secret);
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });

  it("in `verification`, neither the code nor the email in clear in the code's row", async () => {
    const email = "sweep@example.test";
    const code = await ask(email);
    const stored = await rows<Record<string, unknown>>(db, sql`select * from verification`);
    expect(stored).toHaveLength(2);
    const text = (row: Record<string, unknown>) =>
      Object.values(row)
        .filter((v): v is string => typeof v === "string")
        .join("\n");
    for (const row of stored) expect(text(row)).not.toContain(code);
    const codeRows = stored.filter((row) => !String(row.identifier).startsWith("magic-link:"));
    expect(codeRows).toHaveLength(1);
    for (const row of codeRows) {
      expect(text(row)).not.toContain(email);
      expect(text(row)).not.toContain("sign-in-otp-");
    }
  });
});
