// A guest becomes an account with the magic link, against real better-auth and a real Postgres engine. The project's
// data lives in its own table (`game_save`, with a plain foreign key to `user`, as a consumer's would): what
// `onGuestToAccount` does not move would block deleting the guest. First what the plugin does with an email that
// already has an account: the link opens a session of THAT account and the plugin deletes the guest after the move.
import { randomUUID } from "node:crypto";

import { sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import type { AuthKit, GuestToAccountRefusal, GuestToAccountRequest } from "../../src/index.js";

import { authRequest, recordingMailer, testAuth, type TestOptions } from "./fixtures.js";
import {
  lastSessionCookie,
  openDatabase,
  ORIGIN,
  resetDatabase,
  rows,
  SESSION_COOKIE,
  type TestDatabase,
} from "./harness.js";

const EXISTING = { id: "existing-account", email: "existing@example.test" };
const REFUSAL: GuestToAccountRefusal = { code: "EMAIL_HAS_OTHER_PROFILE", details: { world: "w-1" } };

let db: TestDatabase;
const mailer = recordingMailer();
/** What the guard answers; null lets the link through. */
let guardAnswer: GuestToAccountRefusal | null = null;
/** What the move answers after moving (a refusal rolls the move back). */
let moveAnswer: GuestToAccountRefusal | null = null;
const guardCalls: GuestToAccountRequest[] = [];

const options: TestOptions = {
  mailer,
  guardGuestToAccount: (request) => {
    guardCalls.push(request);
    return Promise.resolve(guardAnswer);
  },
  onGuestToAccount: async (tx, { guestUserId, accountUserId }) => {
    await tx.execute(sql`update game_save set user_id = ${accountUserId} where user_id = ${guestUserId}`);
    return moveAnswer ?? undefined;
  },
};

let auth: AuthKit;

beforeAll(async () => {
  db = await openDatabase();
  await db.execute(sql`create table game_save (id text primary key, user_id text not null references "user"(id))`);
  auth = testAuth(db, options);
});

beforeEach(async () => {
  await db.execute(sql`truncate game_save`);
  await resetDatabase(db);
  mailer.sent.length = 0;
  guardCalls.length = 0;
  guardAnswer = null;
  moveAnswer = null;
  await db.execute(sql`
    insert into "user" (id, name, email, email_verified) values (${EXISTING.id}, '', ${EXISTING.email}, true)`);
});

afterAll(async () => {
  await db.$client.close();
});

/** A guest with its session, as the server creates it; returns its id and the browser's Cookie header. */
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
  const [row] = await rows<{ user_id: string }>(db, sql`select user_id from game_save where id = ${saveId}`);
  return row?.user_id;
}

async function userExists(id: string): Promise<boolean> {
  return (await rows(db, sql`select 1 from "user" where id = ${id}`)).length === 1;
}

async function askLink(cookie: string, email: string, errorCallbackURL = "/account"): Promise<string> {
  const asked = await auth.handler(
    authRequest("/sign-in/magic-link", { body: { email, callbackURL: "/", errorCallbackURL }, headers: { cookie } }),
  );
  expect(asked.status).toBe(200);
  return mailer.sent.at(-1)?.url ?? "";
}

/** Asks for the link with the guest's cookie and opens it with it, as its browser would. */
async function linkWith(cookie: string, email: string, errorCallbackURL?: string): Promise<Response> {
  const url = await askLink(cookie, email, errorCallbackURL);
  return auth.handler(new Request(url, { headers: { cookie } }));
}

function sessionCookieOf(response: Response): string | undefined {
  return response.headers
    .getSetCookie()
    .find((c) => c.startsWith(`${SESSION_COOKIE}=`) && !c.startsWith(`${SESSION_COOKIE}=;`));
}

async function sessionUser(cookie: string): Promise<string | null> {
  return (await auth.currentUser(new Headers({ cookie })))?.id ?? null;
}

describe("an email that already has an account", () => {
  it("every row of the guest moves to that account, the guest disappears and the session is the account's", async () => {
    const anon = await guest();
    const [first, second] = [await save(anon.userId), await save(anon.userId)];
    const theirs = await save(EXISTING.id);
    const res = await linkWith(anon.cookie, EXISTING.email);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`${ORIGIN}/`);
    expect([await ownerOf(first), await ownerOf(second), await ownerOf(theirs)]).toEqual([
      EXISTING.id,
      EXISTING.id,
      EXISTING.id,
    ]);
    expect(await userExists(anon.userId)).toBe(false);
    expect(await sessionUser((sessionCookieOf(res) ?? "").split(";")[0] ?? "")).toBe(EXISTING.id);
    expect(guardCalls).toEqual([{ guestUserId: anon.userId, email: EXISTING.email, accountUserId: EXISTING.id }]);
  });

  it("a new email creates the account and takes the rows", async () => {
    const anon = await guest();
    const mine = await save(anon.userId);
    const res = await linkWith(anon.cookie, "new@example.test");
    expect(res.status).toBe(302);
    const owner = await ownerOf(mine);
    expect(owner).not.toBe(anon.userId);
    expect(await userExists(anon.userId)).toBe(false);
    expect(guardCalls).toEqual([{ guestUserId: anon.userId, email: "new@example.test", accountUserId: null }]);
    expect(await rows(db, sql`select email from "user" where id = ${owner ?? ""}`)).toEqual([{ email: "new@example.test" }]);
  });

  it("without a guest session the link just signs in: no guard, no move", async () => {
    const other = await guest();
    const theirs = await save(other.userId);
    const url = await askLink("", EXISTING.email);
    const res = await auth.handler(new Request(url));
    expect(res.status).toBe(302);
    expect(guardCalls).toEqual([]);
    expect(await ownerOf(theirs)).toBe(other.userId);
  });
});

describe("the guard refuses: nothing is linked", () => {
  it("no row moves, the guest and its session stay, no cookie, and the redirect names the refusal", async () => {
    guardAnswer = REFUSAL;
    const anon = await guest();
    const mine = await save(anon.userId);
    const theirs = await save(EXISTING.id);
    const res = await linkWith(anon.cookie, EXISTING.email);
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location") ?? "");
    expect(location.origin).toBe(ORIGIN);
    expect(location.pathname).toBe("/account");
    expect(location.searchParams.get("error")).toBe(REFUSAL.code);
    expect(location.searchParams.get("world")).toBe("w-1");
    expect(sessionCookieOf(res)).toBeUndefined();
    expect(await ownerOf(mine)).toBe(anon.userId);
    expect(await ownerOf(theirs)).toBe(EXISTING.id);
    expect(await userExists(anon.userId)).toBe(true);
    expect(await sessionUser(anon.cookie)).toBe(anon.userId);
    expect(await rows(db, sql`select 1 from session where user_id = ${EXISTING.id}`)).toHaveLength(0);
  });

  it("the token stays unused: the same link still signs in from a browser without the guest", async () => {
    guardAnswer = REFUSAL;
    const anon = await guest();
    const url = await askLink(anon.cookie, EXISTING.email);
    expect((await auth.handler(new Request(url, { headers: { cookie: anon.cookie } }))).status).toBe(302);
    const elsewhere = await auth.handler(new Request(url));
    expect(await sessionUser((sessionCookieOf(elsewhere) ?? "").split(";")[0] ?? "")).toBe(EXISTING.id);
  });

  // better-auth already refuses a foreign callback when the link is asked for; refusal.ts falls back to the app's root
  // anyway (tests/unit/refusal.test.ts), in case a link carries one.
  it("an errorCallbackURL on another origin is refused when asking for the link", async () => {
    const anon = await guest();
    const asked = await auth.handler(
      authRequest("/sign-in/magic-link", {
        body: { email: EXISTING.email, callbackURL: "/", errorCallbackURL: "https://evil.example/steal" },
        headers: { cookie: anon.cookie },
      }),
    );
    expect(asked.status).toBe(403);
    expect(mailer.sent).toEqual([]);
  });

  it("asking for the link answers the same with a refusal ahead and without", async () => {
    guardAnswer = REFUSAL;
    const anon = await guest();
    const ask = (email: string) =>
      auth.handler(
        authRequest("/sign-in/magic-link", { body: { email, callbackURL: "/" }, headers: { cookie: anon.cookie } }),
      );
    const refused = await ask(EXISTING.email);
    const clean = await ask("new@example.test");
    expect(refused.status).toBe(clean.status);
    expect(await refused.text()).toBe(await clean.text());
    expect(guardCalls).toEqual([]);
  });
});

describe("the race: the guard lets it through and the move refuses", () => {
  it("the move is rolled back, the account's new session deleted and the guest's cookie put back", async () => {
    moveAnswer = REFUSAL;
    const anon = await guest();
    const mine = await save(anon.userId);
    const res = await linkWith(anon.cookie, EXISTING.email);
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location") ?? "");
    expect(location.pathname).toBe("/account");
    expect(location.searchParams.get("error")).toBe(REFUSAL.code);
    expect(await ownerOf(mine)).toBe(anon.userId);
    expect(await userExists(anon.userId)).toBe(true);
    expect(await rows(db, sql`select 1 from session where user_id = ${EXISTING.id}`)).toHaveLength(0);
    expect(await sessionUser(lastSessionCookie(res) ?? "")).toBe(anon.userId);
  });
});
