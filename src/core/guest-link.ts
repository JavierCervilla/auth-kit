/**
 * What better-auth calls when a guest becomes an account.
 *
 * Behaviour pinned by the integration tests: opening the magic link of an email that already has an account opens a
 * session of THAT account (it does not create another), and the anonymous plugin calls `onLinkAccount` AFTER creating
 * the new session and setting its cookie; then it deletes the guest and, if the delete fails (a row still pointing to
 * it), swallows the error and only logs it. Hence:
 * - `onGuestToAccount` moves the guest's data before that delete;
 * - `guardGuestToAccount` runs BEFORE, in a hook in front of the magic link and the code: whoever brings a live token
 *   or the right code has proven the email is theirs, and from there the link can be refused with no side effect (token
 *   unused, no new session, no cookie). If `onLinkAccount` refused instead, the new session and its cookie would
 *   already be set.
 * - If a refusal still shows up between the guard and the move (a race), the move refuses: the transaction rolls back,
 *   the new session is deleted, the guest's cookie is put back and the answer is the guard's.
 *
 * With the email code the email is proven when the code MATCHES. The guard looks at the latest code row of that email
 * and, if it is live, has attempts left and its hash matches in constant time, asks the guard; a refusal is a 409
 * without consuming the code. A wrong code does nothing here and the plugin counts the attempt.
 */
import { timingSafeEqual } from "node:crypto";

import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import type { AnonymousOptions } from "better-auth/plugins/anonymous";

import { EMAIL_CODE } from "./policies.js";
import { refusalError, refusalURL, type RedirectQuery } from "./refusal.js";
import { EMAIL_CODE_VERIFY_PATH, MAGIC_LINK_VERIFY_PATH } from "./routes.js";
import { hashToken } from "./token-hash.js";
import type { AuthDatabase, AuthKitOptions, GuestToAccount, GuestToAccountRefusal, TransactionOf } from "./types.js";

type GuardContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
type Guard = NonNullable<AuthKitOptions<AuthDatabase>["guardGuestToAccount"]>;
type OnLinkAccount = NonNullable<AnonymousOptions["onLinkAccount"]>;

const magicLinkIdentifier = (token: string) => `magic-link:${hashToken(token)}`;

function emailOf(value: string): string | null {
  try {
    const parsed = JSON.parse(value) as { email?: unknown };
    return typeof parsed.email === "string" ? parsed.email : null;
  } catch {
    return null;
  }
}

function sameHash(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** The code's email, if `otp` matches the latest live row of that email with attempts left (as `emailOTP`, unspent). */
async function provenByCode(ctx: GuardContext): Promise<string | null> {
  const body = ctx.body as { email?: unknown; otp?: unknown } | undefined;
  if (typeof body?.email !== "string" || typeof body.otp !== "string") return null;
  const email = body.email.toLowerCase();
  const pending = await ctx.context.internalAdapter.findVerificationValue(`sign-in-otp-${email}`);
  if (!pending || pending.expiresAt.getTime() <= Date.now()) return null;
  const separator = pending.value.lastIndexOf(":");
  const stored = separator === -1 ? pending.value : pending.value.slice(0, separator);
  const attempts = separator === -1 ? 0 : Number.parseInt(pending.value.slice(separator + 1) || "0", 10);
  if (!(attempts < EMAIL_CODE.allowedAttempts)) return null;
  return sameHash(hashToken(body.otp), stored) ? email : null;
}

/** The email the request has already proven: the live magic-link token's, or the matching code's. */
async function provenEmail(ctx: GuardContext): Promise<string | null> {
  if (ctx.path === EMAIL_CODE_VERIFY_PATH) return provenByCode(ctx);
  const token: unknown = ctx.query?.token;
  if (typeof token !== "string" || token === "") return null;
  // A token that does not exist or expired is refused by the plugin; only a live one matters here.
  const pending = await ctx.context.internalAdapter.findVerificationValue(magicLinkIdentifier(token));
  if (!pending || pending.expiresAt.getTime() <= Date.now()) return null;
  return emailOf(pending.value);
}

/** Answers a refusal the way the route expects: 409 on the code route, a redirect on the magic link. */
function refuse(ctx: GuardContext, refusal: GuestToAccountRefusal): never {
  if (ctx.path === EMAIL_CODE_VERIFY_PATH) throw refusalError(refusal);
  throw ctx.redirect(refusalURL(ctx.context.baseURL, ctx.query as RedirectQuery | undefined, refusal));
}

/** In front of opening the magic link or checking the code: the project's guard, with no side effect. */
export async function guardGuestLink(ctx: GuardContext, guard: Guard): Promise<void> {
  if (ctx.path !== MAGIC_LINK_VERIFY_PATH && ctx.path !== EMAIL_CODE_VERIFY_PATH) return;
  const session = await getSessionFromCtx(ctx, { disableRefresh: true });
  if (!session || (session.user as { isAnonymous?: boolean | null }).isAnonymous !== true) return;
  const email = await provenEmail(ctx);
  if (!email) return;
  const existing = await ctx.context.internalAdapter.findUserByEmail(email.toLowerCase());
  const refusal = await guard({ guestUserId: session.user.id, email, accountUserId: existing?.user.id ?? null });
  if (refusal) refuse(ctx, refusal);
}

class RefusedMove extends Error {
  constructor(readonly refusal: GuestToAccountRefusal) {
    super("guest-to-account move refused");
  }
}

/** Runs the project's move in one transaction; a refusal rolls it back and comes back as the result. */
async function moveGuest<TDb extends AuthDatabase>(
  db: TDb,
  move: AuthKitOptions<TDb>["onGuestToAccount"],
  link: GuestToAccount,
): Promise<GuestToAccountRefusal | null> {
  try {
    await db.transaction(async (tx) => {
      // `tx` is whatever this database's `transaction` hands out, which is what TransactionOf<TDb> names.
      const refusal = await move(tx as TransactionOf<TDb>, link);
      if (refusal) throw new RefusedMove(refusal);
    });
    return null;
  } catch (error) {
    if (error instanceof RefusedMove) return error.refusal;
    throw error;
  }
}

/** The anonymous plugin's `onLinkAccount`: the project's move, with the race safety net. */
export function onLinkAccount<TDb extends AuthDatabase>(
  db: TDb,
  move: AuthKitOptions<TDb>["onGuestToAccount"],
): OnLinkAccount {
  return async ({ anonymousUser, newUser, ctx }) => {
    const link = { guestUserId: anonymousUser.user.id, accountUserId: newUser.user.id };
    const refusal = await moveGuest(db, move, link);
    if (!refusal) return;
    await ctx.context.internalAdapter.deleteSession(newUser.session.token);
    await setSessionCookie(ctx, { session: anonymousUser.session, user: anonymousUser.user });
    refuse(ctx, refusal);
  };
}
