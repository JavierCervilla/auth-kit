/**
 * Which better-auth routes are reachable over HTTP. An allowlist: everything else answers 404 without entering
 * better-auth, including whatever a future version or a new plugin adds. Opening a route is one line here, with its
 * reason, and its case in the allowlist test.
 *
 * Open:
 * - GET /get-session: the own session or `null`. Read-only, and the route that renews the cookie (`updateAge`) from the
 *   browser: for a guest, losing the cookie is losing the profile.
 * - With mail on: ask for the sign-in email (send limit in front), open the magic link (where a guest becomes an
 *   account) and check the code from the same email (closed body and check limit in front). No other `emailOTP` route:
 *   the code is only sent together with the link.
 *
 * Closed on purpose (not exhaustive; the test walks every registered endpoint):
 * - POST /sign-in/anonymous: guests are created only by the server, with `signInAnonymously()` after the sign-up limit.
 *   Open, anyone could create guests at will (CWE-770).
 * - POST /delete-anonymous-user: deleting a user is the project's business, with its own side effects.
 * - POST /sign-out, email and password, email change, accounts and sessions: the package uses none of them.
 */
import { AUTH_BASE_PATH, EMAIL_CODE_VERIFY_PATH, MAGIC_LINK_VERIFY_PATH, SEND_SIGN_IN_EMAIL_PATH } from "./routes.js";

export interface AuthRoute {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Path relative to AUTH_BASE_PATH, exact. */
  path: string;
}

export const ALWAYS_OPEN_ROUTES: readonly AuthRoute[] = [{ method: "GET", path: "/get-session" }];

export const EMAIL_ROUTES: readonly AuthRoute[] = [
  { method: "POST", path: SEND_SIGN_IN_EMAIL_PATH },
  { method: "GET", path: MAGIC_LINK_VERIFY_PATH },
  { method: "POST", path: EMAIL_CODE_VERIFY_PATH },
];

/** The allowlist for what is on: without mail, its routes answer the same 404 as any other. */
export function exposedRoutes(emailOn: boolean): readonly AuthRoute[] {
  return emailOn ? [...ALWAYS_OPEN_ROUTES, ...EMAIL_ROUTES] : ALWAYS_OPEN_ROUTES;
}

/** The allowlisted route a request targets, matched exactly on method and path, or undefined. */
export function exposedRoute(request: Request, routes: readonly AuthRoute[]): AuthRoute | undefined {
  const { pathname } = new URL(request.url);
  if (!pathname.startsWith(`${AUTH_BASE_PATH}/`)) return undefined;
  const path = pathname.slice(AUTH_BASE_PATH.length);
  return routes.find((route) => route.method === request.method && route.path === path);
}

export const notFound = (): Response =>
  new Response("Not Found", { status: 404, headers: { "Cache-Control": "no-store" } });
