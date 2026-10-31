/** How a refused guest-to-account link answers: a redirect for the magic link, a 409 for the email code. */
import { APIError } from "better-auth/api";

import type { GuestToAccountRefusal } from "./types.js";

const DEFAULT_MESSAGE = "This email cannot be linked to the current guest.";

export interface RedirectQuery {
  callbackURL?: unknown;
  errorCallbackURL?: unknown;
}

const nonEmpty = (value: unknown): value is string => typeof value === "string" && value !== "";

/**
 * Where the page gets the refusal back: its `errorCallbackURL` (or `callbackURL`), only if it is on the app's own
 * origin; otherwise the app's root. The refusal's details become query parameters, and `error` its code.
 */
export function refusalURL(baseURL: string, query: RedirectQuery | undefined, refusal: GuestToAccountRefusal): string {
  const raw = [query?.errorCallbackURL, query?.callbackURL].find(nonEmpty);
  const own = new URL(baseURL).origin;
  let url = new URL(raw ?? "/", baseURL);
  if (url.origin !== own) url = new URL("/", baseURL);
  for (const [name, value] of Object.entries(refusal.details ?? {})) url.searchParams.set(name, value);
  url.searchParams.set("error", refusal.code);
  return url.toString();
}

/** The 409 of the email-code route: the same code the magic link's redirect names, with the details. */
export function refusalError(refusal: GuestToAccountRefusal): APIError {
  return new APIError("CONFLICT", {
    ...refusal.details,
    code: refusal.code,
    message: refusal.message ?? DEFAULT_MESSAGE,
  });
}
