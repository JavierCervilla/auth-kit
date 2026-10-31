// The pure pieces around better-auth's routes: where a refusal sends the page back, the closed body of the code route,
// the single code error over HTTP, the email's locale and the send-limit 429.
import { describe, expect, it } from "vitest";

import { assertClosedCodeBody, sameCodeErrorStatus } from "../../src/core/email-code-route.js";
import { refusalError, refusalURL } from "../../src/core/refusal.js";
import { rateLimitedError } from "../../src/core/send-limit.js";
import { localeOf } from "../../src/core/sign-in-email.js";

const BASE = "https://app.example/api/auth";
const REFUSAL = { code: "REFUSED", details: { world: "w-1", error: "ignored" } };

describe("refusalURL", () => {
  it("goes back to errorCallbackURL, then callbackURL, then the root, on the app's own origin", () => {
    expect(refusalURL(BASE, { errorCallbackURL: "/account", callbackURL: "/" }, REFUSAL)).toBe(
      "https://app.example/account?world=w-1&error=REFUSED",
    );
    expect(refusalURL(BASE, { callbackURL: "/play" }, REFUSAL)).toBe("https://app.example/play?world=w-1&error=REFUSED");
    expect(refusalURL(BASE, undefined, REFUSAL)).toBe("https://app.example/?world=w-1&error=REFUSED");
  });

  it("never follows another origin, and a detail cannot override the error code", () => {
    const url = new URL(refusalURL(BASE, { errorCallbackURL: "https://evil.example/x" }, REFUSAL));
    expect(url.origin).toBe("https://app.example");
    expect(url.pathname).toBe("/");
    expect(url.searchParams.getAll("error")).toEqual(["REFUSED"]);
  });
});

describe("refusalError", () => {
  it("is a 409 with the code, a message and the details, which cannot override the code", () => {
    const error = refusalError(REFUSAL);
    expect(error.statusCode).toBe(409);
    expect(error.body).toEqual({ world: "w-1", error: "ignored", code: "REFUSED", message: expect.any(String) });
  });
});

describe("assertClosedCodeBody", () => {
  const json = new Request(`${BASE}/sign-in/email-otp`, { method: "POST", headers: { "content-type": "application/json" } });

  it("accepts exactly { email, otp } as strings", () => {
    expect(() => assertClosedCodeBody({ request: json, body: { otp: "123456", email: "a@example.test" } })).not.toThrow();
  });

  it.each([
    ["an extra field", { email: "a@example.test", otp: "123456", name: "x" }],
    ["a missing field", { email: "a@example.test" }],
    ["a number", { email: "a@example.test", otp: 123456 }],
    ["an array", [{ email: "a@example.test", otp: "123456" }]],
    ["null", null],
  ])("refuses %s with a 400", (_case, body) => {
    expect(() => assertClosedCodeBody({ request: json, body })).toThrow(expect.objectContaining({ statusCode: 400 }));
  });

  it("refuses a body that is not JSON", () => {
    const form = new Request(`${BASE}/sign-in/email-otp`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    expect(() => assertClosedCodeBody({ request: form, body: { email: "a", otp: "1" } })).toThrow();
  });
});

describe("sameCodeErrorStatus", () => {
  const codeRoute = new Request(`${BASE}/sign-in/email-otp`, { method: "POST" });

  it("turns the exhausted code's 403 into the same 400 as the others", async () => {
    const res = await sameCodeErrorStatus(codeRoute, Response.json({ code: "OTP_NOT_VALID" }, { status: 403 }));
    expect(res.status).toBe(400);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.text()).toBe(JSON.stringify({ code: "OTP_NOT_VALID" }));
  });

  it("leaves any other answer and any other route alone", async () => {
    const forbidden = Response.json({ code: "INVALID_ORIGIN" }, { status: 403 });
    expect(await sameCodeErrorStatus(codeRoute, forbidden)).toBe(forbidden);
    const other = Response.json({ code: "OTP_NOT_VALID" }, { status: 403 });
    expect(await sameCodeErrorStatus(new Request(`${BASE}/get-session`), other)).toBe(other);
  });
});

describe("localeOf", () => {
  it("takes the first Accept-Language tag, or null", () => {
    expect(localeOf(new Headers({ "accept-language": "es-ES,es;q=0.9" }))).toBe("es-ES");
    expect(localeOf(new Headers({ "accept-language": "fr;q=0.8" }))).toBe("fr");
    expect(localeOf(new Headers())).toBeNull();
    expect(localeOf(undefined)).toBeNull();
  });
});

describe("rateLimitedError", () => {
  it("is a 429 with Retry-After, no-store and one body for every case", () => {
    const error = rateLimitedError(42);
    expect(error.statusCode).toBe(429);
    expect(new Headers(error.headers).get("retry-after")).toBe("42");
    expect(new Headers(error.headers).get("cache-control")).toBe("no-store");
    expect(error.body).toEqual(rateLimitedError(3600).body);
  });
});
