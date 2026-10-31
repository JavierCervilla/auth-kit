// No better-auth route is open by accident. `auth.handler` is an allowlist: everything not in it answers 404 without
// entering better-auth, also the routes a future version adds. This test walks EVERY endpoint the real instance
// registers (core and plugins), with mail off and on. The database is untouchable: a request that reached better-auth
// and looked anything up would count a call.
import { describe, expect, it } from "vitest";

import { ALWAYS_OPEN_ROUTES, createAuth, EMAIL_ROUTES, type AuthKit, type Mailer } from "../../src/index.js";
import { exposedRoutes, type AuthRoute } from "../../src/core/route-allowlist.js";

const ORIGIN = "https://app.example";
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;

let touched = 0;
const untouchable = {
  execute: () => {
    touched += 1;
    return Promise.reject(new Error("touched"));
  },
  transaction: () => {
    touched += 1;
    return Promise.reject(new Error("touched"));
  },
};

const mailer: Mailer = { configured: true, send: () => Promise.resolve({ ok: true }) };

function build(withMail: boolean): AuthKit {
  return createAuth({
    db: untouchable,
    baseURL: ORIGIN,
    secret: "s".repeat(32),
    email: { render: () => ({ subject: "", text: "", html: "" }) },
    onGuestToAccount: () => Promise.resolve(),
    env: {},
    log: () => {},
    ...(withMail ? { mailer } : {}),
  });
}

const off = build(false);
const on = build(true);

function endpointPaths(auth: AuthKit): string[] {
  const paths = Object.values(auth.api as Record<string, { path?: string }>)
    .map((endpoint) => endpoint.path)
    .filter((path): path is string => typeof path === "string");
  return [...new Set(paths)].sort();
}

const request = (method: string, path: string, cookie = "better-auth.session_token=x.y") =>
  new Request(`${ORIGIN}/api/auth${path}`, {
    method,
    headers: { origin: ORIGIN, "content-type": "application/json", cookie },
    ...(method === "GET" ? {} : { body: "{}" }),
  });

async function expectClosed(auth: AuthKit, method: string, path: string): Promise<void> {
  const before = touched;
  const res = await auth.handler(request(method, path));
  expect(res.status, `${method} ${path}`).toBe(404);
  expect(await res.text(), `${method} ${path}`).toBe("Not Found");
  expect(touched, `${method} ${path} reached better-auth`).toBe(before);
}

const concrete = (path: string) => path.replace(":id", "google").replace(":token", "x");
const isOpen = (routes: readonly AuthRoute[], method: string, path: string) =>
  routes.some((r) => r.method === method && r.path === path);

describe("the allowlist", () => {
  it("is GET /get-session, plus the three email routes with mail on", () => {
    expect(ALWAYS_OPEN_ROUTES).toEqual([{ method: "GET", path: "/get-session" }]);
    expect(EMAIL_ROUTES).toEqual([
      { method: "POST", path: "/sign-in/magic-link" },
      { method: "GET", path: "/magic-link/verify" },
      { method: "POST", path: "/sign-in/email-otp" },
    ]);
    expect(exposedRoutes(false)).toEqual(ALWAYS_OPEN_ROUTES);
    expect(exposedRoutes(true)).toEqual([...ALWAYS_OPEN_ROUTES, ...EMAIL_ROUTES]);
  });

  it("better-auth registers many routes the package does not use (if the count changes, review the allowlist)", () => {
    const paths = endpointPaths(off);
    for (const path of ["/sign-in/anonymous", "/delete-anonymous-user", "/sign-up/email", "/sign-in/email", "/sign-out"]) {
      expect(paths).toContain(path);
    }
    expect(paths.length).toBeGreaterThan(20);
    expect(paths).not.toContain("/sign-in/magic-link");
    expect(endpointPaths(on)).toEqual(expect.arrayContaining(EMAIL_ROUTES.map((r) => r.path)));
  });
});

describe("closed routes answer 404 without reaching better-auth", () => {
  it.each([
    ["mail off", off, false],
    ["mail on", on, true],
  ] as const)("%s: every registered endpoint not allowlisted, with every method", async (_case, auth, mail) => {
    const open = exposedRoutes(mail);
    for (const path of endpointPaths(auth).map(concrete)) {
      for (const method of METHODS) {
        if (!isOpen(open, method, path)) await expectClosed(auth, method, path);
      }
    }
  });

  it("POST /sign-in/anonymous and /delete-anonymous-user: guests are created only by signInAnonymously", async () => {
    for (const auth of [off, on]) {
      await expectClosed(auth, "POST", "/sign-in/anonymous");
      await expectClosed(auth, "POST", "/delete-anonymous-user");
    }
  });

  it("with mail on, every other emailOTP route is closed: the code is only sent with the magic link", async () => {
    const otpPaths = endpointPaths(on).filter((p) => p.includes("email-otp") && p !== "/sign-in/email-otp");
    expect(otpPaths).toEqual(
      expect.arrayContaining([
        "/email-otp/send-verification-otp",
        "/email-otp/check-verification-otp",
        "/email-otp/verify-email",
        "/email-otp/reset-password",
        "/forget-password/email-otp",
      ]),
    );
    for (const path of otpPaths) for (const method of METHODS) await expectClosed(on, method, path);
  });

  it("with mail off, the email routes answer the same 404 as any other", async () => {
    for (const route of EMAIL_ROUTES) await expectClosed(off, route.method, route.path);
  });

  it("variants of an open route (trailing slash, double slash, upper case, encoded, longer) are 404", async () => {
    for (const variant of ["/get-session/", "//get-session", "/GET-SESSION", "/get%2Dsession", "/get-session/x"]) {
      await expectClosed(on, "GET", variant);
    }
  });

  it("a path outside /api/auth and a route never registered are 404", async () => {
    const before = touched;
    for (const url of [`${ORIGIN}/get-session`, `${ORIGIN}/api/auth/some-future-route`]) {
      expect((await on.handler(new Request(url))).status, url).toBe(404);
    }
    expect(touched).toBe(before);
  });

  it("GET /get-session does reach better-auth", async () => {
    const res = await on.handler(new Request(`${ORIGIN}/api/auth/get-session`));
    expect(res.status).toBe(200);
    expect(await res.json()).toBeNull();
  });
});
