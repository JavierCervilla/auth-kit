import { describe, expect, it } from "vitest";

import { DEFAULT_LIMITS, EMAIL_CODE, MAGIC_LINK_EXPIRES_IN_SECONDS, SESSION } from "../../src/index.js";

// Boundary values: the exact numbers are the policy (docs/design.md), so a change here must be a deliberate,
// versioned breaking change, never a drive-by edit.
describe("fixed guarantees", () => {
  it("expires a magic link after 10 minutes", () => {
    expect(MAGIC_LINK_EXPIRES_IN_SECONDS).toBe(600);
  });

  it("gives the email code 6 digits, the link's expiry and 3 attempts", () => {
    expect(EMAIL_CODE).toEqual({ length: 6, expiresInSeconds: 600, allowedAttempts: 3 });
  });

  it("keeps a session 180 days and renews it at most daily", () => {
    expect(SESSION).toEqual({ expiresInSeconds: 15_552_000, updateAgeSeconds: 86_400 });
  });
});

// The usage limits are configurable; these are their defaults, Tercer Tiempo's values.
describe("default limits", () => {
  it("are Tercer Tiempo's: sends 5/h per email and 20/h per IP, code checks 10/day per email and 30/h per IP, guests 30/h per IP and 1000/h in total", () => {
    expect(DEFAULT_LIMITS).toEqual({
      sendPerEmailPerHour: 5,
      sendPerIpPerHour: 20,
      codeCheckPerEmailPerDay: 10,
      codeCheckPerIpPerHour: 30,
      guestSignUpPerIpPerHour: 30,
      guestSignUpGlobalPerHour: 1000,
    });
  });
});
