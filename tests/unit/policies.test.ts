import { describe, expect, it } from "vitest";

import { EMAIL_CODE, MAGIC_LINK_EXPIRES_IN_SECONDS, SEND_LIMITS, SESSION } from "../../src/index.js";

// Boundary values: the exact numbers are the policy (docs/design.md), so a change here must be a deliberate,
// versioned breaking change, never a drive-by edit.
describe("fixed policies", () => {
  it("expires a magic link after 10 minutes", () => {
    expect(MAGIC_LINK_EXPIRES_IN_SECONDS).toBe(600);
  });

  it("gives the email code 6 digits, the link's expiry and 3 attempts", () => {
    expect(EMAIL_CODE).toEqual({ length: 6, expiresInSeconds: 600, allowedAttempts: 3 });
  });

  it("keeps a session 180 days and renews it at most daily", () => {
    expect(SESSION).toEqual({ expiresInSeconds: 15_552_000, updateAgeSeconds: 86_400 });
  });

  it("limits sends to 5 per hour per email and 20 per hour per IP", () => {
    expect(SEND_LIMITS.perEmail).toEqual({ hits: 5, windowSeconds: 3600 });
    expect(SEND_LIMITS.perIp).toEqual({ hits: 20, windowSeconds: 3600 });
  });
});
