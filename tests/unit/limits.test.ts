// The usage limits from the environment (Tercer Tiempo's variable names) and from the `limits` option: unset means the
// default; a blank, non-integer, zero or negative value is a start-up error naming the setting, never echoing the value.
import { describe, expect, it } from "vitest";

import { DEFAULT_LIMITS, LIMIT_VARIABLES, limitsFromEnv } from "../../src/index.js";
import { resolveLimits } from "../../src/rate-limit/config.js";

describe("limitsFromEnv", () => {
  it("with no variables, the defaults", () => {
    expect(limitsFromEnv({})).toEqual(DEFAULT_LIMITS);
  });

  it("reads each variable by Tercer Tiempo's name", () => {
    expect(LIMIT_VARIABLES).toEqual({
      sendPerEmailPerHour: "RATE_LIMIT_MAGIC_LINK_EMAIL_PER_HOUR",
      sendPerIpPerHour: "RATE_LIMIT_MAGIC_LINK_IP_PER_HOUR",
      codeCheckPerEmailPerDay: "RATE_LIMIT_OTP_VERIFY_EMAIL_PER_DAY",
      codeCheckPerIpPerHour: "RATE_LIMIT_OTP_VERIFY_IP_PER_HOUR",
      guestSignUpPerIpPerHour: "RATE_LIMIT_ANON_SIGNUP_PER_HOUR",
      guestSignUpGlobalPerHour: "RATE_LIMIT_ANON_SIGNUP_GLOBAL_PER_HOUR",
    });
    const env = Object.fromEntries(Object.values(LIMIT_VARIABLES).map((name, i) => [name, String(100 + i)]));
    expect(limitsFromEnv(env)).toEqual({
      sendPerEmailPerHour: 100,
      sendPerIpPerHour: 101,
      codeCheckPerEmailPerDay: 102,
      codeCheckPerIpPerHour: 103,
      guestSignUpPerIpPerHour: 104,
      guestSignUpGlobalPerHour: 105,
    });
  });

  it("only what is set changes", () => {
    expect(limitsFromEnv({ RATE_LIMIT_ANON_SIGNUP_PER_HOUR: "7" })).toEqual({ ...DEFAULT_LIMITS, guestSignUpPerIpPerHour: 7 });
  });

  it.each(["", " ", "0", "-3", "1.5", "12abc", " 12", "1e3", "99999999999999999999"])(
    "%j is a start-up error naming the variable and not echoing the value",
    (raw) => {
      let message = "";
      try {
        limitsFromEnv({ RATE_LIMIT_OTP_VERIFY_IP_PER_HOUR: raw });
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toContain("RATE_LIMIT_OTP_VERIFY_IP_PER_HOUR");
      if (raw.trim() !== "") expect(message).not.toContain(raw.trim());
    },
  );
});

describe("resolveLimits: the option merged over the defaults", () => {
  it("absent or empty, the defaults; partial, only those keys change", () => {
    expect(resolveLimits(undefined)).toEqual(DEFAULT_LIMITS);
    expect(resolveLimits({})).toEqual(DEFAULT_LIMITS);
    expect(resolveLimits({ sendPerIpPerHour: 2, codeCheckPerEmailPerDay: 3 })).toEqual({
      ...DEFAULT_LIMITS,
      sendPerIpPerHour: 2,
      codeCheckPerEmailPerDay: 3,
    });
  });

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])("%s is refused, naming the limit", (value) => {
    expect(() => resolveLimits({ guestSignUpGlobalPerHour: value })).toThrow("limits.guestSignUpGlobalPerHour");
  });
});
