// What `createAuth` accepts: the secret, the base URL and the extra trusted origins, plus the environment better-auth
// reads by itself. Errors name the option and never repeat its value.
import { describe, expect, it } from "vitest";

import { resolveSettings, type SettingsInput } from "../../src/core/settings.js";

const SECRET = "s".repeat(32);
const BASE: SettingsInput = { secret: SECRET, baseURL: "https://app.example", env: {} };

function errorOf(input: SettingsInput): string {
  try {
    resolveSettings(input);
  } catch (error) {
    return (error as Error).message;
  }
  return "";
}

describe("secret", () => {
  it("empty or shorter than 32 characters: refused, without the value", () => {
    expect(errorOf({ ...BASE, secret: "" })).toContain("secret");
    expect(errorOf({ ...BASE, secret: "short-one" })).toContain("secret");
    expect(errorOf({ ...BASE, secret: "short-one" })).not.toContain("short-one");
  });
});

describe("baseURL", () => {
  it("not a URL, or not http(s): refused", () => {
    for (const url of ["not a url", "ftp://app.example"]) expect(errorOf({ ...BASE, baseURL: url }), url).toContain("baseURL");
  });

  // With a path, every URL better-auth builds would carry it.
  it("with a path, query or fragment: refused", () => {
    for (const url of ["https://app.example/app/", "https://app.example/app", "https://app.example/?a=1", "https://app.example/#x"]) {
      expect(errorOf({ ...BASE, baseURL: url }), url).toContain("baseURL must be just the origin");
      expect(errorOf({ ...BASE, baseURL: url }), url).not.toContain("app.example");
    }
  });

  // The value as WRITTEN is checked, not the URL after `new URL` normalised it.
  it("must be exactly the origin as written, with or without the slash", () => {
    for (const url of [
      "https://user:hunter2@app.example",
      "https://app.example.",
      "https://app.example ",
      " https://app.example",
      "HTTPS://App.example",
      "https://app.example:443",
      "https://app.example//",
    ]) {
      const message = errorOf({ ...BASE, baseURL: url });
      expect(message, JSON.stringify(url)).toContain("baseURL");
      expect(message).not.toContain("hunter2");
      expect(message).not.toContain("app.example");
    }
    for (const url of ["https://app.example", "https://app.example/", "http://localhost:3000", "https://app.local"]) {
      expect(() => resolveSettings({ ...BASE, baseURL: url }), url).not.toThrow();
    }
  });
});

describe("secure cookies", () => {
  it("in production always, even over http", () => {
    expect(resolveSettings({ ...BASE, baseURL: "http://app.example", env: { NODE_ENV: "production" } }).secureCookies).toBe(
      true,
    );
  });

  it("outside production, secure over https and not over http (local development)", () => {
    const env = { NODE_ENV: "development" };
    expect(resolveSettings({ ...BASE, baseURL: "https://app.local", env }).secureCookies).toBe(true);
    expect(resolveSettings({ ...BASE, baseURL: "http://localhost:3000", env }).secureCookies).toBe(false);
  });
});

describe("BETTER_AUTH_TELEMETRY", () => {
  it("1 or true: refused; unset, empty or 0: accepted", () => {
    expect(errorOf({ ...BASE, env: { BETTER_AUTH_TELEMETRY: "1" } })).toContain("BETTER_AUTH_TELEMETRY");
    expect(errorOf({ ...BASE, env: { BETTER_AUTH_TELEMETRY: "true" } })).toContain("BETTER_AUTH_TELEMETRY");
    for (const value of [undefined, "", "0"]) {
      expect(() => resolveSettings({ ...BASE, env: { BETTER_AUTH_TELEMETRY: value } })).not.toThrow();
    }
  });
});

describe("trustedOrigins", () => {
  it("none by default", () => {
    expect(resolveSettings(BASE).trustedOrigins).toEqual([]);
  });

  it("keeps each origin once and drops the base URL's", () => {
    const settings = resolveSettings({
      ...BASE,
      trustedOrigins: ["https://app.example", "https://second.example", "https://second.example", "http://localhost:3001"],
    });
    expect(settings.trustedOrigins).toEqual(["https://second.example", "http://localhost:3001"]);
  });

  it("each entry, as written, must be exactly one origin; the error does not repeat it", () => {
    for (const bad of [
      "https://app?.second.example",
      " https://second.example",
      "https://second.example/",
      "https://second.example/a/path",
      "https://second.example?x=1",
      "https://Second.example",
      "",
    ]) {
      const message = errorOf({ ...BASE, trustedOrigins: [bad] });
      expect(message, bad).toContain("trustedOrigins entry 1");
      expect(message, bad).not.toContain("second");
    }
  });

  it("not an http(s) URL: refused without the value", () => {
    for (const bad of ["second.example", "ftp://second.example", "javascript:alert(1)"]) {
      const message = errorOf({ ...BASE, trustedOrigins: [bad] });
      expect(message, bad).toContain("trustedOrigins");
      expect(message, bad).not.toContain("second");
      expect(message, bad).not.toContain("alert");
    }
  });

  // `new URL("https://*.example.org")` is valid and better-auth would honour the wildcard.
  it("a wildcard host: refused without the value", () => {
    for (const bad of ["https://*.example.org", "http://*:3000", "https://app.*.org"]) {
      const message = errorOf({ ...BASE, trustedOrigins: [bad] });
      expect(message, bad).toContain("wildcard");
      expect(message, bad).not.toContain("example.org");
      expect(message, bad).not.toContain("*");
    }
  });

  it("BETTER_AUTH_TRUSTED_ORIGINS, which better-auth reads raw, follows the same rules", () => {
    expect(() =>
      resolveSettings({ ...BASE, env: { BETTER_AUTH_TRUSTED_ORIGINS: "https://second.example,http://localhost:3001" } }),
    ).not.toThrow();
    for (const bad of ["https://*.second.example", "https://second.example ,http://localhost:3001", "https://second.example,"]) {
      const message = errorOf({ ...BASE, env: { BETTER_AUTH_TRUSTED_ORIGINS: bad } });
      expect(message, bad).toContain("BETTER_AUTH_TRUSTED_ORIGINS");
      expect(message, bad).not.toContain("second");
    }
    expect(() => resolveSettings({ ...BASE, env: { BETTER_AUTH_TRUSTED_ORIGINS: "  " } })).not.toThrow();
  });
});
