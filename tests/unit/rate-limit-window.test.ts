// The integration tests' wait before exhausting a quota: nothing with room left, else until the next window.
import { describe, expect, it } from "vitest";

import { WINDOW_CUSHION_MS, waitBeforeExhaustingMs } from "../integration/rate-limit-window.js";

describe("waitBeforeExhaustingMs", () => {
  it("no wait while the window has at least the margin left", () => {
    expect(waitBeforeExhaustingMs(15, 15)).toBe(0);
    expect(waitBeforeExhaustingMs(3000, 15)).toBe(0);
  });

  it("under the margin, what is left plus the cushion", () => {
    expect(waitBeforeExhaustingMs(14.2, 15)).toBe(14_200 + WINDOW_CUSHION_MS);
    expect(waitBeforeExhaustingMs(-1, 15)).toBe(WINDOW_CUSHION_MS);
  });

  it("refuses inputs that are not numbers", () => {
    expect(() => waitBeforeExhaustingMs(Number.NaN, 15)).toThrow();
    expect(() => waitBeforeExhaustingMs(10, -1)).toThrow();
  });
});
