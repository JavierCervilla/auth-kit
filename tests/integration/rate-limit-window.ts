// Fixed windows of the send limit in the integration tests. The limiter counts by clock windows,
// `date_bin(<window>, now(), timestamptz 'epoch')`: a test that exhausts a quota and expects the 429 fails if its attempts
// fall on both sides of the hour, because the last one counts in the new window and passes. Before exhausting a quota,
// `untilWindowHasRoom` asks the database how long the current window has left and, if it is under the margin, waits
// for the next one.
import { sql } from "drizzle-orm";

import { rows, type TestDatabase } from "./harness.js";

export const HOUR_WINDOW_SECONDS = 3600;
/** What a test is given to exhaust its quota inside one window. */
export const WINDOW_MARGIN_SECONDS = 15;
/** What is waited on top after the window changes, so as not to land right on the edge. */
export const WINDOW_CUSHION_MS = 250;
/** The timeout of a test that may wait: the config's 30 s plus the longest wait (margin and cushion). */
export const WINDOW_TEST_TIMEOUT_MS = 30_000 + WINDOW_MARGIN_SECONDS * 1000 + WINDOW_CUSHION_MS;

/** How long to wait (ms) before exhausting a quota: nothing if the window has at least `marginSeconds` left. */
export function waitBeforeExhaustingMs(remainingSeconds: number, marginSeconds: number): number {
  if (!Number.isFinite(remainingSeconds) || !Number.isFinite(marginSeconds) || marginSeconds < 0) {
    throw new Error(`window: invalid inputs (${remainingSeconds}, ${marginSeconds})`);
  }
  if (remainingSeconds >= marginSeconds) return 0;
  return Math.ceil(Math.max(0, remainingSeconds) * 1000) + WINDOW_CUSHION_MS;
}

async function remainingInWindowSeconds(db: TestDatabase, windowSeconds: number): Promise<number> {
  const [row] = await rows<{ remaining: number }>(
    db,
    sql`select extract(epoch from date_bin(${windowSeconds}::int * interval '1 second', now(), timestamptz 'epoch')
      + ${windowSeconds}::int * interval '1 second' - now())::float8 as remaining`,
  );
  if (typeof row?.remaining !== "number") throw new Error("the database did not say how long the window has left");
  return row.remaining;
}

/** Before exhausting a quota: if the current window has under `marginSeconds` left, wait for the next. */
export async function untilWindowHasRoom(
  db: TestDatabase,
  windowSeconds: number,
  marginSeconds = WINDOW_MARGIN_SECONDS,
): Promise<void> {
  const waitMs = waitBeforeExhaustingMs(await remainingInWindowSeconds(db, windowSeconds), marginSeconds);
  if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
}
