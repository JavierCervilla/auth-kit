/**
 * The send-limit counters: fixed-window rows, one per scope, subject and window. Not domain data, so no tenant column.
 * The key is an HMAC of the subject, never the IP address or the email in clear (rate-limit/limiter.ts).
 */
import { sql } from "drizzle-orm";
import { check, customType, index, integer, pgTable, primaryKey, text, timestamp } from "drizzle-orm/pg-core";

/** The scopes the package counts: a closed catalogue, enforced by a CHECK. */
export const RATE_LIMIT_SCOPES = ["magic_link_email", "magic_link_ip"] as const;
export type RateLimitScope = (typeof RATE_LIMIT_SCOPES)[number];

/** The stored key is HMAC-SHA256 truncated to 16 bytes: neither an IP address nor an email fits there in clear. */
export const RATE_LIMIT_KEY_BYTES = 16;

const bytea = customType<{ data: Buffer }>({ dataType: () => "bytea" });

const scopeList = RATE_LIMIT_SCOPES.map((scope) => `'${scope}'`).join(", ");

export const rateLimitCounter = pgTable(
  "rate_limit_counter",
  {
    scope: text("scope").notNull(),
    key: bytea("key").notNull(),
    windowStart: timestamp("window_start", { withTimezone: true }).notNull(),
    hits: integer("hits").notNull().default(0),
  },
  (t) => [
    primaryKey({ columns: [t.scope, t.key, t.windowStart] }),
    check("rate_limit_counter_hits_check", sql`${t.hits} >= 0`),
    check("rate_limit_counter_scope_check", sql`${t.scope} in (${sql.raw(scopeList)})`),
    check("rate_limit_counter_key_check", sql`octet_length(${t.key}) = ${sql.raw(String(RATE_LIMIT_KEY_BYTES))}`),
    // The purge of expired windows (limiter.ts) finds them by window start without scanning the table.
    index("rate_limit_counter_window_start_idx").on(t.windowStart),
  ],
);
