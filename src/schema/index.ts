/**
 * The package's Drizzle tables. Add `authTables` to your own schema and migrations; `createAuth` expects them in the
 * database it is given.
 */
import { account, accountRelations, session, sessionRelations, user, userRelations, verification } from "./auth-tables.js";
import { rateLimitCounter } from "./rate-limit-counter.js";

export { account, accountRelations, session, sessionRelations, user, userRelations, verification } from "./auth-tables.js";
export { RATE_LIMIT_KEY_BYTES, RATE_LIMIT_SCOPES, rateLimitCounter, type RateLimitScope } from "./rate-limit-counter.js";

/** Every table and relation of the package, to spread into a Drizzle schema. */
export const authTables = {
  user,
  session,
  account,
  verification,
  rateLimitCounter,
  userRelations,
  sessionRelations,
  accountRelations,
} as const;
