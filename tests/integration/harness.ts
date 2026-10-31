// The integration harness: a fresh in-memory Postgres per test file (PGlite, Postgres compiled to WebAssembly, in
// process), with the package's tables created from `authTables` by drizzle-kit, the same DDL a consumer's migration gets.
import { PGlite } from "@electric-sql/pglite";
import { generateDrizzleJson, generateMigration } from "drizzle-kit/api";
import { sql, type SQL } from "drizzle-orm";
import { drizzle, type PgliteDatabase } from "drizzle-orm/pglite";

import { authTables } from "../../src/schema/index.js";

export type TestDatabase = PgliteDatabase<typeof authTables> & { $client: PGlite };

export const ORIGIN = "https://app.example";
export const SECRET = "integration-test-secret-".padEnd(48, "x");
export const SESSION_COOKIE = "__Secure-better-auth.session_token";

let ddl: Promise<string[]> | undefined;

/** The CREATE statements for `authTables`, generated once per file. */
function authTablesDdl(): Promise<string[]> {
  ddl ??= generateMigration(generateDrizzleJson({}), generateDrizzleJson({ ...authTables }));
  return ddl;
}

/** A new empty database with the package's tables. */
export async function openDatabase(): Promise<TestDatabase> {
  const client = new PGlite();
  const db = drizzle({ client, schema: authTables });
  for (const statement of await authTablesDdl()) await db.execute(sql.raw(statement));
  return db;
}

/** Empties every table of the package. */
export async function resetDatabase(db: TestDatabase): Promise<void> {
  await db.execute(sql`truncate "user", session, account, verification, rate_limit_counter cascade`);
}

/** The rows of a raw query. */
export async function rows<T extends Record<string, unknown>>(db: TestDatabase, query: SQL): Promise<T[]> {
  const result = await db.execute(query);
  return result.rows as T[];
}

/** The `Set-Cookie` of the session, or throws. */
export function sessionSetCookie(headers: Headers): string {
  const found = headers.getSetCookie().find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  if (!found) throw new Error(`no ${SESSION_COOKIE} in Set-Cookie`);
  return found;
}

/** The `Cookie` header a browser would send back for that `Set-Cookie`. */
export function cookieHeader(setCookie: string): Headers {
  return new Headers({ cookie: setCookie.split(";")[0] ?? "" });
}

/** The last session cookie a response leaves (the one the browser keeps), as `name=value`, or undefined. */
export function lastSessionCookie(response: Response): string | undefined {
  const cookies = response.headers.getSetCookie().filter((c) => c.startsWith(`${SESSION_COOKIE}=`));
  const last = cookies.at(-1);
  if (!last || last.startsWith(`${SESSION_COOKIE}=;`)) return undefined;
  return last.split(";")[0];
}
