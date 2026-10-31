import { defineConfig } from "vitest/config";

// Integration tests: real better-auth against a real Postgres engine, PGlite (Postgres compiled to WebAssembly, in
// process), so the suite runs on any CI runner without Docker or a database service (docs/design.md, «Quality gates»).
// Each test file opens its own in-memory database.
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/integration/**/*.int.test.ts"],
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
