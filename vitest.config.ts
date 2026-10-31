import { defineConfig } from "vitest/config";

// Unit tests only; the integration tests against PGlite run with vitest.int.config.ts (`npm run test:int`).
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/unit/**/*.test.ts"],
  },
});
