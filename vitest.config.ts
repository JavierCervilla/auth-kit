import { defineConfig } from "vitest/config";

// Unit tests only; the integration tests against Postgres get their own config when the extracted code lands.
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/unit/**/*.test.ts"],
  },
});
