import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // The open_secret fixture runs the full verify+aggregate+open in wasm.
    testTimeout: 60_000,
  },
});
