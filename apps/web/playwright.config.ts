import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://127.0.0.1:5174",
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: [
    {
      command:
        "AA_DEMO_MODE=true cargo run -p ai-agent-permission-enforcer-api",
      cwd: "../..",
      url: "http://127.0.0.1:8787/api/health",
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        AA_DEMO_MODE: "true",
        AA_DEMO_AGENT_TOKEN: "playwright-fixture-token",
        DATABASE_URL: `sqlite:///tmp/ai-agent-permission-enforcer-playwright-${process.pid}.db`,
      },
    },
    {
      command: "pnpm dev --host 127.0.0.1 --port 5174",
      url: "http://127.0.0.1:5174",
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
