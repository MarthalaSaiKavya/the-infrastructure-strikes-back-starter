// Smoke test: verify the repo layout the event depends on exists.
// These are deploy-health checks — if any of these fail, the app is
// in no shape to host the event. Run with: `npm test`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { resolve, join } from "node:path";

const root = resolve(new URL("../../", import.meta.url).pathname);

const REQUIRED_FILES = [
  "LICENSE",
  "package.json",
  "tsconfig.json",
  "next.config.mjs",
  "middleware.ts",
  ".env.example",
  "README.md",
  "app/page.tsx",
  "app/layout.tsx",
  "app/%5Fadmin/page.tsx",
  "app/api/auth/login/route.ts",
  "app/api/auth/session/route.ts",
  "app/api/auth/stepup/route.ts",
  "app/api/actions/create/route.ts",
  "app/api/actions/list/route.ts",
  "app/api/actions/[id]/route.ts",
  "app/api/identity/signup/route.ts",
  "app/api/identity/profile/route.ts",
  "app/api/identity/reset/route.ts",
  "app/api/%5Fadmin/events/route.ts",
  "app/api/%5Fadmin/reset/route.ts",
  "src/auth/index.ts",
  "src/api/index.ts",
  "src/identity/index.ts",
  "src/shared/admin.ts",
  "lib/telemetry.ts",
  "lib/tenant.ts",
  "lib/config.ts",
  "lib/store.ts",
  "docs/EVENT_RULES.md",
  "docs/DEPLOY.md",
  "docs/SCORING.md",
  "docs/ARCHITECTURE.md",
];

test("required files exist", () => {
  const missing = REQUIRED_FILES.filter((f) => !existsSync(join(root, f)));
  assert.deepEqual(missing, [], `missing files: ${missing.join(", ")}`);
});
