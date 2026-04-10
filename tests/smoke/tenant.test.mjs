// Smoke test: deployment identifier is present and stable.
//
// This test shells out to the tenant module indirectly by reading the
// .env.example to ensure TENANT_ID is documented. The runtime behavior
// is covered by tests/functional/http.test.mjs against a live server.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(new URL("../../", import.meta.url).pathname);

test(".env.example documents TENANT_ID, ADMIN_TOKEN, SESSION_SECRET, EVENT_START_ISO", () => {
  const env = readFileSync(resolve(root, ".env.example"), "utf8");
  assert.match(env, /TENANT_ID/);
  assert.match(env, /ADMIN_TOKEN/);
  assert.match(env, /SESSION_SECRET/);
  assert.match(env, /EVENT_START_ISO/);
});
