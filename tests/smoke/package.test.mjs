// Smoke test: package.json sanity.
// If scripts or deps drift from what the event expects, deployments
// and participants will hit friction. Catch that early.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(new URL("../../", import.meta.url).pathname);
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));

test("has required scripts", () => {
  for (const name of ["dev", "build", "start", "test"]) {
    assert.ok(pkg.scripts[name], `missing script: ${name}`);
  }
});

test("has next/react deps", () => {
  assert.ok(pkg.dependencies.next, "missing next dep");
  assert.ok(pkg.dependencies.react, "missing react dep");
  assert.ok(pkg.dependencies["react-dom"], "missing react-dom dep");
});

test("no surprise production deps", () => {
  // Event infra: keep the prod dep set tiny so forks stay cheap to
  // deploy. If a new prod dep is needed, the set is small enough that
  // bumping this number is a visible, reviewable change.
  //
  // Current allowlist:
  //   - next, react, react-dom  (framework)
  //   - @vercel/analytics       (event traffic telemetry)
  const count = Object.keys(pkg.dependencies).length;
  assert.ok(
    count <= 4,
    `expected <=4 prod deps, found ${count}: ${Object.keys(pkg.dependencies).join(", ")}`,
  );
});
