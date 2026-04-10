// Functional test: happy path against a running server.
//
// Gated on TEST_BASE_URL. If unset, all tests are skipped — this lets
// `npm test` stay instant for deploy-health checks. To run:
//
//   npm run build && npm start &
//   TEST_BASE_URL=http://localhost:3000 ADMIN_TOKEN=letmein \
//     node --test tests/functional
//
// These tests cover the happy path only: signup, login, session, create
// action, list actions, get action, profile read, password reset round
// trip, and admin events readable with the right token. They do NOT
// attempt to prove the absence of vulnerability classes — that is the
// job of code review, not automated tests.

import { test } from "node:test";
import assert from "node:assert/strict";

const BASE = process.env.TEST_BASE_URL;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "letmein";

const describe = BASE ? test : test.skip;

// Shared state across ordered tests.
const ctx = {
  username: "alice_" + Math.random().toString(36).slice(2, 8),
  password: "supersecret",
  cookie: "",
  userId: "",
  actionId: "",
};

async function call(method, path, body, cookie) {
  const headers = { "content-type": "application/json" };
  if (cookie) headers["cookie"] = cookie;
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const setCookie = res.headers.get("set-cookie") || "";
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* empty body */
  }
  return { status: res.status, json, setCookie };
}

describe("landing page exposes tenant id", async () => {
  const res = await fetch(BASE + "/");
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /deployment identifier/i);
  assert.match(html, /tenant_|[A-Za-z0-9_-]{4,}/);
});

describe("signup creates a user", async () => {
  const { status, json } = await call("POST", "/api/identity/signup", {
    username: ctx.username,
    password: ctx.password,
    email: `${ctx.username}@example.test`,
    displayName: "Alice",
  });
  assert.equal(status, 200);
  assert.equal(json.username, ctx.username);
  ctx.userId = json.id;
});

describe("login returns a session cookie", async () => {
  const { status, json, setCookie } = await call("POST", "/api/auth/login", {
    username: ctx.username,
    password: ctx.password,
  });
  assert.equal(status, 200);
  assert.equal(json.ok, true);
  assert.match(setCookie, /isb_session=/);
  ctx.cookie = setCookie.split(";")[0];
});

describe("session inspection reflects the login", async () => {
  const { status, json } = await call(
    "GET",
    "/api/auth/session",
    null,
    ctx.cookie,
  );
  assert.equal(status, 200);
  assert.equal(json.authenticated, true);
  assert.equal(json.identity, ctx.username);
});

describe("create action", async () => {
  const { status, json } = await call(
    "POST",
    "/api/actions/create",
    { title: "first", body: "hello" },
    ctx.cookie,
  );
  assert.equal(status, 201);
  assert.equal(json.title, "first");
  ctx.actionId = json.id;
});

describe("list actions returns the created one", async () => {
  const { status, json } = await call(
    "GET",
    "/api/actions/list",
    null,
    ctx.cookie,
  );
  assert.equal(status, 200);
  assert.ok(json.actions.some((a) => a.id === ctx.actionId));
});

describe("get action by id (happy path, with x-user-id)", async () => {
  // The ownership helper reads x-user-id — that's the seeded flaw.
  // This test sends the legitimate value because it is asserting the
  // *happy path*. Blue-team fixes must still keep this flow working.
  const res = await fetch(BASE + "/api/actions/" + ctx.actionId, {
    headers: { cookie: ctx.cookie, "x-user-id": ctx.userId },
  });
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.equal(json.id, ctx.actionId);
});

describe("profile read", async () => {
  const { status, json } = await call(
    "GET",
    "/api/identity/profile",
    null,
    ctx.cookie,
  );
  assert.equal(status, 200);
  assert.equal(json.username, ctx.username);
});

describe("password reset round trip", async () => {
  const req = await call("POST", "/api/identity/reset", {
    mode: "request",
    username: ctx.username,
  });
  assert.equal(req.status, 200);
  assert.ok(req.json.token, "expected a reset token in response");
  const newPassword = "newpassword123";
  const confirm = await call("POST", "/api/identity/reset", {
    mode: "confirm",
    token: req.json.token,
    newPassword,
  });
  assert.equal(confirm.status, 200);
  // Log back in with the new password.
  const login = await call("POST", "/api/auth/login", {
    username: ctx.username,
    password: newPassword,
  });
  assert.equal(login.status, 200);
});

describe("admin events requires token", async () => {
  const bad = await fetch(BASE + "/api/_admin/events");
  assert.equal(bad.status, 401);
  const good = await fetch(BASE + "/api/_admin/events?limit=10", {
    headers: { "x-admin-token": ADMIN_TOKEN },
  });
  assert.equal(good.status, 200);
  const json = await good.json();
  assert.ok(Array.isArray(json.events));
});
