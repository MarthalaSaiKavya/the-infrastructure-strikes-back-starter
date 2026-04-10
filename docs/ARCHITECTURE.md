# architecture

This document exists so a participant can understand the app in under
ten minutes. It is deliberately short. If something is not documented
here, read the source — it's small.

## Stack

- **Next.js 14** (App Router) + **TypeScript**
- **No database.** All state lives in `lib/store.ts` (in-memory Maps).
- **No external auth.** Sessions are signed cookies (HMAC-SHA256).
- **No extra production dependencies** beyond Next/React.

The app must boot fast locally and deploy fast to Vercel. Every design
decision here is in service of those two goals.

## Layout

```
app/                  — next.js routes & pages
  api/auth/...        — auth endpoints
  api/actions/...     — action api endpoints
  api/identity/...    — identity endpoints
  api/_admin/...      — judge-only endpoints (plumbing)
  _admin/page.tsx     — judge dashboard (plumbing)
  page.tsx            — landing page with deployment id

src/                  — surfaces blue teams modify
  auth/               — password hashing, sessions, stepup
  api/                — action ownership helper
  identity/           — reset token helper
  shared/             — admin token gate (narrow allowlist)

lib/                  — plumbing blue teams do NOT modify
  telemetry.ts        — event log shape + ring buffer
  tenant.ts           — deployment identifier
  config.ts           — secret/env reads
  store.ts            — in-memory store

middleware.ts         — stamps x-request-id + x-request-start
tests/                — smoke (static) + functional (http)
docs/                 — you are here
```

## Request lifecycle

1. `middleware.ts` attaches a `x-request-id` header and a start
   timestamp to every incoming request.
2. The route handler does its work.
3. Before returning, the handler calls `logEvent({...})` from
   `lib/telemetry.ts` with the route name, status, and optional actor.
4. The log record includes the tenant id from `lib/tenant.ts`, the
   request id, and the measured duration.
5. The record goes into the in-memory ring buffer (last 2000 entries)
   and to stdout as JSON.

Log record shape:

```ts
{
  timestamp: string,     // ISO 8601
  request_id: string,
  tenant_id: string,
  route: string,
  method: string,
  status: number,
  actor: string | null,
  duration_ms: number
}
```

## State

`lib/store.ts` holds:

- `users: Map<userId, User>`
- `usersByUsername: Map<username, userId>`
- `actions: Map<actionId, ActionObject>`
- `resetTokens: Map<token, ResetToken>`
- `loginAttempts: Map<username, counter>` (hook; not used by default)

`POST /api/_admin/reset` wipes the store and the log buffer.

## Auth model

- Passwords: scrypt (`N=16384`, 32-byte key), format
  `scrypt$<salt_hex>$<hash_hex>`.
- Sessions: `base64url(json).base64url(hmac_sha256)`, stored in the
  `isb_session` HttpOnly cookie.
- Optional step-up: a fixed event-wide code, verified on demand.

## Admin

- `GET /api/_admin/events?route=&method=&status=&actor=&limit=`
- `POST /api/_admin/reset`
- `GET /_admin` — dashboard UI, polls events every 3 seconds.

All three require the `x-admin-token` header (or `?token=` query
parameter) matching `ADMIN_TOKEN` (default `letmein`).

## Seeded flaws

Nine application-layer flaws, three per surface. Each is commented in
source with the phrase `SEEDED FLAW`.

### auth (`src/auth/`)

1. **Fail-open step-up check** (`stepup.ts`): `verifyStepupCode` wraps
   its comparison in `try/catch` and returns `true` on thrown error.
2. **Client-influenced session identity** (`app/api/auth/login/route.ts`):
   if the login body contains `identity`, that value is stored in the
   session as the display/audit identity, regardless of the
   authenticated username.
3. **No login rate limit** (`app/api/auth/login/route.ts`): the handler
   never reads or writes `store.loginAttempts`. The hook exists; no
   one calls it.

### api (`src/api/`)

1. **Ownership check trusts caller-controlled identifier**
   (`src/api/ownership.ts`): `isActionOwner` compares the action's
   `ownerId` to the `x-user-id` request header.
2. **Verbose internal error leakage**
   (`app/api/actions/create/route.ts`): the catch block returns the
   error message, full stack, and the raw received body.
3. **No action creation rate limit**
   (`app/api/actions/create/route.ts`): no per-user or global limit.

### identity (`src/identity/`)

1. **Unrestricted signup** (`app/api/identity/signup/route.ts`): no
   rate limit, no password strength check, no CAPTCHA.
2. **Weak reset token generation** (`src/identity/reset.ts`):
   `Math.random().toString(36)` — 10-character, low-entropy,
   non-cryptographic.
3. **Profile update lacks proper subject verification**
   (`app/api/identity/profile/route.ts`): requires a session, but
   then updates whichever `userId` is named in the request body.

## What to leave alone

- Anything in `lib/`, `middleware.ts`, `app/_admin/`, `app/api/_admin/`,
  and `tests/` is event plumbing. Blue teams should not modify it.
- The log record shape is load-bearing for the judge dashboard. Adding
  optional fields is fine if logging stays structured; renaming or
  removing fields breaks the dashboard.
