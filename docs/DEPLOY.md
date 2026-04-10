# deploy

## Reference deployment

The organizers run a canonical, unmodified copy of this starter at:

**https://attack.day-zero.dev**

That deployment tracks `main` on this repo, has all nine seeded flaws
in place, and is the "before" baseline for the event. Use it to:

- confirm you understand what the starter does before you fork
- sanity-check probe requests against a known-good (known-bad?) copy
- compare behavior if your own deployment acts differently from expected

Your fork will live at a different URL — likely
`https://<your-fork-slug>.vercel.app` or whatever you configure.
**Do not attack `attack.day-zero.dev` as part of scoring** — judges
score each team's own deployment.

## Local

```bash
npm install
cp .env.example .env.local
# IMPORTANT: set EVENT_START_ISO to a past time in .env.local for dev,
# otherwise middleware will serve the gate splash and block the app.
echo 'EVENT_START_ISO=2000-01-01T00:00:00Z' >> .env.local
npm run dev
```

Then open http://localhost:3000.

To run the happy-path functional suite against your local server (the
gate must be open, so set `EVENT_START_ISO` in the server's env, not
the test runner's):

```bash
npm run build
EVENT_START_ISO=2000-01-01T00:00:00Z npm start &
TEST_BASE_URL=http://localhost:3000 ADMIN_TOKEN=letmein npm run test:functional
```

`npm test` (no suffix) runs only the instant structural/deploy-health
smoke checks — it does **not** boot a server and is unaffected by the
gate. Use it in CI.

## Vercel (recommended)

1. Fork this repo on GitHub.
2. Go to https://vercel.com/new, import your fork.
3. No build-config changes are needed — Next.js is auto-detected.
4. Set the following environment variables in the Vercel project
   settings:

   | name              | required | value                                                        |
   |-------------------|----------|--------------------------------------------------------------|
   | `TENANT_ID`       | yes      | short stable id, e.g. `team-ravens`                          |
   | `ADMIN_TOKEN`     | yes      | long random string                                           |
   | `SESSION_SECRET`  | yes      | long random string (≥ 32 chars)                              |
   | `EVENT_START_ISO` | no       | ISO 8601 gate time; defaults to `2026-04-09T17:55:00-07:00`  |

5. Click **Deploy**. First deploy should finish in under two minutes.
6. Open the deployed URL. Confirm the landing page shows your
   `TENANT_ID` (not a random `tenant_<hex>` value, not the reference
   deploy's `infra-strikes-back`).
7. Submit the deployment URL via the event submission form.

Target: from fork to submitted URL in under 20 minutes. If you get
stuck, compare your deploy against the reference at
https://attack.day-zero.dev — everything except the `TENANT_ID` on
the landing page should match on an unhardened fork.

## Env var notes

- If `TENANT_ID` is missing, the app generates a random one on first
  boot. That is fine for local dev, but for the event you **must** set
  it so your deployment is identifiable to judges.
- If `ADMIN_TOKEN` is missing, it falls back to `letmein`. **Change it
  for any public deployment.**
- If `SESSION_SECRET` is missing, an ephemeral value is generated at
  boot. Sessions will not survive cold starts. For the event you
  **must** set it.
- `EVENT_START_ISO` gates the entire app behind a time check. Before
  the gate opens, browsers see a splash page with a countdown and
  `/api/*` returns `503 {"error":"gate_closed", ...}`. After the gate
  opens, the real app passes through normally. The default in the
  middleware is `2026-04-09T17:55:00-07:00` (5 min safety margin before
  the nominal 18:00 PDT kickoff). To run locally **before** that time,
  set `EVENT_START_ISO=2000-01-01T00:00:00Z` or any other past
  timestamp. To test the splash on a deployed instance, leave the env
  var unset (or set it to a future time) — you should see the gate.

## Other hosts

Any host that runs Node.js 20+ and Next.js 14 works. This starter does
not use edge-runtime-only features.
