# the infrastructure strikes back — starter

> **Synthetic adversarial training repo. Not production. Not a real system.**
>
> All names, endpoints, and flows in this repo are synthetic. Do **not**
> assume resemblance to any real company, product, architecture, or
> internal system. This repo exists solely to host a live adversarial
> engineering event, and is intentionally under-defended at the
> application layer.

## What this is

A small, naive web app with three hardening surfaces:

- **auth** — login, session inspection, optional step-up
- **api** — create / list / get action objects
- **identity** — signup, profile read/update, password reset

Blue teams fork this repo, pick one area, harden it, and deploy. Judges
score by reading logs from the admin dashboard on each deployment.

**Canonical reference deployment:** https://attack.day-zero.dev — a
clean, unmodified copy of this starter that judges and participants
can hit to see the intended "before" behavior. Your fork's deployment
will live at a different URL (see `docs/DEPLOY.md`).

## Round 3: Adversarial Agent Experiment

This is a **two-phase event**, and the attackers are **Red Team
developers driving autonomous agents**. Humans pick targets and
strategy; agents execute volume.

- **Phase 1 — passive hardening (start → 7:00 PM PDT):** fork, harden
  your assigned surface against the seeded flaws, deploy, submit
  Form #1. No attacks yet. No fight-back yet.
- **Phase 2 — active defense (7:00 PM → 8:00 PM PDT):** Red agents
  release against your deployment. You may now fight back within a
  bounded scope: rate limits, IP blocks, tarpits, honeypots, deception
  against classified adversarial traffic, extra telemetry. The
  happy-path probe must still pass — an overeager defense that locks
  legitimate users out is a hard zero. Submit Form #2 at 8:00 PM.
- **No commits after 8:00 PM PDT.**

See `docs/EVENT_RULES.md` for the full list of what's allowed and
forbidden in Phase 2, and `docs/SCORING.md` for the six-category
rubric.

## What this is **not**

- Not a framework
- Not a reusable security pattern
- Not a demo of anything real
- Not hardened
- Not polished

Refer to `docs/EVENT_RULES.md` for the rules, scope, and deadlines.

## Quick start

```bash
npm install
cp .env.example .env.local     # edit if you like
npm run dev
# open http://localhost:3000
```

Admin dashboard: http://localhost:3000/_admin (default token is `letmein`).

## Blue-team modification scope

You may modify:

- `src/auth/`
- `src/api/`
- `src/identity/`
- a narrow allowlist under `src/shared/` (only if clearly necessary)

You may **not** modify:

- `lib/telemetry.ts` — event logging
- `lib/tenant.ts` — deployment identifier
- `lib/store.ts` shape — you can read from it, but don't change its shape
- `middleware.ts` — request-id plumbing
- `app/_admin/*`, `app/api/_admin/*` — judge dashboard
- `tests/` — deploy-health and happy-path checks

If you change out-of-scope files, your deployment will not be scored.

## Seeded weaknesses (the point of the event)

There are exactly nine intentional application-layer flaws. Each is
commented in source with the phrase `SEEDED FLAW`. Three live in each
surface:

- **auth**: fail-open step-up check, client-influenced session identity,
  no login rate limit
- **api**: ownership check trusts caller-controlled identifier, verbose
  internal error leakage, no action creation rate limit
- **identity**: unrestricted signup, weak reset token generation,
  profile update lacks proper subject verification

Things that are explicitly **not** in scope (and must not be introduced):

- RCE, SQLi, SSRF, XSS, path traversal, arbitrary file access

If you find something that looks like one of those, it is a bug in the
starter, not an intended target — please flag it to the event
organizers.

## Deployment

See `docs/DEPLOY.md`. Short version: push your fork, click deploy on
Vercel, set `TENANT_ID`, `ADMIN_TOKEN`, and `SESSION_SECRET`, submit
your deployment URL. Should take well under 20 minutes.

The canonical reference deploy at https://attack.day-zero.dev runs
the exact code on `main` with all seeded flaws in place — useful for
reproducing a baseline before you start hardening.

## Scoring

See `docs/SCORING.md`.

## Architecture

See `docs/ARCHITECTURE.md`.

## Submission

Submit your deployment URL via the event submission form before the
deadline in `docs/EVENT_RULES.md`. **Late submissions are not scored.**

## License

This software is distributed under an Event Use Only License — see
[`LICENSE`](./LICENSE). Not open source. Redistribution prohibited
outside the April 9, 2026 event.
