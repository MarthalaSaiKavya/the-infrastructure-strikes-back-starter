# scoring

Round 3 is scored across **six categories**, each rated 1 to 5,
multiplied by a weight, summed to a total out of 100. Two categories
are scored entirely from the Phase 2 window (7:00 PM → 8:00 PM PDT).

## The rubric

| # | Category | Weight | What judges look at |
|---|---|---|---|
| 1 | **Initial design quality** | 25% | Your 7:00 PM `git diff`. Did you find and fix the three seeded flaws? Is the code sound and proportionate? |
| 2 | **Coverage of surface** | 15% | Did you address the highest-risk paths in your domain, or just cosmetic issues? |
| 3 | **Stability and continuity** | 15% | Does the happy-path probe pass? Did functional tests stay green? Did your Phase 2 hot-fixes break anything? **Hard gate: happy-path failure = 0 on this category and forfeits live-window categories.** |
| 4 | **Live adaptation** *(Phase 2)* | 20% | Diff between 7:00 PM and 8:00 PM submissions. Did you read `/_admin` telemetry and respond to what Red was actually doing? Were your fight-back tactics targeted or thrashy? |
| 5 | **Live exploit reduction** *(Phase 2)* | 15% | Ratio of blocked to successful attacks during 7:00 to 8:00 PM, measured from `/api/_admin/events`. |
| 6 | **Explanation and rationale** | 10% | Your descriptions in both forms. Can you clearly explain what you changed initially, what you changed reactively, and why? |

## On fight-back tactics specifically

Honeypots, deception, and tarpits are **observationally scored**. They
don't earn bonus points directly, but judges weight them into "live
adaptation" (category 4) when they're clearly tied to observed
attacker behavior in your event log.

- **A honeypot deployed because you saw agents hammering
  `/api/admin/users` at 7:12 PM** → 5
- **A honeypot deployed because it seemed cool** → 2

Tell the story in Form #2.

## How each category gets scored, concretely

### 1. Initial design quality (25%)

Judges read your 7:00 PM `git diff` directly:

- **Did you find the seeded weaknesses?** Each domain has 3 flaws
  marked `SEEDED FLAW`. All 3 is the baseline.
- **Did you fix them well?** Minimal, understandable, closes the actual
  attack path.
- **Did you avoid regressions?** A fix that breaks a different endpoint
  costs points.

### 2. Coverage of assigned surface (15%)

Prioritization under time pressure:

- **auth:** fail-open step-up and session identity before cosmetic
  logging.
- **api:** ownership validation and error leakage before variable
  renames.
- **identity:** signup rate limiting and reset token strength before
  profile UI.

### 3. Stability and continuity (15%) — with a hard gate

Functional tests in `tests/functional/` must stay green. Judges run a
happy-path probe against your deployment at multiple points during
Phase 2. If the probe fails at any scored checkpoint (signup, login,
authenticated read, authenticated write):

- Stability → **0**
- Live adaptation (category 4) → **forfeit**
- Live exploit reduction (category 5) → **forfeit**

This is the single biggest footgun in Phase 2. An overeager rate
limiter or a too-aggressive deception rule will lock legitimate traffic
out and end your event. Test every hot-fix against a clean session
before you move on.

### 4. Live adaptation (20%) — the heart of the event

Judges compare 7:00 PM vs 8:00 PM `git diff` and look for:

- **Did you read `/_admin` and respond to real attacker behavior?**
  If Red agents probed endpoint X 400 times between 7:10 and 7:20 and
  you deployed a targeted fix at 7:22, that's a 5.
- **Did you notice strategy shifts?** If Red's endpoint mix changed
  at 7:35 (a human pivot) and you responded to the new target, that
  is strong signal.
- **Surgical or thrashy?** Small, targeted, deployed fast beats a
  sprawling refactor.
- **Did your live changes hold?** A hot-fix that introduced a new bug
  or tripped the happy-path probe scores worse than no change at all.
- **Phase 2 tactics used intelligently?** A honeypot or tarpit tied to
  a specific observed pattern is high-signal. Random deception is
  noise. Remember: the Red dev driving the agents can see your
  honeypot response and adapt, so plausibility matters.
- **Rationale explained in Form #2?** Heavily weighted.

**A 5 looks like:**

> "At 7:14 we saw agents iterating POST `/api/actions/create` with
> title enumeration. Deployed a per-session create rate limit at 7:18,
> attempts dropped from 200/min to 5/min. At 7:31 Red shifted to
> `/api/identity/reset` (clearly a human pivot — the pattern changed).
> Added a honeypot returning plausible-but-fake reset tokens and
> tarpitted those IPs at 7:36."

**A 1 looks like:**

> No changes during Phase 2 despite obvious signals, or panicked
> changes that broke the happy-path probe.

### 5. Live exploit reduction (15%)

Scored from `/api/_admin/events` using the admin token from Form #1.
Ratio of blocked to successful attacks during 7:00 to 8:00 PM. Because
agents generate volume for every team, **every team is scored**.

### 6. Explanation and rationale (10%)

- **Form #1 (7:00 PM):** 3 to 5 sentences on initial hardening approach.
- **Form #2 (8:00 PM):** 2 to 3 sentences on what you changed during
  Phase 2 and why, tied to specific observations from your event log.

The Phase 2 description is the one that moves scores.

## Tie-break rules

Within 2 points, tie-breaks go to:

1. The team that reduced the most meaningful attack paths while keeping
   the happy-path probe green
2. The team with stronger prioritization under time pressure
3. The team with clearer explanation of trade-offs and remaining risk

## What loses points

- Out-of-scope file changes (automatic zero; see `EVENT_RULES.md`).
- New production dependencies.
- Defensive code that only exists to make a single probe pass (judges
  read diffs).
- Blanket catch-all changes like "401 on every route" — breaks happy
  path, scores zero.
- Deception served to legitimate traffic, not just adversarial traffic.
- Commits pushed after 8:00 PM PDT.

## Judging process

1. Phase 1 ends at 7:00 PM PDT. Form #1 submissions close.
2. Red Team developers release their agents at 7:00 PM sharp.
3. Judges open `/_admin` on your deployment using the token from
   Form #1 and observe telemetry throughout Phase 2.
4. Judges run the happy-path probe at multiple checkpoints during
   Phase 2.
5. At 8:00 PM, Form #2 submissions close. All commits locked.
6. Between 8:00 and 9:00 PM, judges compare diffs, read descriptions,
   and compute category scores.
7. Winners announced at 9:00 PM.
