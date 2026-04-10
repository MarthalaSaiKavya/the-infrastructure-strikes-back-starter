# event rules

> This repo is synthetic event infrastructure. Nothing in it resembles a
> real company, product, or internal system. All names and flows are
> invented for the purpose of running this event.

## The event

**The Infrastructure Strikes Back, Round 3** — an Adversarial Agent
Experiment. April 9, 2026 · Oakland.

Round 3 is a **two-phase event**, and the attackers are **Red Team
developers operating autonomous agents**. Humans pick the targets and
strategy. Agents execute the volume. Expect both mechanical sweeps and
mid-hour strategic pivots when a Red dev notices something soft.

- You fork this repo.
- You are assigned exactly one of the three surfaces: **auth**, **api**,
  or **identity**.
- You harden your assigned surface against the three seeded flaws in
  Phase 1, then actively defend under agent attack in Phase 2.
- You submit two forms, one at 7:00 PM PDT and one at 8:00 PM PDT.
- Judges read your diffs, your deployment's event log, and your
  descriptions.

## The phases

### Phase 1 — passive hardening (start → 7:00 PM PDT)

- Fork, harden your assigned domain against the seeded flaws, deploy.
- No attacks yet. No fight-back yet.
- Scored like prior rounds: find the flaws, fix them cleanly, don't
  break the happy path.
- **Submit Form #1 at 7:00 PM PDT** (URL, admin token, `git diff`,
  3–5 sentence hardening description).

### Phase 2 — active defense (7:00 PM → 8:00 PM PDT)

- At 7:00 PM sharp, Red Team developers point their agents at your
  deployment. Attacks run continuously for the full hour.
- You are now allowed to **fight back**, inside a bounded scope (see
  below).
- **Submit Form #2 at 8:00 PM PDT** (final `git diff`, 2–3 sentence
  Phase 2 description tied to observations from your event log).
- **No commits after 8:00 PM PDT.**

## Submission deadlines

- **Form #1 at 7:00 PM PDT** — hard deadline. Late = no score.
- **Form #2 at 8:00 PM PDT** — hard deadline. Late = no score.

Form #1 URL will be provided in the briefing distributed by organizers.

## What you are allowed to modify (in both phases)

- `src/auth/` (auth team only)
- `src/api/` (api team only)
- `src/identity/` (identity team only)
- A narrow allowlist under `src/shared/` — only if clearly necessary,
  and judges will read the diff.

## What you are never allowed to modify

- `lib/telemetry.ts` — event logging
- `lib/tenant.ts` — deployment identifier
- `lib/store.ts` shape (you can read; don't change the shape)
- `middleware.ts` — request-id plumbing and time gate
- `app/_admin/*`, `app/api/_admin/*` — judge dashboard
- `tests/` — deploy-health and happy-path checks
- `package.json` dependencies list (scripts are fine)

**Deployments that modify out-of-scope files are not scored.**

## Phase 2 — what you CAN do

Fight-back tactics permitted between 7:00 PM and 8:00 PM PDT:

- **Rate limiting, IP blocking, ban lists, tarpits, slow responses**
- **Honeypot routes** that return fake data to detected attackers
- **Deception responses** (fake tokens, fake action objects, fake admin
  endpoints) served to traffic you've classified as adversarial
- **Additional telemetry and fingerprinting** to classify attacker
  traffic
- Any combination of the above, deployed as hot-fixes during the live
  window

## Phase 2 — what you CANNOT do (ever)

- **Attack other Blue teams' deployments**
- **Attack the canonical reference deployment** (`attack.day-zero.dev`)
- **Attack the judge or attacker infrastructure itself**
- Modify files outside `src/[your-domain]/` (and the narrow shared
  allowlist)
- Add new production dependencies
- Exfiltrate data anywhere off Vercel
- **Return intentionally wrong responses to *legitimate* traffic.**
  Deception is allowed only against traffic you've classified as
  adversarial.
- **Push commits after 8:00 PM PDT**

## The happy-path hard gate

At all times during Phase 2, the judges' happy-path probe must pass.
The probe exercises: signup, login, authenticated read, authenticated
write.

**If the probe fails at any scored checkpoint during Phase 2:**

- Your deployment scores zero on stability
- You forfeit the live-window categories (live adaptation + live
  exploit reduction)
- Total event score drops regardless of how elegant your fight-back was

This is the single biggest footgun in Phase 2. An overeager rate
limiter or a too-aggressive deception rule will lock legitimate traffic
out and end your event. **Test every hot-fix against a clean session
before you declare victory.**

## Why the human-plus-agent dynamic matters

- **Everyone gets attacked heavily.** Agents generate volume. Expect
  hundreds to thousands of requests. The "low attack volume, category
  drops" escape hatch from prior rounds is gone.
- **Patterns carry intent, not just mechanics.** A Red dev who notices
  your auth is soft will redirect their agents. Watch for sudden
  changes in endpoint mix — those are human decisions, not agent
  quirks.
- **Templated probes still repeat.** The agent-executed layer reuses
  payloads. One good fix can kill thousands of requests. Prioritize
  accordingly.
- **Bad patches get found fast, by both layers.** The agent firehose
  catches regressions in seconds. Red devs watching their dashboards
  catch weird behavior almost as fast. A hot-fix that breaks the
  happy path will not hide.
- **Honeypots and deception are visible to humans.** A Red dev can
  notice "that response is suspicious" and adapt. Your deception has
  to be plausible enough to fool a person who is paying attention, not
  just a script.
- **Retry storms are real.** If you rate-limit, expect agents to back
  off and retry, and expect humans to adjust the agent config. A quiet
  minute is not a win.

## What is out of scope for attacks

Judges will not probe for, and you do not need to defend against:

- remote code execution
- SQL injection (there is no SQL)
- server-side request forgery
- cross-site scripting
- path traversal
- arbitrary file read/write

If your deployment exhibits any of those classes, it is a starter bug —
flag it to the organizers.

## Fair play

- Don't attack other teams' deployments, at any phase.
- Don't publish exploits against other teams' deployments during the
  event.
- Don't add telemetry that phones home to an external service.
- Keep your diff readable — judges review the code, not just the
  runtime behavior.

## Questions

Post in `#help` on Discord. Organizers are monitoring.

Good luck. Out-think the humans driving the agents.
