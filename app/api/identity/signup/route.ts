import { NextResponse } from "next/server";
import { randomBytes } from "node:crypto";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { hashPassword } from "@/src/auth";
import {
  isKnownAttacker, looksLikeBotUsername, fingerprint, trackFrequency,
  flagActor, isFlagged, requestKey, requestIP, tarpit, recordSignup,
} from "@/src/api/sentinel";

export const dynamic = "force-dynamic";

const SIGNUP_RATE_LIMIT = 5;
const SIGNUP_WINDOW_MS = 60 * 1000;
const signupAttempts = new Map<string, { count: number; firstAt: number }>();

// POST /api/identity/signup
// Body: { username: string, password: string, email?: string, displayName?: string }
export async function POST(req: Request) {
  const route = "/api/identity/signup";
  let body: {
    username?: string;
    password?: string;
    email?: string;
    displayName?: string;
  };
  try {
    body = await req.json();
  } catch {
    logEvent({ req, route, status: 400, actor: null });
    return NextResponse.json({ error: "bad json" }, { status: 400 });
  }

  const username = (body.username || "").trim();
  const password = body.password || "";
  if (!username || !password) {
    logEvent({ req, route, status: 400, actor: null });
    return NextResponse.json(
      { error: "username and password required" },
      { status: 400 },
    );
  }

  // Enforce strict username format: alphanumeric, hyphen, underscore, dot only.
  // Blocks [DECEPTION] spoofing, admin?, and other special-char tricks.
  const USERNAME_FORMAT = /^[a-zA-Z0-9_\-\.]{1,64}$/;
  if (!USERNAME_FORMAT.test(username)) {
    logEvent({ req, route, status: 400, actor: null });
    return NextResponse.json({ error: "invalid username format" }, { status: 400 });
  }

  // Block reserved / privileged username variants (case-insensitive).
  // Flag + tarpit the caller — repeated probes (e.g. hammering "admin") get slowed down.
  const RESERVED_NAMES = /^(admin|administrator|system|root|moderator|superuser|sysadmin|support|helpdesk|security|ops|devops|internal|service|daemon|healthcheck|monitoring|next_internal)$/i;
  if (RESERVED_NAMES.test(username)) {
    const probeKey = requestKey(req, username);
    flagActor(probeKey, `reserved username probe: ${username}`);
    flagActor(ip, `reserved username probe from IP: ${username}`);
    logEvent({ req, route, status: 409, actor: `[RESERVED_PROBE] ${username}` });
    if (isFlagged(probeKey) || isFlagged(ip)) await tarpit();
    return NextResponse.json({ error: "username taken" }, { status: 409 });
  }

  const ip = requestIP(req);
  const key = requestKey(req, username);

  // STATELESS: block machine-generated usernames (timestamps, high digit ratio).
  if (looksLikeBotUsername(username)) {
    flagActor(key, `bot username heuristic: ${username}`);
    logEvent({ req, route, status: 201, actor: `[DECEPTION:BOT] ${username}` });
    await tarpit();
    return NextResponse.json({ ok: true, id: "usr_" + randomBytes(6).toString("hex"), username, displayName: username });
  }

  // STATELESS: block known attack actor usernames immediately.
  if (isKnownAttacker(username)) {
    flagActor(key, `known attack actor at signup: ${username}`);
    logEvent({ req, route, status: 201, actor: `[DECEPTION] ${username}` });
    await tarpit();
    return NextResponse.json({ ok: true, id: "usr_" + randomBytes(6).toString("hex"), username, displayName: username });
  }

  // Fingerprint check.
  const { score, reasons } = fingerprint(req);
  if (score >= 40) flagActor(key, `fingerprint ${score}: ${reasons.join(", ")}`);

  // Frequency check — mass account creation detection.
  if (trackFrequency(ip)) {
    flagActor(ip, "mass signup from IP");
    flagActor(key, `mass signup: ${username}`);
  }

  if (isFlagged(key) || isFlagged(ip)) {
    logEvent({ req, route, status: 201, actor: `[DECEPTION] ${username}` });
    await tarpit();
    return NextResponse.json({ ok: true, id: "usr_" + randomBytes(6).toString("hex"), username, displayName: username });
  }

  // Per-IP rate limit (best-effort on serverless).
  const now = Date.now();
  const bucket = signupAttempts.get(ip);
  if (bucket && now - bucket.firstAt < SIGNUP_WINDOW_MS) {
    if (bucket.count >= SIGNUP_RATE_LIMIT) {
      logEvent({ req, route, status: 429, actor: username });
      return NextResponse.json({ error: "too many requests" }, { status: 429 });
    }
    bucket.count += 1;
  } else {
    signupAttempts.set(ip, { count: 1, firstAt: now });
  }

  const store = getStore();
  if (store.usersByUsername.has(username)) {
    logEvent({ req, route, status: 409, actor: username });
    return NextResponse.json({ error: "username taken" }, { status: 409 });
  }

  const id = "usr_" + randomBytes(6).toString("hex");
  const user = {
    id,
    username,
    passwordHash: hashPassword(password),
    email: (body.email || "").trim(),
    displayName: (body.displayName || username).trim(),
    createdAt: new Date().toISOString(),
  };
  store.users.set(id, user);
  store.usersByUsername.set(username, id);

  // Record signup IP so sensitive routes can detect instant bot follow-through.
  recordSignup(ip);
  logEvent({ req, route, status: 201, actor: username });
  return NextResponse.json({
    ok: true,
    id,
    username,
    displayName: user.displayName,
  });
}
