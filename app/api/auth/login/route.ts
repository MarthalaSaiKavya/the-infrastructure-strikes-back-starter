import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import {
  sessionCookieHeader,
  signSession,
  verifyPassword,
} from "@/src/auth";
import {
  isKnownAttacker, fingerprint, trackFrequency, flagActor, isFlagged,
  requestKey, requestIP, tarpit,
} from "@/src/api/sentinel";

export const dynamic = "force-dynamic";

const LOGIN_RATE_LIMIT = 10;
const LOGIN_WINDOW_MS = 60 * 1000;
const loginAttempts = new Map<string, { count: number; firstAt: number }>();

// POST /api/auth/login
// Body: { username: string, password: string }
export async function POST(req: Request) {
  const route = "/api/auth/login";
  let body: { username?: string; password?: string; identity?: string };
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

  // Reject malformed usernames (e.g. "[DECEPTION] admin", "admin?") early.
  const USERNAME_FORMAT = /^[a-zA-Z0-9_\-\.]{1,64}$/;
  if (!USERNAME_FORMAT.test(username)) {
    logEvent({ req, route, status: 400, actor: null });
    return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
  }

  const ip = requestIP(req);
  const key = requestKey(req, username);

  // STATELESS: block known attack actors immediately.
  if (isKnownAttacker(username)) {
    flagActor(key, `known attack actor at login: ${username}`);
    logEvent({ req, route, status: 401, actor: `[DECEPTION] ${username}` });
    await tarpit();
    return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
  }

  // Fingerprint check.
  const { score, reasons } = fingerprint(req);
  if (score >= 40) flagActor(key, `fingerprint ${score}: ${reasons.join(", ")}`);

  // Frequency check on IP for brute-force detection.
  if (trackFrequency(ip)) {
    flagActor(ip, "brute-force login from IP");
    flagActor(key, `brute-force login: ${username}`);
  }

  if (isFlagged(key) || isFlagged(ip)) {
    logEvent({ req, route, status: 401, actor: `[DECEPTION] ${username}` });
    await tarpit();
    return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
  }

  // Stateless per-IP rate limit (best-effort on serverless).
  const now = Date.now();
  const bucket = loginAttempts.get(ip);
  if (bucket && now - bucket.firstAt < LOGIN_WINDOW_MS) {
    if (bucket.count >= LOGIN_RATE_LIMIT) {
      logEvent({ req, route, status: 429, actor: username });
      return NextResponse.json({ error: "too many requests" }, { status: 429 });
    }
    bucket.count += 1;
  } else {
    loginAttempts.set(ip, { count: 1, firstAt: now });
  }

  const store = getStore();
  const userId = store.usersByUsername.get(username);
  const user = userId ? store.users.get(userId) : undefined;
  if (!user || !verifyPassword(password, user.passwordHash)) {
    logEvent({ req, route, status: 401, actor: username });
    return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
  }

  // FIXED: ignore caller-supplied identity field — always use verified username.
  const identity = user.username;

  const token = signSession({
    userId: user.id,
    identity,
    stepup: false,
    iat: Date.now(),
  });

  logEvent({ req, route, status: 200, actor: identity });
  const res = NextResponse.json({ ok: true, identity });
  res.headers.set("Set-Cookie", sessionCookieHeader(token));
  return res;
}
