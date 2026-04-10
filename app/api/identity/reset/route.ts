import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { hashPassword } from "@/src/auth";
import { RESET_TOKEN_TTL_MS, generateResetToken } from "@/src/identity";
import {
  isKnownAttacker, looksLikeBotUsername, trackFrequency, flagActor, isFlagged,
  requestKey, requestIP, tarpit, freshSignupHittingSensitiveRoute,
} from "@/src/api/sentinel";

export const dynamic = "force-dynamic";

// POST /api/identity/reset
export async function POST(req: Request) {
  const route = "/api/identity/reset";
  let body: {
    mode?: string;
    username?: string;
    token?: string;
    newPassword?: string;
  };
  try {
    body = await req.json();
  } catch {
    logEvent({ req, route, status: 400, actor: null });
    return NextResponse.json({ error: "bad json" }, { status: 400 });
  }

  const ip = requestIP(req);
  const ipKey = requestKey(req);
  const username = (body.username || "").trim();

  // STATELESS: block machine-generated usernames.
  if (username && looksLikeBotUsername(username)) {
    flagActor(requestKey(req, username), `bot username at reset: ${username}`);
    logEvent({ req, route, status: 200, actor: `[DECEPTION:BOT] ${username}` });
    await tarpit();
    return NextResponse.json({ ok: true, token: null });
  }

  // Sequential attack pattern: signup → reset within 8s = bot.
  if (freshSignupHittingSensitiveRoute(ip)) {
    flagActor(ipKey, "sequential bot: signup→reset within 8s");
    logEvent({ req, route, status: 200, actor: `[DECEPTION:SEQ] ${username || "—"}` });
    await tarpit();
    return NextResponse.json({ ok: true, token: null });
  }

  // STATELESS: block known attackers.
  if (username && isKnownAttacker(username)) {
    flagActor(requestKey(req, username), `known attack actor at reset: ${username}`);
    logEvent({ req, route, status: 200, actor: `[DECEPTION] ${username}` });
    await tarpit();
    return NextResponse.json({ ok: true, token: null });
  }

  // Frequency — token spray / brute force protection.
  if (trackFrequency(ipKey)) {
    flagActor(ipKey, "high frequency on reset endpoint");
  }
  if (isFlagged(ipKey)) {
    logEvent({ req, route, status: 429, actor: username || "—" });
    return NextResponse.json({ error: "too many requests" }, { status: 429 });
  }

  const store = getStore();

  if (body.mode === "request") {
    if (!username) {
      logEvent({ req, route, status: 400, actor: null });
      return NextResponse.json({ error: "username required" }, { status: 400 });
    }
    const userId = store.usersByUsername.get(username);
    if (!userId) {
      logEvent({ req, route, status: 200, actor: username });
      return NextResponse.json({ ok: true, token: null });
    }
    const token = generateResetToken();
    store.resetTokens.set(token, {
      token,
      userId,
      expiresAt: Date.now() + RESET_TOKEN_TTL_MS,
    });
    logEvent({ req, route, status: 200, actor: username });
    return NextResponse.json({ ok: true, token });
  }

  if (body.mode === "confirm") {
    const token = (body.token || "").trim();
    const newPassword = body.newPassword || "";
    if (!token || !newPassword) {
      logEvent({ req, route, status: 400, actor: null });
      return NextResponse.json(
        { error: "token and newPassword required" },
        { status: 400 },
      );
    }
    const entry = store.resetTokens.get(token);
    if (!entry || entry.expiresAt < Date.now()) {
      logEvent({ req, route, status: 400, actor: null });
      return NextResponse.json(
        { error: "invalid or expired token" },
        { status: 400 },
      );
    }
    const user = store.users.get(entry.userId);
    if (!user) {
      logEvent({ req, route, status: 404, actor: null });
      return NextResponse.json({ error: "user not found" }, { status: 404 });
    }
    user.passwordHash = hashPassword(newPassword);
    store.resetTokens.delete(token);
    logEvent({ req, route, status: 200, actor: user.username });
    return NextResponse.json({ ok: true });
  }

  logEvent({ req, route, status: 400, actor: null });
  return NextResponse.json(
    { error: "mode must be 'request' or 'confirm'" },
    { status: 400 },
  );
}
