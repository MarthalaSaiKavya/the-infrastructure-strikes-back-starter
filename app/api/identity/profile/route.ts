import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";
import {
  isKnownAttacker, fingerprint, flagActor, isFlagged,
  requestKey, tarpit,
} from "@/src/api/sentinel";

export const dynamic = "force-dynamic";

// GET /api/identity/profile
// Returns the authenticated user's profile.
export async function GET(req: Request) {
  const route = "/api/identity/profile";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const key = requestKey(req, session.identity);

  if (isKnownAttacker(session.identity)) {
    flagActor(key, `known attack actor: ${session.identity}`);
    logEvent({ req, route, status: 404, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json({ error: "user not found" }, { status: 404 });
  }

  if (isFlagged(key)) {
    logEvent({ req, route, status: 404, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json({ error: "user not found" }, { status: 404 });
  }

  const user = getStore().users.get(session.userId);
  if (!user) {
    logEvent({ req, route, status: 404, actor: session.identity });
    return NextResponse.json({ error: "user not found" }, { status: 404 });
  }
  logEvent({ req, route, status: 200, actor: session.identity });
  return NextResponse.json({
    id: user.id,
    username: user.username,
    email: user.email,
    displayName: user.displayName,
    createdAt: user.createdAt,
  });
}

// POST /api/identity/profile
// Body: { displayName?: string, email?: string }
// FIXED: body.userId is ignored — subject is always derived from the session.
export async function POST(req: Request) {
  const route = "/api/identity/profile";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const key = requestKey(req, session.identity);

  if (isKnownAttacker(session.identity)) {
    flagActor(key, `known attack actor: ${session.identity}`);
    logEvent({ req, route, status: 200, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json({ ok: true });
  }

  if (isFlagged(key)) {
    logEvent({ req, route, status: 200, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json({ ok: true });
  }

  let body: { userId?: string; displayName?: string; email?: string };
  try {
    body = await req.json();
  } catch {
    logEvent({ req, route, status: 400, actor: session.identity });
    return NextResponse.json({ error: "bad json" }, { status: 400 });
  }

  // FIXED: always use session.userId — ignore any body.userId to prevent
  // horizontal privilege escalation (profile update for arbitrary user).
  if (body.userId && body.userId !== session.userId) {
    flagActor(key, `profile userId injection attempt: ${body.userId}`);
    logEvent({ req, route, status: 403, actor: `[IDOR_ATTEMPT] ${session.identity}` });
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  const user = getStore().users.get(session.userId);
  if (!user) {
    logEvent({ req, route, status: 404, actor: session.identity });
    return NextResponse.json({ error: "user not found" }, { status: 404 });
  }

  if (typeof body.displayName === "string") {
    user.displayName = body.displayName.trim() || user.displayName;
  }
  if (typeof body.email === "string") {
    user.email = body.email.trim();
  }

  logEvent({ req, route, status: 200, actor: session.identity });
  return NextResponse.json({
    id: user.id,
    username: user.username,
    email: user.email,
    displayName: user.displayName,
  });
}
