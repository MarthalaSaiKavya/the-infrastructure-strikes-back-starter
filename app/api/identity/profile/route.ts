import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";

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
// Body: { userId?: string, displayName?: string, email?: string }
//
// SEEDED FLAW: "Profile update lacks proper subject verification".
// The handler requires *some* valid session, then updates whichever
// user id is named in the request body. If body.userId is absent it
// falls back to the session's user id — so the happy path looks fine.
// But any authenticated caller can mutate any profile by naming a
// different userId.
//
// Blue teams: the fix is to ignore body.userId entirely and always
// derive the subject from the session.
export async function POST(req: Request) {
  const route = "/api/identity/profile";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  let body: { userId?: string; displayName?: string; email?: string };
  try {
    body = await req.json();
  } catch {
    logEvent({ req, route, status: 400, actor: session.identity });
    return NextResponse.json({ error: "bad json" }, { status: 400 });
  }

  // SEEDED FLAW: body.userId wins over session.userId.
  const targetUserId = body.userId || session.userId;
  const user = getStore().users.get(targetUserId);
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
