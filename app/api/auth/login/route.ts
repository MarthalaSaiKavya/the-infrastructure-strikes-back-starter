import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import {
  sessionCookieHeader,
  signSession,
  verifyPassword,
} from "@/src/auth";

export const dynamic = "force-dynamic";

// POST /api/auth/login
// Body: { username: string, password: string, identity?: string }
//
// SEEDED FLAWS:
//  - "Client-influenced session identity": if the body includes an
//    `identity` field, we stash it into the session as the display /
//    ownership handle instead of using the authenticated username.
//    Downstream checks trust session.identity — so an attacker who
//    authenticates as themselves can claim any identity they like.
//  - "No login rate limit": the store has a loginAttempts map for a
//    counter, but this handler never reads or writes it. Blue teams
//    should notice the dead hook and wire a real limit.
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

  const store = getStore();
  const userId = store.usersByUsername.get(username);
  const user = userId ? store.users.get(userId) : undefined;
  if (!user || !verifyPassword(password, user.passwordHash)) {
    logEvent({ req, route, status: 401, actor: username });
    return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
  }

  // SEEDED FLAW: trust caller-supplied identity field if present.
  const identity =
    typeof body.identity === "string" && body.identity.trim()
      ? body.identity.trim()
      : user.username;

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
