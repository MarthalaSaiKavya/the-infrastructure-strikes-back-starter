import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { hashPassword } from "@/src/auth";
import { RESET_TOKEN_TTL_MS, generateResetToken } from "@/src/identity";

export const dynamic = "force-dynamic";

// POST /api/identity/reset
//
// Two modes, selected by body.mode:
//   { mode: "request", username }
//     -> creates a reset token bound to the user, returns it in the
//        response. (Event infra has no email; this is fine.)
//   { mode: "confirm", token, newPassword }
//     -> swaps the user's password hash if the token matches and is
//        not expired.
//
// See src/identity/reset.ts for the seeded weak-token flaw.
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

  const store = getStore();

  if (body.mode === "request") {
    const username = (body.username || "").trim();
    if (!username) {
      logEvent({ req, route, status: 400, actor: null });
      return NextResponse.json({ error: "username required" }, { status: 400 });
    }
    const userId = store.usersByUsername.get(username);
    if (!userId) {
      // Respond success regardless to avoid trivial username enumeration
      // via this endpoint. Still weak overall — token gen is predictable.
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
