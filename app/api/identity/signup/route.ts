import { NextResponse } from "next/server";
import { randomBytes } from "node:crypto";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { hashPassword } from "@/src/auth";

export const dynamic = "force-dynamic";

// POST /api/identity/signup
// Body: { username: string, password: string, email?: string, displayName?: string }
//
// SEEDED FLAW: "Unrestricted signup".
// No rate limit, no password strength check, no disposable-email
// detection, no CAPTCHA. The only check is uniqueness of username.
// A script can create arbitrary accounts. Blue teams should add limits
// and validation.
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

  logEvent({ req, route, status: 201, actor: username });
  return NextResponse.json({
    ok: true,
    id,
    username,
    displayName: user.displayName,
  });
}
