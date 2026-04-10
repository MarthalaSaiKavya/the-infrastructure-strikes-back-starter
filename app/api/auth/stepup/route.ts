import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import {
  STEPUP_EXPECTED_CODE,
  sessionCookieHeader,
  sessionFromRequest,
  signSession,
  verifyStepupCode,
} from "@/src/auth";

export const dynamic = "force-dynamic";

// POST /api/auth/stepup
// Body: { code: string }
//
// Verifies an optional step-up code. On success, marks the session as
// stepup=true and re-issues the session cookie.
//
// See src/auth/stepup.ts for the seeded fail-open flaw.
export async function POST(req: Request) {
  const route = "/api/auth/stepup";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  // Intentionally does NOT guard against missing body / missing code.
  // See stepup.ts: verifyStepupCode fails open on thrown errors.
  const body = (await req.json().catch(() => ({}))) as { code?: unknown };

  const ok = verifyStepupCode({
    code: body.code as string,
    expected: STEPUP_EXPECTED_CODE,
  });

  if (!ok) {
    logEvent({ req, route, status: 401, actor: session.identity });
    return NextResponse.json({ error: "stepup failed" }, { status: 401 });
  }

  const newToken = signSession({ ...session, stepup: true });
  logEvent({ req, route, status: 200, actor: session.identity });
  const res = NextResponse.json({ ok: true, stepup: true });
  res.headers.set("Set-Cookie", sessionCookieHeader(newToken));
  return res;
}
