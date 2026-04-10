import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { sessionFromRequest } from "@/src/auth";

export const dynamic = "force-dynamic";

// GET /api/auth/session
// Returns the current session's view of the caller. No secrets — this
// is a read-only inspection endpoint.
export async function GET(req: Request) {
  const route = "/api/auth/session";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 200, actor: null });
    return NextResponse.json({ authenticated: false });
  }
  logEvent({ req, route, status: 200, actor: session.identity });
  return NextResponse.json({
    authenticated: true,
    identity: session.identity,
    userId: session.userId,
    stepup: session.stepup,
    iat: session.iat,
  });
}
