import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";
import { isActionOwner } from "@/src/api";

export const dynamic = "force-dynamic";

// GET /api/actions/[id]
// Returns a single action if the caller is its owner.
//
// Ownership is checked via src/api/ownership.ts — see the seeded flaw
// there. This handler looks correct on the surface but trusts a
// caller-controlled identifier for the ownership comparison.
export async function GET(req: Request, context: { params: { id: string } }) {
  const route = "/api/actions/[id]";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const id = context.params.id;
  const action = getStore().actions.get(id);
  if (!action) {
    logEvent({ req, route, status: 404, actor: session.identity });
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }

  if (!isActionOwner(action, req)) {
    logEvent({ req, route, status: 403, actor: session.identity });
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  logEvent({ req, route, status: 200, actor: session.identity });
  return NextResponse.json(action);
}
