import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";

export const dynamic = "force-dynamic";

// GET /api/actions/list
// Returns actions owned by the authenticated user.
export async function GET(req: Request) {
  const route = "/api/actions/list";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const store = getStore();
  const mine = Array.from(store.actions.values()).filter(
    (a) => a.ownerId === session.userId,
  );
  logEvent({ req, route, status: 200, actor: session.identity });
  return NextResponse.json({ count: mine.length, actions: mine });
}
