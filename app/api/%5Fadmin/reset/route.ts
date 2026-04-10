import { NextResponse } from "next/server";
import { checkAdmin } from "@/src/shared/admin";
import { clearEvents, logEvent } from "@/lib/telemetry";
import { resetStore } from "@/lib/store";

export const dynamic = "force-dynamic";

// POST /api/_admin/reset
// Admin-token protected. Wipes the in-memory store and the event buffer.
// Use this between scoring rounds.
export async function POST(req: Request) {
  const route = "/api/_admin/reset";
  const gate = checkAdmin(req);
  if (!gate.ok) {
    logEvent({ req, route, status: 401, actor: "admin?" });
    return NextResponse.json({ error: gate.reason }, { status: 401 });
  }
  resetStore();
  clearEvents();
  logEvent({ req, route, status: 200, actor: "admin" });
  return NextResponse.json({ ok: true });
}
