import { NextResponse } from "next/server";
import { checkAdmin } from "@/src/shared/admin";
import { getEvents, logEvent } from "@/lib/telemetry";

export const dynamic = "force-dynamic";

// GET /api/_admin/events[?route=...&method=...&status=...&actor=...&limit=200]
// Admin-token protected. Returns the in-memory event buffer, newest last.
export async function GET(req: Request) {
  const route = "/api/_admin/events";
  const gate = checkAdmin(req);
  if (!gate.ok) {
    logEvent({ req, route, status: 401, actor: "admin?" });
    return NextResponse.json({ error: gate.reason }, { status: 401 });
  }

  const url = new URL(req.url);
  const fRoute = url.searchParams.get("route");
  const fMethod = url.searchParams.get("method");
  const fStatus = url.searchParams.get("status");
  const fActor = url.searchParams.get("actor");
  const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get("limit") || 200)));

  let rows = getEvents();
  if (fRoute) rows = rows.filter((r) => r.route.includes(fRoute));
  if (fMethod) rows = rows.filter((r) => r.method.toUpperCase() === fMethod.toUpperCase());
  if (fStatus) rows = rows.filter((r) => String(r.status) === fStatus);
  if (fActor) rows = rows.filter((r) => (r.actor || "").includes(fActor));

  const trimmed = rows.slice(-limit);
  logEvent({ req, route, status: 200, actor: "admin" });
  return NextResponse.json({ count: trimmed.length, events: trimmed });
}
