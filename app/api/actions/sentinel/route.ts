import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { sentinelStats } from "@/src/api/sentinel";
import { getAdminToken } from "@/lib/config";

export const dynamic = "force-dynamic";

// GET /api/actions/sentinel?token=<admin_token>
// Returns live attacker detection stats: flagged actors, canary hits, etc.
// Protected by admin token — same as the judge dashboard.
export async function GET(req: Request) {
  const route = "/api/actions/sentinel";
  const url = new URL(req.url);
  const token = req.headers.get("x-admin-token") || url.searchParams.get("token") || "";

  if (token !== getAdminToken()) {
    logEvent({ req, route, status: 401, actor: "admin?" });
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  logEvent({ req, route, status: 200, actor: "admin" });
  return NextResponse.json(sentinelStats());
}
