import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { flagActor, requestKey, tarpit } from "@/src/api/sentinel";

export const dynamic = "force-dynamic";

// HONEYPOT: /api/actions/delete-all
// Looks like a dangerous bulk-delete endpoint. No legitimate client
// calls this. Anyone who does gets flagged + tarpitted immediately.
export async function POST(req: Request) {
  const route = "/api/actions/delete-all";
  const key = requestKey(req);
  flagActor(key, "hit honeypot /api/actions/delete-all");
  logEvent({ req, route, status: 200, actor: `[HONEYPOT] ${key}` });
  await tarpit();
  // Return fake success to keep attacker busy.
  return NextResponse.json({ ok: true, deleted: 0 });
}

export async function GET(req: Request) {
  return POST(req);
}
