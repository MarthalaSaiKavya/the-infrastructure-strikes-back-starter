import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { flagActor, requestKey, tarpit } from "@/src/api/sentinel";

export const dynamic = "force-dynamic";

// HONEYPOT: /api/actions/admin
// No legitimate client should ever hit this route. Anyone who does
// is probing the API surface and gets flagged + tarpitted.
export async function GET(req: Request) {
  const route = "/api/actions/admin";
  const key = requestKey(req);
  flagActor(key, "hit honeypot /api/actions/admin");
  logEvent({ req, route, status: 403, actor: `[HONEYPOT] ${key}` });
  await tarpit();
  return NextResponse.json({ error: "forbidden" }, { status: 403 });
}

export async function POST(req: Request) {
  return GET(req);
}
