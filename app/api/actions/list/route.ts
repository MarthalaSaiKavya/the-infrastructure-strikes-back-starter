import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";
import {
  isKnownAttacker, fingerprint, trackFrequency, flagActor, isFlagged,
  requestKey, requestIP, tarpit, fakeActionList,
} from "@/src/api/sentinel";

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

  const ip = requestIP(req);
  const key = requestKey(req, session.identity);

  // STATELESS: immediately serve fake list to known attack actor patterns.
  if (isKnownAttacker(session.identity)) {
    flagActor(key, `known attack actor: ${session.identity}`);
    logEvent({ req, route, status: 200, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json(fakeActionList());
  }

  // Fingerprint and frequency checks.
  const { score, reasons } = fingerprint(req);
  if (score >= 40) {
    flagActor(key, `fingerprint score ${score}: ${reasons.join(", ")}`);
  }
  if (trackFrequency(key)) {
    flagActor(key, "high request frequency on list");
  }

  // Serve fake list to flagged traffic.
  if (isFlagged(key) || isFlagged(ip)) {
    logEvent({ req, route, status: 200, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json(fakeActionList());
  }

  const store = getStore();
  const mine = Array.from(store.actions.values()).filter(
    (a) => a.ownerId === session.userId,
  );
  logEvent({ req, route, status: 200, actor: session.identity });
  return NextResponse.json({ count: mine.length, actions: mine });
}
