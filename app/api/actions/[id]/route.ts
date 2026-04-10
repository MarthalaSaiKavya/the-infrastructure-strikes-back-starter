import { NextResponse } from "next/server";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";
import { isActionOwner } from "@/src/api";
import {
  isKnownAttacker, isCanary, isFlagged, flagActor, requestKey, requestIP,
  tarpit, fakeActionList, trackEnumeration, trackSwarm, issueCanary,
} from "@/src/api/sentinel";

export const dynamic = "force-dynamic";

// GET /api/actions/[id]
export async function GET(req: Request, context: { params: { id: string } }) {
  const route = "/api/actions/[id]";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const id = context.params.id;
  const ip = requestIP(req);
  const key = requestKey(req, session.identity);

  // STATELESS: immediately serve deception to known attack actor patterns.
  if (isKnownAttacker(session.identity)) {
    flagActor(key, `known attack actor: ${session.identity}`);
    logEvent({ req, route, status: 200, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json(issueCanary(session.identity));
  }

  // Bot swarm detection: multiple distinct actors from the same IP.
  if (trackSwarm(ip, session.identity)) {
    flagActor(ip, `bot swarm: multiple actors from same IP`);
    flagActor(key, `part of bot swarm from ${ip}`);
    logEvent({ req, route, status: 403, actor: `[SWARM] ${session.identity}` });
    await tarpit();
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  // Canary token check — attacker stored and re-fetched a deception ID.
  const canary = isCanary(id);
  if (canary.hit) {
    flagActor(key, `canary token retrieved (issued to ${canary.issuedTo})`);
    logEvent({ req, route, status: 200, actor: `[CANARY_HIT] ${session.identity}` });
    await tarpit();
    return NextResponse.json({
      id,
      ownerId: session.userId,
      title: "Shared Resource Access",
      body: "Confidential — do not distribute",
      createdAt: new Date().toISOString(),
    });
  }

  // Serve deception to already-flagged traffic.
  if (isFlagged(key) || isFlagged(ip)) {
    logEvent({ req, route, status: 200, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    const fake = (fakeActionList() as { actions: object[] }).actions[0];
    return NextResponse.json(fake);
  }

  const action = getStore().actions.get(id);
  if (!action) {
    // Track enumeration — repeated 404s flag the caller.
    if (trackEnumeration(key)) {
      flagActor(key, "ID enumeration: repeated 404s on /api/actions/[id]");
      logEvent({ req, route, status: 404, actor: `[ENUM] ${session.identity}` });
    } else {
      logEvent({ req, route, status: 404, actor: session.identity });
    }
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }

  if (!isActionOwner(action, req)) {
    logEvent({ req, route, status: 403, actor: session.identity });
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  logEvent({ req, route, status: 200, actor: session.identity });
  return NextResponse.json(action);
}
