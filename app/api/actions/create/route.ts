import { NextResponse } from "next/server";
import { randomBytes } from "node:crypto";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";
import {
  isKnownAttacker, fingerprint, trackFrequency, trackSwarm,
  flagActor, isFlagged, requestKey, requestIP,
  tarpit, issueCanary, looksLikeSQLInjection,
} from "@/src/api/sentinel";

export const dynamic = "force-dynamic";

const RATE_LIMIT = 20;
const RATE_WINDOW_MS = 60 * 1000;
const createAttempts = new Map<string, { count: number; firstAt: number }>();

export async function POST(req: Request) {
  const route = "/api/actions/create";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  const ip = requestIP(req);
  const key = requestKey(req, session.identity);

  // STATELESS: immediately serve deception to known attack actor patterns.
  if (isKnownAttacker(session.identity)) {
    flagActor(key, `known attack actor: ${session.identity}`);
    logEvent({ req, route, status: 201, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json(issueCanary(session.identity), { status: 201 });
  }

  // Fingerprint suspicious clients.
  const { score, reasons } = fingerprint(req);
  if (score >= 40) flagActor(key, `fingerprint ${score}: ${reasons.join(", ")}`);

  // Frequency and swarm checks.
  if (trackFrequency(key)) flagActor(key, "high frequency on create");
  if (trackSwarm(ip, session.identity)) {
    flagActor(ip, "bot swarm");
    flagActor(key, `swarm from ${ip}`);
  }

  // Stateful deception for flagged traffic.
  if (isFlagged(key) || isFlagged(ip)) {
    logEvent({ req, route, status: 201, actor: `[DECEPTION] ${session.identity}` });
    await tarpit();
    return NextResponse.json(issueCanary(session.identity), { status: 201 });
  }

  // Rate limit per user.
  const now = Date.now();
  const bucket = createAttempts.get(session.userId);
  if (bucket && now - bucket.firstAt < RATE_WINDOW_MS) {
    if (bucket.count >= RATE_LIMIT) {
      logEvent({ req, route, status: 429, actor: session.identity });
      return NextResponse.json({ error: "too many requests" }, { status: 429 });
    }
    bucket.count += 1;
  } else {
    createAttempts.set(session.userId, { count: 1, firstAt: now });
  }

  let rawBody: unknown;
  try {
    rawBody = await req.json();
    const body = rawBody as { title?: unknown; body?: unknown };
    const title = String(body.title ?? "").trim();
    const content = String(body.body ?? "").trim();

    if (looksLikeSQLInjection(title) || looksLikeSQLInjection(content)) {
      flagActor(key, "SQL injection probe in payload");
      logEvent({ req, route, status: 400, actor: `[SQLI_PROBE] ${session.identity}` });
      await tarpit();
      return NextResponse.json({ error: "invalid input" }, { status: 400 });
    }

    if (!title) throw new Error("title is required");
    if (title.length > 200) throw new Error("title too long (max 200)");

    const id = "act_" + randomBytes(6).toString("hex");
    const action = { id, ownerId: session.userId, title, body: content, createdAt: new Date().toISOString() };
    getStore().actions.set(id, action);

    logEvent({ req, route, status: 201, actor: session.identity });
    return NextResponse.json(action, { status: 201 });
  } catch (e) {
    logEvent({ req, route, status: 500, actor: session.identity });
    return NextResponse.json({ error: "internal" }, { status: 500 });
  }
}
