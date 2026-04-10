import { NextResponse } from "next/server";
import { randomBytes } from "node:crypto";
import { logEvent } from "@/lib/telemetry";
import { getStore } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";

export const dynamic = "force-dynamic";

// POST /api/actions/create
// Body: { title: string, body: string }
//
// SEEDED FLAWS:
//  - "Verbose internal error leakage": the catch block returns the raw
//    error message, stack, and a dump of the request body for
//    "debuggability". Attackers can learn internals by forcing errors.
//  - "No action creation rate limit": no per-user or global limit. A
//    client can spam create as fast as it can send.
export async function POST(req: Request) {
  const route = "/api/actions/create";
  const session = sessionFromRequest(req);
  if (!session) {
    logEvent({ req, route, status: 401, actor: null });
    return NextResponse.json({ error: "not authenticated" }, { status: 401 });
  }

  let rawBody: unknown;
  try {
    rawBody = await req.json();
    const body = rawBody as { title?: unknown; body?: unknown };

    const title = String(body.title ?? "").trim();
    const content = String(body.body ?? "").trim();
    if (!title) throw new Error("title is required");
    if (title.length > 200) throw new Error("title too long (max 200)");

    const id = "act_" + randomBytes(6).toString("hex");
    const action = {
      id,
      ownerId: session.userId,
      title,
      body: content,
      createdAt: new Date().toISOString(),
    };
    getStore().actions.set(id, action);

    logEvent({ req, route, status: 201, actor: session.identity });
    return NextResponse.json(action, { status: 201 });
  } catch (e) {
    const err = e as Error;
    logEvent({ req, route, status: 500, actor: session.identity });
    // SEEDED FLAW: verbose internal error leakage.
    return NextResponse.json(
      {
        error: "internal",
        message: err.message,
        stack: err.stack,
        received: rawBody,
      },
      { status: 500 },
    );
  }
}
