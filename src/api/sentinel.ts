// Attacker detection, fingerprinting, tarpit, canary, and deception system.
// All state is module-level (survives across requests in the same process).

import { randomBytes } from "node:crypto";

// --- Flagged actor registry ---
const flaggedActors = new Map<string, { flaggedAt: number; reason: string }>();

// --- Request frequency tracking (general) ---
const requestFreq = new Map<string, { count: number; windowStart: number }>();
const FREQ_WINDOW_MS = 10_000;
const FREQ_THRESHOLD = 15;

// --- ID enumeration tracking ---
// Tracks 404s per key — rapid enumeration flags the caller.
const enumTracker = new Map<string, { count: number; windowStart: number }>();
const ENUM_WINDOW_MS = 15_000;
const ENUM_THRESHOLD = 8;

// --- Bot swarm tracking ---
// Maps IP -> Set of distinct actors seen from that IP.
const swarmTracker = new Map<string, Set<string>>();
const SWARM_THRESHOLD = 3; // 3+ distinct actors from same IP = swarm

// --- SQL injection pattern detection ---
const SQL_INJECTION_RE = /('|--|;|\/\*|\*\/|union\s|select\s|insert\s|drop\s|or\s+1=1|or\s+')/i;

// --- Canary token registry ---
const canaryTokens = new Map<string, { issuedAt: number; issuedTo: string }>();

// --- Tarpit delay ---
const TARPIT_DELAY_MS = 8_000;

// Fake action pool for deception
const FAKE_ACTIONS = [
  { id: "act_decoy_001", ownerId: "usr_decoy", title: "Q3 Budget Review", body: "See attached spreadsheet", createdAt: "2026-04-09T18:00:00.000Z" },
  { id: "act_decoy_002", ownerId: "usr_decoy", title: "Infrastructure Audit", body: "Pending approval from ops team", createdAt: "2026-04-09T18:01:00.000Z" },
  { id: "act_decoy_003", ownerId: "usr_decoy", title: "Access Review", body: "Monthly user access review in progress", createdAt: "2026-04-09T18:02:00.000Z" },
];

// --- Fingerprinting ---
export function fingerprint(req: Request): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;

  const ua = req.headers.get("user-agent") || "";
  const accept = req.headers.get("accept") || "";

  if (!ua) {
    score += 40;
    reasons.push("missing user-agent");
  } else if (/curl|python|go-http|axios|node-fetch|httpclient|wget|java|ruby|php/i.test(ua)) {
    score += 30;
    reasons.push(`bot user-agent: ${ua.slice(0, 40)}`);
  }

  if (!accept) {
    score += 20;
    reasons.push("missing accept header");
  }

  if (!req.headers.get("accept-language")) {
    score += 10;
    reasons.push("missing accept-language");
  }

  return { score, reasons };
}

// --- SQL injection probe detection ---
// Returns true if the payload looks like a SQL injection attempt.
export function looksLikeSQLInjection(input: string): boolean {
  return SQL_INJECTION_RE.test(input);
}

// --- General frequency tracking ---
export function trackFrequency(key: string): boolean {
  const now = Date.now();
  const entry = requestFreq.get(key);
  if (!entry || now - entry.windowStart > FREQ_WINDOW_MS) {
    requestFreq.set(key, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count > FREQ_THRESHOLD;
}

// --- ID enumeration tracking ---
// Call on 404 responses. Returns true when threshold exceeded.
export function trackEnumeration(key: string): boolean {
  const now = Date.now();
  const entry = enumTracker.get(key);
  if (!entry || now - entry.windowStart > ENUM_WINDOW_MS) {
    enumTracker.set(key, { count: 1, windowStart: now });
    return false;
  }
  entry.count += 1;
  return entry.count >= ENUM_THRESHOLD;
}

// --- Bot swarm detection ---
// Track distinct actors per IP. Returns true when swarm threshold hit.
export function trackSwarm(ip: string, actor: string): boolean {
  if (!swarmTracker.has(ip)) {
    swarmTracker.set(ip, new Set());
  }
  const actors = swarmTracker.get(ip)!;
  actors.add(actor);
  return actors.size >= SWARM_THRESHOLD;
}

// --- Flag an actor ---
export function flagActor(key: string, reason: string): void {
  if (!flaggedActors.has(key)) {
    flaggedActors.set(key, { flaggedAt: Date.now(), reason });
  }
}

// --- Check if flagged ---
export function isFlagged(key: string): boolean {
  return flaggedActors.has(key);
}

// --- Derive a request key from IP + optional actor ---
export function requestKey(req: Request, actor?: string | null): string {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("x-real-ip")
    || "unknown";
  return actor ? `${ip}:${actor}` : ip;
}

// --- Extract just the IP ---
export function requestIP(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("x-real-ip")
    || "unknown";
}

// --- Tarpit ---
export async function tarpit(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, TARPIT_DELAY_MS));
}

// --- Issue a canary token ---
export function issueCanary(actor: string): object {
  const id = "act_c" + randomBytes(5).toString("hex");
  canaryTokens.set(id, { issuedAt: Date.now(), issuedTo: actor });
  return {
    id,
    ownerId: "usr_" + randomBytes(4).toString("hex"),
    title: "Shared Resource Access",
    body: "Confidential — do not distribute",
    createdAt: new Date().toISOString(),
  };
}

// --- Check if an ID is a canary ---
export function isCanary(id: string): { hit: boolean; issuedTo?: string } {
  const entry = canaryTokens.get(id);
  if (!entry) return { hit: false };
  return { hit: true, issuedTo: entry.issuedTo };
}

// --- Deception responses ---
export function fakeActionList(): object {
  return { count: FAKE_ACTIONS.length, actions: FAKE_ACTIONS };
}

export function fakeCreatedAction(): object {
  return {
    id: "act_f" + randomBytes(5).toString("hex"),
    ownerId: "usr_" + randomBytes(4).toString("hex"),
    title: "Pending Review",
    body: "",
    createdAt: new Date().toISOString(),
  };
}

// --- Sentinel stats for admin endpoint ---
export function sentinelStats(): object {
  return {
    flagged_count: flaggedActors.size,
    canary_count: canaryTokens.size,
    swarm_ips: Array.from(swarmTracker.entries())
      .filter(([, actors]) => actors.size >= SWARM_THRESHOLD)
      .map(([ip, actors]) => ({ ip, actor_count: actors.size })),
    flagged_actors: Array.from(flaggedActors.entries()).map(([k, v]) => ({
      key: k,
      reason: v.reason,
      flagged_ago_s: Math.round((Date.now() - v.flaggedAt) / 1000),
    })),
  };
}
