import { createHmac, timingSafeEqual } from "node:crypto";
import { getSessionSecret } from "@/lib/config";

// Signed cookie session. Naive on purpose — no rotation, no expiry
// enforcement beyond a soft field.

export const SESSION_COOKIE = "isb_session";

export type SessionData = {
  userId: string;
  // "identity" is the display handle used for ownership / audit.
  // This is populated from login input (see auth/login) — see seeded flaw.
  identity: string;
  // When true, the session has cleared the optional step-up check.
  stepup: boolean;
  // Issued-at timestamp (ms).
  iat: number;
};

function b64url(input: Buffer | string): string {
  const b = typeof input === "string" ? Buffer.from(input, "utf8") : input;
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64url(s: string): Buffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64");
}

export function signSession(data: SessionData): string {
  const payload = b64url(JSON.stringify(data));
  const mac = b64url(
    createHmac("sha256", getSessionSecret()).update(payload).digest(),
  );
  return `${payload}.${mac}`;
}

export function verifySession(token: string | undefined | null): SessionData | null {
  if (!token) return null;
  const dot = token.indexOf(".");
  if (dot <= 0) return null;
  const payload = token.slice(0, dot);
  const mac = token.slice(dot + 1);
  const expected = createHmac("sha256", getSessionSecret()).update(payload).digest();
  const provided = fromB64url(mac);
  if (provided.length !== expected.length) return null;
  if (!timingSafeEqual(provided, expected)) return null;
  try {
    const parsed = JSON.parse(fromB64url(payload).toString("utf8")) as SessionData;
    if (typeof parsed !== "object" || !parsed) return null;
    if (typeof parsed.userId !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}

// Read the session from a request's Cookie header.
export function sessionFromRequest(req: Request): SessionData | null {
  const cookie = req.headers.get("cookie") || "";
  const entries = cookie.split(/;\s*/).map((kv) => {
    const i = kv.indexOf("=");
    return i < 0 ? [kv, ""] : [kv.slice(0, i), kv.slice(i + 1)];
  });
  const found = entries.find(([k]) => k === SESSION_COOKIE);
  if (!found) return null;
  return verifySession(decodeURIComponent(found[1]));
}

// Build a Set-Cookie header value for the session cookie.
export function sessionCookieHeader(token: string | null): string {
  if (token === null) {
    return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
  }
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`;
}
