import { randomBytes } from "node:crypto";

// Centralized config reads. Blue teams should NOT modify this file.
//
// Defaults are deliberately permissive so the app "just runs" for the event.
// Operators set real values via environment variables.

let cachedSessionSecret: string | null = null;

export function getAdminToken(): string {
  return process.env.ADMIN_TOKEN?.trim() || "letmein";
}

export function getSessionSecret(): string {
  if (cachedSessionSecret) return cachedSessionSecret;
  const fromEnv = process.env.SESSION_SECRET?.trim();
  if (fromEnv) {
    cachedSessionSecret = fromEnv;
    return cachedSessionSecret;
  }
  // Ephemeral fallback: sessions won't survive a restart. Fine for the event.
  cachedSessionSecret = randomBytes(32).toString("hex");
  return cachedSessionSecret;
}
