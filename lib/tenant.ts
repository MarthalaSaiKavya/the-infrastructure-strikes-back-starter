import { randomBytes } from "node:crypto";

// Stable deployment/tenant identifier.
//
// Rules (per event spec):
//   - use TENANT_ID env var if present
//   - otherwise generate a stable identifier on first boot
//   - show it on the landing page
//   - include it in every log record
//
// "Stable on first boot" means: within the lifetime of a single process,
// the same id is returned for every call. On Vercel, each cold start
// generates a new one unless TENANT_ID is set — which is the intended
// production knob and what operators use for the event.
//
// Blue teams should NOT modify this file — it is event plumbing.

let cached: string | null = null;

export function getTenantId(): string {
  if (cached) return cached;
  const fromEnv = process.env.TENANT_ID?.trim();
  if (fromEnv) {
    cached = fromEnv;
    return cached;
  }
  cached = "tenant_" + randomBytes(6).toString("hex");
  return cached;
}
