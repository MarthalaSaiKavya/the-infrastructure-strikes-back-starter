import { getAdminToken } from "@/lib/config";

// Minimal admin/judge gate. Accepts the token via header or query.
// Blue teams should NOT need to modify this — admin access is event plumbing.
export function checkAdmin(req: Request): { ok: true } | { ok: false; reason: string } {
  const expected = getAdminToken();
  const header = req.headers.get("x-admin-token") || "";
  const url = new URL(req.url);
  const query = url.searchParams.get("token") || "";
  const provided = header || query;
  if (!provided) return { ok: false, reason: "missing admin token" };
  if (provided !== expected) return { ok: false, reason: "bad admin token" };
  return { ok: true };
}
