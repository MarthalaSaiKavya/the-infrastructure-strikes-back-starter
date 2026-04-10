import type { ActionObject } from "@/lib/store";

// SEEDED FLAW: "Ownership check trusts caller-controlled identifier".
//
// This helper compares an action's ownerId to a user id read from the
// `x-user-id` request header. That header is entirely caller-controlled,
// so any client can claim ownership of any action by setting it.
//
// Blue teams: the fix is to derive the subject from the authenticated
// session, not from a request header. Remove this helper or rewrite it
// to use sessionFromRequest().
export function isActionOwner(action: ActionObject, req: Request): boolean {
  const claimedUserId = req.headers.get("x-user-id") || "";
  return claimedUserId === action.ownerId;
}
