import type { ActionObject } from "@/lib/store";
import { sessionFromRequest } from "@/src/auth";

export function isActionOwner(action: ActionObject, req: Request): boolean {
  const session = sessionFromRequest(req);
  if (!session) return false;
  return session.userId === action.ownerId;
}
