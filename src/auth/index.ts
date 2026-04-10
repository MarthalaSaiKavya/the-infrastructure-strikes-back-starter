// Auth module surface used by route handlers.
// Blue teams: this is one of the primary hardening surfaces.

export { hashPassword, verifyPassword } from "./passwords";
export {
  SESSION_COOKIE,
  signSession,
  verifySession,
  sessionFromRequest,
  sessionCookieHeader,
} from "./session";
export type { SessionData } from "./session";
export { verifyStepupCode, STEPUP_EXPECTED_CODE } from "./stepup";
