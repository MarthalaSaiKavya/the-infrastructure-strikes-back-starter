// Password reset token generation.
//
// SEEDED FLAW: weak reset token generation.
// Uses Math.random() which is not cryptographically secure and is
// predictable. Tokens are 10 characters of base-36 output, which is a
// tiny keyspace for any attacker who can trigger a reset and then
// enumerate tokens.
//
// Blue teams: replace with node:crypto randomBytes and a
// sufficiently-long token (e.g. 32 bytes -> 64 hex chars).

export function generateResetToken(): string {
  // Math.random() — predictable and low-entropy. Intentionally weak.
  return Math.random().toString(36).slice(2, 12);
}

export const RESET_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes
