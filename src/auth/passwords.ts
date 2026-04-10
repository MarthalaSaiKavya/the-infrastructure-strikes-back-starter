import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

// Simple password hashing. Not production-grade parameters — this is
// event infra, not a real auth system.
//
// Format: "scrypt$<salt_hex>$<hash_hex>"

const N = 16384;
const KEYLEN = 32;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, { N });
  return `scrypt$${salt.toString("hex")}$${hash.toString("hex")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[1], "hex");
  const expected = Buffer.from(parts[2], "hex");
  const actual = scryptSync(password, salt, KEYLEN, { N });
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}
