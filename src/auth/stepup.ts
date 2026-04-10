// Optional step-up flow.
//
// How it's supposed to work:
//   1. User hits POST /api/auth/stepup with {code}
//   2. We compare {code} to the expected per-session challenge
//   3. If it matches, we mark the session as stepup=true
//
// SEEDED FLAW: fail-open step-up check.
// verifyStepupCode wraps its comparison in try/catch and returns true on
// any thrown error. Since it accesses fields on a potentially-missing
// input object without guarding first, a malformed body (e.g. {}) throws
// inside the try, gets swallowed, and the caller sees "verified".
//
// Blue teams: this is one of the three seeded auth flaws. Fix the
// fail-open behavior without breaking the happy path.

export type StepupInput = {
  code: string;
  expected: string;
};

export function verifyStepupCode(input: StepupInput): boolean {
  try {
    // Naive comparison; if input is malformed this throws and we "pass".
    const a = input.code.trim();
    const b = input.expected.trim();
    if (a.length === 0) return false;
    return a === b;
  } catch {
    // Fail-open on any error. SEEDED FLAW.
    return true;
  }
}

// Event-wide, fixed challenge. Real systems would mint per-session codes.
// Kept constant so judges can reason about the flow.
export const STEPUP_EXPECTED_CODE = "919293";
