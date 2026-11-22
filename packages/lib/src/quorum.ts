import type { Setting } from "./types.js";

/** REQ-6-11's four settings this calculation applies to. */
export type SettingKind = "recovery" | "membership" | "removal" | "deactivation";

/**
 * REQ-6-8: the number of guardian approvals a setting value requires, given
 * N (guardians in the state before the operation) and E (guardians eligible
 * to approve it -- the caller computes E, since REQ-6-8 defines it
 * per-operation-type: E = N - 1 for `removeGuardian`, E = N otherwise).
 */
export function requiredApprovals(kind: SettingKind, value: Setting, n: number, e: number): number {
  // Step 1.
  let required: number;
  if (value === "any") required = 1;
  else if (value === "majority") required = Math.floor(e / 2) + 1;
  else if (value === "all") required = e;
  else required = Math.min(value, e);

  // Step 2.
  if (value !== "any" && n >= 2) required = Math.max(required, 2);

  // Step 3.
  if (kind === "membership" || kind === "deactivation") required = Math.max(required, Math.floor(n / 2) + 1);

  return required;
}

/** REQ-6-9: a clause that requires guardians per a setting cannot be met if E is 0 or if the required number exceeds E. */
export function guardiansCanApprove(required: number, e: number): boolean {
  return e > 0 && required <= e;
}
