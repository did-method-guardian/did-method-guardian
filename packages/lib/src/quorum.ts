import type { Did, Threshold } from "./types.js";

/**
 * The minimum number of signatures required to satisfy `threshold` out of `n`
 * eligible signers. Majority is strict (`floor(n/2)+1`), not "at least half" --
 * strictness is what guarantees quorum intersection (any two valid signing
 * sets must share a member), which "at least half" does not for even `n`.
 * See spec §4.6.
 */
export function requiredCount(threshold: Threshold, n: number): number {
  if (threshold === "any") return n === 0 ? Infinity : 1;
  if (threshold === "unanimous") return n;
  if (threshold === "majority") return Math.floor(n / 2) + 1;
  if (typeof threshold === "object" && "at_least" in threshold) {
    return Math.max(threshold.at_least, 0);
  }
  throw new Error(`unknown threshold: ${JSON.stringify(threshold)}`);
}

/**
 * Checks whether `signers` (a set of DIDs that produced a valid, independently
 * verified signature over this exact operation) satisfies `threshold` among
 * `eligible` (the current set this threshold is evaluated against -- e.g. the
 * current guardian set, as of the operation's own `prev` anchor).
 *
 * This is a simple count-and-check, not a combinatorial search: duplicates
 * and ineligible signers are ignored, never double-counted or substituted.
 */
export function meetsThreshold(
  threshold: Threshold,
  signers: Did[],
  eligible: Did[],
): boolean {
  const eligibleSet = new Set(eligible);
  const validDistinctSigners = new Set(signers.filter((d) => eligibleSet.has(d)));
  const required = requiredCount(threshold, eligible.length);
  return validDistinctSigners.size >= required;
}

/**
 * The signers required for a `guardian_transfer`: every outgoing guardian
 * (consenting to their own removal) plus every *genuinely new* incoming
 * guardian -- someone who wasn't already in `current` before this operation.
 * Telling "continuing" apart from "newly joining" requires knowing `current`;
 * `outgoing`/`incoming` alone can't distinguish them (both are just "absent
 * from outgoing, present in incoming" from that narrower view).
 */
export function requiredTransferSigners(current: Did[], outgoing: Did[], incoming: Did[]): Did[] {
  const genuinelyNew = incoming.filter((d) => !current.includes(d));
  return [...new Set([...outgoing, ...genuinelyNew])];
}
