import type { Did, Threshold } from "./types.js";

/**
 * The minimum number of signatures required to satisfy `threshold` out of `n`
 * eligible signers. Majority is strict (`floor(n/2)+1`), not "at least half" --
 * strictness is what guarantees quorum intersection (any two valid signing
 * sets must share a member), which "at least half" does not for even `n`.
 * See spec §4.6.
 */
export function requiredCount(threshold: Threshold, n: number): number {
  // Audit WS-1.3/REQ-5-1: every threshold kind is unsatisfiable over an
  // empty eligible set -- zero valid signers must never be enough, no
  // matter which kind is configured. Without this, a guardian-less ward
  // (recovery_threshold evaluated against zero guardians) or a ward whose
  // sole guardian is deactivated (REQ-4-4) would let an attacker's bare
  // PoP-only proof satisfy "unanimous" or "at_least: 0" trivially.
  if (n === 0) return Infinity;
  if (threshold === "any") return 1;
  if (threshold === "unanimous") return n;
  if (threshold === "majority") return Math.floor(n / 2) + 1;
  if (typeof threshold === "object" && "at_least" in threshold) {
    // k < 1 would make this kind trivially satisfiable by zero signers too
    // (Math.max(k,0) === 0) -- treat it the same as an empty eligible set:
    // unsatisfiable, not merely "0 required". validatePolicy (WS-1.8)
    // additionally refuses to install a policy with k < 1 at all; this is
    // defense in depth for any threshold value that reaches here regardless.
    return threshold.at_least < 1 ? Infinity : threshold.at_least;
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
 *
 * Plus one more: when `current` is empty, this operation is establishing a
 * guardian over a previously guardian-less (fully autonomous) ward -- the
 * ward's own current operational key must also sign. Without this, anyone
 * could impose guardianship on an autonomous ward unilaterally, just by
 * having a willing incoming guardian sign; nothing would ever require the
 * ward's own consent to acquiring oversight in the first place. Ordinary
 * reshuffles among a ward's own already-consenting guardians don't re-
 * require this -- the ward already accepted oversight once, this isn't
 * re-litigated on every later transfer among those guardians.
 */
export function requiredTransferSigners(wardDid: Did, current: Did[], outgoing: Did[], incoming: Did[]): Did[] {
  const genuinelyNew = incoming.filter((d) => !current.includes(d));
  const required = [...outgoing, ...genuinelyNew];
  if (current.length === 0) required.push(wardDid);
  return [...new Set(required)];
}
