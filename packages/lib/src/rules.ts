import { canonicalize } from "./crypto.js";
import { guardiansCanApprove, requiredApprovals } from "./quorum.js";
import { invalid, sameEntry, VALID, type ShapeResult } from "./operations.js";
import type { Entry, Key, Operation, Policy, State } from "./types.js";
import { DEFAULT_POLICY } from "./types.js";

/** REQ-5-16: a key approves if it produced a valid proof. */
function allApprove(validKeys: Set<Key>, keys: Key[]): boolean {
  return keys.every((k) => validKeys.has(k));
}

/** REQ-5-16: a guardian or successor approves if at least one key in its entry approves. */
function entryApproves(validKeys: Set<Key>, entry: Entry): boolean {
  return entry.keys.some((k) => validKeys.has(k));
}

function oneCurrentKey(validKeys: Set<Key>, state: State): boolean {
  return state.keys.some((k) => validKeys.has(k));
}

function countApprovingGuardians(validKeys: Set<Key>, entries: Entry[]): number {
  return entries.filter((e) => entryApproves(validKeys, e)).length;
}

/** The REQ-6-8/REQ-6-9 "guardians per membership" clause alone, exported for accept.ts's own REQ-10-7 row 5: it needs to know whether membership would already be met counting only guardians the registrar can confirm still have standing, independent of the successor-to-null waiver. */
export function membershipApproved(stateBefore: State, validKeys: Set<Key>): boolean {
  const n = stateBefore.guardians.length;
  if (n === 0) return true;
  const required = requiredApprovals("membership", stateBefore.policy.membership ?? DEFAULT_POLICY.membership, n, n);
  return guardiansCanApprove(required, n) && countApprovingGuardians(validKeys, stateBefore.guardians) >= required;
}

/** REQ-7-6/REQ-7-7: create. */
export function checkCreateApprovals(op: Extract<Operation, { type: "create" }>, validKeys: Set<Key>): ShapeResult {
  if (!allApprove(validKeys, op.keys)) return invalid("REQ-7-6: create requires a proof of possession for every key in keys");
  for (const g of op.guardians) {
    if (!allApprove(validKeys, g.keys)) return invalid(`REQ-7-6: create requires a proof of possession for every key in ${g.did}'s entry`);
  }
  if (op.successor && !allApprove(validKeys, op.successor.keys)) return invalid("REQ-7-6: create requires a proof of possession for every key in successor's entry");
  return VALID;
}

/** REQ-7-6/REQ-7-10: update. */
export function checkUpdateApprovals(_op: Extract<Operation, { type: "update" }>, newKeys: Key[], stateBefore: State, validKeys: Set<Key>): ShapeResult {
  if (!allApprove(validKeys, newKeys)) return invalid("REQ-7-6: update requires a proof of possession for every key in keys");
  if (oneCurrentKey(validKeys, stateBefore)) return VALID;
  const n = stateBefore.guardians.length;
  const e = n;
  const required = requiredApprovals("recovery", stateBefore.policy.recovery ?? DEFAULT_POLICY.recovery, n, e);
  if (guardiansCanApprove(required, e) && countApprovingGuardians(validKeys, stateBefore.guardians) >= required) return VALID;
  return invalid("REQ-7-6: update requires one current key or enough guardian approvals per recovery");
}

/** REQ-7-6/REQ-7-13: addGuardian. */
export function checkAddGuardianApprovals(op: Extract<Operation, { type: "addGuardian" }>, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  if (stateBefore.guardians.some((g) => g.did === op.entry.did)) return invalid("REQ-7-13: the DID of entry must not already be a guardian");
  if (!allApprove(validKeys, op.entry.keys)) return invalid("REQ-7-6: addGuardian requires a proof of possession for every key in entry");
  if (!oneCurrentKey(validKeys, stateBefore)) return invalid("REQ-7-6: addGuardian requires one current key");
  const n = stateBefore.guardians.length;
  if (n === 0) return VALID;
  const e = n;
  const required = requiredApprovals("membership", stateBefore.policy.membership ?? DEFAULT_POLICY.membership, n, e);
  if (!guardiansCanApprove(required, e)) return invalid("REQ-6-9: guardians cannot approve this addGuardian");
  if (countApprovingGuardians(validKeys, stateBefore.guardians) < required) return invalid("REQ-7-6: addGuardian requires enough guardian approvals per membership");
  return VALID;
}

/** REQ-7-6/REQ-7-15: updateGuardian. */
export function checkUpdateGuardianApprovals(op: Extract<Operation, { type: "updateGuardian" }>, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  const namedEntry = stateBefore.successor?.did === op.guardian ? stateBefore.successor : stateBefore.guardians.find((g) => g.did === op.guardian);
  if (!namedEntry) return invalid("REQ-7-15: guardian must be the DID of a current guardian or of the successor");
  if (!allApprove(validKeys, op.keys)) return invalid("REQ-7-6: updateGuardian requires a proof of possession for every key in keys");
  if (entryApproves(validKeys, namedEntry)) return VALID;
  if (!oneCurrentKey(validKeys, stateBefore)) return invalid("REQ-7-6: updateGuardian requires a key in the named entry, or one current key together with one other guardian");
  const others = stateBefore.guardians.filter((g) => g.did !== op.guardian);
  if (others.some((g) => entryApproves(validKeys, g))) return VALID;
  return invalid("REQ-7-6: updateGuardian requires a key in the named entry, or one current key together with one other guardian");
}

/** REQ-7-6/REQ-7-17: removeGuardian. */
export function checkRemoveGuardianApprovals(op: Extract<Operation, { type: "removeGuardian" }>, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  const removed = stateBefore.guardians.find((g) => g.did === op.guardian);
  if (!removed) return invalid("REQ-7-17: guardian must be the DID of a current guardian");

  const n = stateBefore.guardians.length;
  if (n >= 2 && entryApproves(validKeys, removed)) return VALID;

  const others = stateBefore.guardians.filter((g) => g.did !== op.guardian);
  const e = n - 1;
  const required = requiredApprovals("removal", stateBefore.policy.removal ?? DEFAULT_POLICY.removal, n, e);
  if (guardiansCanApprove(required, e) && countApprovingGuardians(validKeys, others) >= required) return VALID;

  const hasEvidence = op.evidence !== undefined;
  if (hasEvidence && oneCurrentKey(validKeys, stateBefore)) return VALID;

  if (n === 1 && stateBefore.successor && oneCurrentKey(validKeys, stateBefore) && entryApproves(validKeys, stateBefore.successor)) return VALID;

  return invalid(
    "REQ-7-6: removeGuardian requires the removed guardian's approval (N >= 2), enough guardian approvals per removal, one current key with evidence, or (N = 1, with a successor) one current key together with the successor",
  );
}

/** D2 (clean-room r7/r7b, Z-1 and Z-3 fixes): the effective value of every `Policy` member that has a default, plus `maxWards`/`extensions` only when present -- `orphan` is deliberately excluded, since the waiver below compares everything else and requires `orphan` specifically to become "deactivate". */
function effectivePolicyExceptOrphan(policy: Policy): object {
  return {
    recovery: policy.recovery ?? DEFAULT_POLICY.recovery,
    membership: policy.membership ?? DEFAULT_POLICY.membership,
    removal: policy.removal ?? DEFAULT_POLICY.removal,
    deactivation: policy.deactivation ?? DEFAULT_POLICY.deactivation,
    ...(policy.maxWards !== undefined ? { maxWards: policy.maxWards } : {}),
    ...(policy.extensions !== undefined ? { extensions: policy.extensions } : {}),
  };
}

/**
 * D2/Z-3 (clean-room r7/r7b): a `setPolicy` that only drops a successor
 * that has lost standing (REQ-10-7's own row 5 is the real, registrar-
 * side gate on whether that's actually true) doesn't need full
 * `membership` approval -- but only for the single, narrow, mechanical
 * change this describes, not for "the successor changed" in general.
 * Z-3's own fix is this exact explicit condition: every policy member
 * other than `orphan` stays exactly as it was (defaults filled in on
 * both sides so an explicit default and an absent member compare
 * equal), no `critical` is added, and `orphan` becomes "deactivate" --
 * the only value it CAN become once `successor` is null (REQ-6-14).
 * Canonicalized (JCS) rather than compared field-by-field so that two
 * semantically identical `extensions` objects with different key order
 * still compare equal, same reasoning as every other hash/compare in
 * this library.
 */
export function isSuccessorToNullWaiver(op: Extract<Operation, { type: "setPolicy" }>, stateBefore: State): boolean {
  if (!stateBefore.successor) return false;
  if (op.successor !== null) return false;
  if (op.critical !== undefined) return false;
  if ((op.policy.orphan ?? DEFAULT_POLICY.orphan) !== "deactivate") return false;
  return canonicalize(effectivePolicyExceptOrphan(op.policy)) === canonicalize(effectivePolicyExceptOrphan(stateBefore.policy));
}

/** REQ-7-6/REQ-7-20: setPolicy. */
export function checkSetPolicyApprovals(op: Extract<Operation, { type: "setPolicy" }>, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  if (!oneCurrentKey(validKeys, stateBefore)) return invalid("REQ-7-6: setPolicy requires one current key");
  const n = stateBefore.guardians.length;
  if (n > 0 && !isSuccessorToNullWaiver(op, stateBefore)) {
    const e = n;
    const required = requiredApprovals("membership", stateBefore.policy.membership ?? DEFAULT_POLICY.membership, n, e);
    if (!guardiansCanApprove(required, e)) return invalid("REQ-6-9: guardians cannot approve this setPolicy");
    if (countApprovingGuardians(validKeys, stateBefore.guardians) < required) return invalid("REQ-7-6: setPolicy requires enough guardian approvals per membership when there are guardians");
  }
  const successorChanged = op.successor !== null && !(stateBefore.successor && sameEntry(op.successor, stateBefore.successor));
  if (op.successor !== null && successorChanged && !allApprove(validKeys, op.successor.keys)) {
    return invalid("REQ-7-6: setPolicy requires a proof of possession for every key in successor, when it names a new successor");
  }
  return VALID;
}

function checkRecoveryGated(op: { type: string }, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  if (oneCurrentKey(validKeys, stateBefore)) return VALID;
  const n = stateBefore.guardians.length;
  const e = n;
  const required = requiredApprovals("recovery", stateBefore.policy.recovery ?? DEFAULT_POLICY.recovery, n, e);
  if (guardiansCanApprove(required, e) && countApprovingGuardians(validKeys, stateBefore.guardians) >= required) return VALID;
  return invalid(`REQ-7-6: ${op.type} requires one current key or enough guardian approvals per recovery`);
}

/** REQ-7-6/REQ-7-22: acceptWard. */
export function checkAcceptWardApprovals(op: Extract<Operation, { type: "acceptWard" }>, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  if (stateBefore.wards.some((w) => w.did === op.ward.did)) return invalid("REQ-7-23: the DID of ward must not already be in wards");
  return checkRecoveryGated(op, stateBefore, validKeys);
}

/** REQ-7-6/REQ-7-25: releaseWard. */
export function checkReleaseWardApprovals(op: Extract<Operation, { type: "releaseWard" }>, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  if (!stateBefore.wards.some((w) => w.did === op.ward)) return invalid("REQ-7-25: ward must be the DID of a record in wards");
  return checkRecoveryGated(op, stateBefore, validKeys);
}

/** REQ-7-6/REQ-7-27: deactivate. */
export function checkDeactivateApprovals(_op: Extract<Operation, { type: "deactivate" }>, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  const n = stateBefore.guardians.length;
  if (n === 0) {
    return oneCurrentKey(validKeys, stateBefore) ? VALID : invalid("REQ-7-6: deactivate requires one current key when there are no guardians");
  }

  const deactivation = stateBefore.policy.deactivation ?? DEFAULT_POLICY.deactivation;
  const e = n;
  const required = requiredApprovals("deactivation", deactivation.threshold, n, e);
  const oneKey = oneCurrentKey(validKeys, stateBefore);
  const guardianThreshold = guardiansCanApprove(required, e) && countApprovingGuardians(validKeys, stateBefore.guardians) >= required;

  if (deactivation.by === "self") return oneKey ? VALID : invalid("REQ-7-6: deactivate requires one current key (policy.deactivation.by: self)");
  if (deactivation.by === "guardians") return guardianThreshold ? VALID : invalid("REQ-7-6: deactivate requires enough guardian approvals per deactivation.threshold (policy.deactivation.by: guardians)");
  if (deactivation.by === "either") return oneKey || guardianThreshold ? VALID : invalid("REQ-7-6: deactivate requires one current key or enough guardian approvals (policy.deactivation.by: either)");
  // "both"
  if (!oneKey) return invalid("REQ-7-6: deactivate requires one current key (policy.deactivation.by: both)");
  if (!guardianThreshold) return invalid("REQ-7-6: deactivate requires enough guardian approvals per deactivation.threshold (policy.deactivation.by: both)");
  return VALID;
}

/** REQ-7-6: dispatches to the rule for `op.type`. `validKeys` is every key with a valid proof on this operation (REQ-5-14/REQ-5-16). */
export function checkApprovals(op: Operation, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  switch (op.type) {
    case "create":
      return checkCreateApprovals(op, validKeys);
    case "update":
      return checkUpdateApprovals(op, op.keys, stateBefore, validKeys);
    case "addGuardian":
      return checkAddGuardianApprovals(op, stateBefore, validKeys);
    case "updateGuardian":
      return checkUpdateGuardianApprovals(op, stateBefore, validKeys);
    case "removeGuardian":
      return checkRemoveGuardianApprovals(op, stateBefore, validKeys);
    case "setPolicy":
      return checkSetPolicyApprovals(op, stateBefore, validKeys);
    case "acceptWard":
      return checkAcceptWardApprovals(op, stateBefore, validKeys);
    case "releaseWard":
      return checkReleaseWardApprovals(op, stateBefore, validKeys);
    case "deactivate":
      return checkDeactivateApprovals(op, stateBefore, validKeys);
  }
}
