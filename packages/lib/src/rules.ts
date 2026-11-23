import { guardiansCanApprove, requiredApprovals } from "./quorum.js";
import { invalid, sameEntry, VALID, type ShapeResult } from "./operations.js";
import type { Entry, Key, Operation, State } from "./types.js";
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

/** REQ-7-6/REQ-7-20: setPolicy. */
export function checkSetPolicyApprovals(op: Extract<Operation, { type: "setPolicy" }>, stateBefore: State, validKeys: Set<Key>): ShapeResult {
  if (!oneCurrentKey(validKeys, stateBefore)) return invalid("REQ-7-6: setPolicy requires one current key");
  const n = stateBefore.guardians.length;
  if (n > 0) {
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
