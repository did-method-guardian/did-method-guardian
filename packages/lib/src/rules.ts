import { guardiansCanApprove, requiredApprovals } from "./quorum.js";
import { parseGuardianDid, type ShapeResult } from "./operations.js";
import type { Did, Key, Operation, State } from "./types.js";
import { DEFAULT_POLICY } from "./types.js";

const invalid = (reason: string): ShapeResult => ({ valid: false, reason });
const VALID: ShapeResult = { valid: true };

/**
 * The signers whose proof on this operation already verified
 * cryptographically (REQ-5-13/REQ-5-14) -- computed by verifyLog.ts, which
 * owns DID resolution. This module takes that result as given and decides
 * only whether REQ-7-4's table is satisfied; it performs no cryptography
 * and resolves no logs.
 */
export interface ValidSigners {
  keys: Set<Key>;
  dids: Set<Did>;
}

function approved(signers: ValidSigners, candidates: Iterable<string>): string[] {
  const out: string[] = [];
  for (const c of candidates) if (signers.keys.has(c) || signers.dids.has(c)) out.push(c);
  return out;
}

/** REQ-7-4: no proof from a signer outside `allowed`. */
function onlyAllowedSigners(signers: ValidSigners, allowed: Set<string>): ShapeResult {
  for (const k of signers.keys) if (!allowed.has(k)) return invalid(`REQ-7-4: no rule for this operation lists ${k} as a signer`);
  for (const d of signers.dids) if (!allowed.has(d)) return invalid(`REQ-7-4: no rule for this operation lists ${d} as a signer`);
  return VALID;
}

/** REQ-7-4/REQ-7-5/REQ-7-6: create. */
export function checkCreateApprovals(op: Extract<Operation, { type: "create" }>, signers: ValidSigners): ShapeResult {
  const parsed = parseGuardianDid(op.did);
  if (!parsed) return invalid("REQ-4-1: did must be a valid did:guardian identifier");
  const rootDid = `did:guardian:${parsed.domain}`;
  const isRoot = op.did === rootDid;

  const allowed = new Set<string>([...op.keys, ...op.guardians]);
  if (!isRoot) allowed.add(rootDid);

  const allowedCheck = onlyAllowedSigners(signers, allowed);
  if (!allowedCheck.valid) return allowedCheck;

  for (const key of op.keys) if (!signers.keys.has(key)) return invalid(`REQ-7-4: create requires a proof of possession for ${key}`);
  for (const guardian of op.guardians) if (!signers.dids.has(guardian)) return invalid(`REQ-7-4: create requires ${guardian}'s own approval`);
  if (!isRoot && !signers.dids.has(rootDid)) return invalid("REQ-7-4: create requires the root identity's approval");
  return VALID;
}

/** REQ-7-4/REQ-7-7/REQ-7-8: update. "one current key" is REQ-7.2's own phrase for a key in the state before the operation. */
export function checkUpdateApprovals(op: Extract<Operation, { type: "update" }>, stateBefore: State, signers: ValidSigners): ShapeResult {
  const allowed = new Set<string>([...op.keys, ...stateBefore.keys, ...stateBefore.guardians]);
  const allowedCheck = onlyAllowedSigners(signers, allowed);
  if (!allowedCheck.valid) return allowedCheck;

  for (const key of op.keys) if (!signers.keys.has(key)) return invalid(`REQ-7-4: update requires a proof of possession for ${key}`);

  const oneCurrentKey = approved(signers, stateBefore.keys).length > 0;
  if (oneCurrentKey) return VALID;

  const n = stateBefore.guardians.length;
  const e = n;
  const required = requiredApprovals("recovery", stateBefore.policy.recovery ?? DEFAULT_POLICY.recovery, n, e);
  if (!guardiansCanApprove(required, e)) return invalid("REQ-6-7: guardians cannot approve this update");
  if (approved(signers, stateBefore.guardians).length < required) return invalid("REQ-7-4: update requires one current key or enough guardian approvals per recovery");
  return VALID;
}

/** REQ-7-4/REQ-7-9/REQ-7-10/REQ-7-11: addGuardian. */
export function checkAddGuardianApprovals(op: Extract<Operation, { type: "addGuardian" }>, stateBefore: State, signers: ValidSigners): ShapeResult {
  if (stateBefore.guardians.includes(op.guardian)) return invalid("REQ-7-10: guardian must not already be a guardian");

  const n = stateBefore.guardians.length;
  const byKey = n === 0;
  const allowed = new Set<string>([op.guardian, ...(byKey ? stateBefore.keys : stateBefore.guardians)]);
  const allowedCheck = onlyAllowedSigners(signers, allowed);
  if (!allowedCheck.valid) return allowedCheck;

  if (!signers.dids.has(op.guardian)) return invalid("REQ-7-4: addGuardian requires the added guardian's own approval");

  if (byKey) {
    if (approved(signers, stateBefore.keys).length === 0) return invalid("REQ-7-4: addGuardian requires one current key when there are no guardians");
    return VALID;
  }
  const e = n;
  const required = requiredApprovals("membership", stateBefore.policy.membership ?? DEFAULT_POLICY.membership, n, e);
  if (!guardiansCanApprove(required, e)) return invalid("REQ-6-7: guardians cannot approve this addGuardian");
  if (approved(signers, stateBefore.guardians).length < required) return invalid("REQ-7-4: addGuardian requires enough guardian approvals per membership");
  return VALID;
}

/** REQ-7-4/REQ-7-12/REQ-7-13/REQ-7-14/REQ-7-15: removeGuardian. Evidence's own validity (REQ-7-14, a deactivate operation hash in the removed guardian's log) is checked by verifyLog.ts; this function only reads whether `evidence` is present. */
export function checkRemoveGuardianApprovals(op: Extract<Operation, { type: "removeGuardian" }>, stateBefore: State, signers: ValidSigners): ShapeResult {
  if (!stateBefore.guardians.includes(op.guardian)) return invalid("REQ-7-13: guardian must be a current guardian");

  const hasEvidence = op.evidence !== undefined;
  const allowed = new Set<string>(hasEvidence ? [...stateBefore.keys, ...stateBefore.guardians] : stateBefore.guardians);
  const allowedCheck = onlyAllowedSigners(signers, allowed);
  if (!allowedCheck.valid) return allowedCheck;

  if (signers.dids.has(op.guardian)) return VALID; // the removed guardian's own approval

  if (hasEvidence && (approved(signers, stateBefore.keys).length > 0 || approved(signers, stateBefore.guardians).length > 0)) return VALID;

  const others = stateBefore.guardians.filter((g) => g !== op.guardian);
  const n = stateBefore.guardians.length;
  const e = n - 1;
  const required = requiredApprovals("removal", stateBefore.policy.removal ?? DEFAULT_POLICY.removal, n, e);
  if (!guardiansCanApprove(required, e)) {
    return invalid(hasEvidence ? "REQ-7-4: removeGuardian requires the removed guardian's approval, or (with evidence) one current key or one guardian" : "REQ-6-7: guardians cannot approve this removeGuardian");
  }
  if (approved(signers, others).length >= required) return VALID;

  return invalid("REQ-7-4: removeGuardian requires the removed guardian's approval, enough guardian approvals per removal, or (with evidence) one current key or one guardian");
}

/** REQ-7-4/REQ-7-16/REQ-7-17: setPolicy. */
export function checkSetPolicyApprovals(_op: Extract<Operation, { type: "setPolicy" }>, stateBefore: State, signers: ValidSigners): ShapeResult {
  const n = stateBefore.guardians.length;
  const allowed = new Set<string>([...stateBefore.keys, ...(n > 0 ? stateBefore.guardians : [])]);
  const allowedCheck = onlyAllowedSigners(signers, allowed);
  if (!allowedCheck.valid) return allowedCheck;

  if (approved(signers, stateBefore.keys).length === 0) return invalid("REQ-7-4: setPolicy requires one current key");
  if (n === 0) return VALID;

  const e = n;
  const required = requiredApprovals("membership", stateBefore.policy.membership ?? DEFAULT_POLICY.membership, n, e);
  if (!guardiansCanApprove(required, e)) return invalid("REQ-6-7: guardians cannot approve this setPolicy");
  if (approved(signers, stateBefore.guardians).length < required) return invalid("REQ-7-4: setPolicy requires enough guardian approvals per membership when there are guardians");
  return VALID;
}

/** REQ-7-4/REQ-7-18/REQ-7-19: deactivate. */
export function checkDeactivateApprovals(_op: Extract<Operation, { type: "deactivate" }>, stateBefore: State, signers: ValidSigners): ShapeResult {
  const n = stateBefore.guardians.length;
  if (n === 0) {
    const allowedCheck = onlyAllowedSigners(signers, new Set(stateBefore.keys));
    if (!allowedCheck.valid) return allowedCheck;
    if (approved(signers, stateBefore.keys).length === 0) return invalid("REQ-7-4: deactivate requires one current key when there are no guardians");
    return VALID;
  }

  const deactivation = stateBefore.policy.deactivation ?? DEFAULT_POLICY.deactivation;
  const e = n;
  const required = requiredApprovals("deactivation", deactivation.threshold, n, e);
  const oneKey = () => approved(signers, stateBefore.keys).length > 0;
  const guardianThreshold = () => guardiansCanApprove(required, e) && approved(signers, stateBefore.guardians).length >= required;

  if (deactivation.by === "self") {
    const allowedCheck = onlyAllowedSigners(signers, new Set(stateBefore.keys));
    if (!allowedCheck.valid) return allowedCheck;
    return oneKey() ? VALID : invalid("REQ-7-4: deactivate requires one current key (policy.deactivation.by: self)");
  }
  if (deactivation.by === "guardians") {
    const allowedCheck = onlyAllowedSigners(signers, new Set(stateBefore.guardians));
    if (!allowedCheck.valid) return allowedCheck;
    return guardianThreshold() ? VALID : invalid("REQ-7-4: deactivate requires enough guardian approvals per deactivation.threshold (policy.deactivation.by: guardians)");
  }
  const allowedCheck = onlyAllowedSigners(signers, new Set([...stateBefore.keys, ...stateBefore.guardians]));
  if (!allowedCheck.valid) return allowedCheck;
  if (deactivation.by === "either") {
    return oneKey() || guardianThreshold() ? VALID : invalid("REQ-7-4: deactivate requires one current key or enough guardian approvals (policy.deactivation.by: either)");
  }
  // "both"
  if (!oneKey()) return invalid("REQ-7-4: deactivate requires one current key (policy.deactivation.by: both)");
  if (!guardianThreshold()) return invalid("REQ-7-4: deactivate requires enough guardian approvals per deactivation.threshold (policy.deactivation.by: both)");
  return VALID;
}

/** REQ-7-4: dispatches to the rule for `op.type`. */
export function checkApprovals(op: Operation, stateBefore: State, signers: ValidSigners): ShapeResult {
  switch (op.type) {
    case "create":
      return checkCreateApprovals(op, signers);
    case "update":
      return checkUpdateApprovals(op, stateBefore, signers);
    case "addGuardian":
      return checkAddGuardianApprovals(op, stateBefore, signers);
    case "removeGuardian":
      return checkRemoveGuardianApprovals(op, stateBefore, signers);
    case "setPolicy":
      return checkSetPolicyApprovals(op, stateBefore, signers);
    case "deactivate":
      return checkDeactivateApprovals(op, stateBefore, signers);
  }
}
