import { checkAlsoKnownAsShape, checkGuardiansShape, checkKeysShape, checkServiceShape } from "./operations.js";
import type { Did, Operation, Service, State } from "./types.js";

export interface ApplyResult {
  valid: boolean;
  reason?: string;
  state?: State;
}

const invalid = (reason: string): ApplyResult => ({ valid: false, reason });

/** REQ-7-6: a create operation's own initial state. */
function initialState(op: Extract<Operation, { type: "create" }>): State {
  return {
    keys: op.keys,
    guardians: op.guardians,
    policy: op.policy,
    services: op.services,
    alsoKnownAs: op.alsoKnownAs,
    deactivated: false,
  };
}

/**
 * REQ-7-8/REQ-7-11/REQ-7-15/REQ-7-17/REQ-7-19: applies one operation
 * (already approved -- see rules.ts) to the state before it, and checks
 * that the result conforms to Section 6 (REQ-8-1 step 5.4), including
 * REQ-6-3 against `did` -- the identity's own DID, which REQ-6-3 forbids
 * from its `guardians` after any operation, not only at `create`. Purely
 * mechanical otherwise: it does not check approvals or signatures.
 */
export function apply(did: Did, stateBefore: State, op: Operation): ApplyResult {
  let state: State;
  switch (op.type) {
    case "create":
      state = initialState(op);
      break;
    case "update":
      state = { ...stateBefore, keys: op.keys, services: op.services, alsoKnownAs: op.alsoKnownAs };
      break;
    case "addGuardian":
      state = { ...stateBefore, guardians: [...stateBefore.guardians, op.guardian] };
      break;
    case "removeGuardian":
      state = { ...stateBefore, guardians: stateBefore.guardians.filter((g) => g !== op.guardian) };
      break;
    case "setPolicy":
      state = { ...stateBefore, policy: op.policy };
      break;
    case "deactivate":
      state = { ...stateBefore, deactivated: true };
      break;
  }

  const keysShape = checkKeysShape(state.keys);
  if (!keysShape.valid) return invalid(keysShape.reason!);
  const guardiansShape = checkGuardiansShape(state.guardians, did);
  if (!guardiansShape.valid) return invalid(guardiansShape.reason!);
  const servicesShape = checkServiceShape(state.services);
  if (!servicesShape.valid) return invalid(servicesShape.reason!);
  const alsoKnownAsShape = checkAlsoKnownAsShape(state.alsoKnownAs);
  if (!alsoKnownAsShape.valid) return invalid(alsoKnownAsShape.reason!);

  return { valid: true, state };
}

export interface DidDocument {
  "@context": string[];
  id: Did;
  verificationMethod: { id: string; type: "Multikey"; controller: Did; publicKeyMultibase: string }[];
  authentication: string[];
  assertionMethod: string[];
  capabilityInvocation: string[];
  service: { id: string; type: string; serviceEndpoint: string }[];
  alsoKnownAs?: string[];
}

/** REQ-9-1/REQ-9-2/REQ-9-4: the DID document derived from the state after the last operation of the log. */
export function toDidDocument(did: Did, state: State): DidDocument {
  const verificationMethod = state.deactivated
    ? []
    : state.keys.map((key, n) => ({ id: `${did}#key-${n}`, type: "Multikey" as const, controller: did, publicKeyMultibase: key }));
  const vmIds = verificationMethod.map((vm) => vm.id);
  const doc: DidDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: did,
    verificationMethod,
    authentication: vmIds,
    assertionMethod: vmIds,
    capabilityInvocation: vmIds,
    service: state.services.map((s: Service) => ({ ...s, id: `${did}${s.id}` })),
  };
  if (state.alsoKnownAs.length > 0) doc.alsoKnownAs = state.alsoKnownAs;
  return doc;
}

export interface ResolutionMetadata {
  versionId: string;
  deactivated?: true;
}

/** REQ-9-3/REQ-9-4. */
export function toResolutionMetadata(lastOperationHash: string, state: State): ResolutionMetadata {
  return state.deactivated ? { versionId: lastOperationHash, deactivated: true } : { versionId: lastOperationHash };
}
