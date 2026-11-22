import {
  checkAlsoKnownAsShape,
  checkGuardiansShape,
  checkKeyOverlap,
  checkKeysShape,
  checkMinKeysExtension,
  checkPolicyShape,
  checkServiceShape,
  checkWardsShape,
  invalid,
  VALID,
  type ShapeResult,
} from "./operations.js";
import type { Did, Entry, Operation, Service, State } from "./types.js";

export interface ApplyResult {
  valid: boolean;
  reason?: string;
  state?: State;
}

/** REQ-7-8: a create operation's own initial state. */
function initialState(op: Extract<Operation, { type: "create" }>): State {
  return {
    keys: op.keys,
    guardians: op.guardians,
    successor: op.successor,
    wards: [],
    policy: op.policy,
    services: op.services,
    alsoKnownAs: op.alsoKnownAs,
    deactivated: false,
    critical: [],
  };
}

/** REQ-6-10: the change `removeGuardian` applies when it leaves `guardians` empty. */
function applyOrphan(state: State): State {
  if (state.guardians.length > 0) return state;
  const orphan = state.policy.orphan ?? "deactivate";
  if (orphan === "deactivate") return { ...state, deactivated: true };
  if (orphan === "independent") return state;
  // "successor"
  const successor = state.successor as Entry;
  return { ...state, guardians: [successor], successor: null, policy: { ...state.policy, orphan: "deactivate" } };
}

/** REQ-7-32: an operation's own `critical` (only `create`/`setPolicy` can carry one) adds each name to the state's `critical`, if not already there. */
function applyCritical(state: State, op: { critical?: string[] }): State {
  if (!op.critical || op.critical.length === 0) return state;
  const critical = [...state.critical];
  for (const name of op.critical) if (!critical.includes(name)) critical.push(name);
  return { ...state, critical };
}

/**
 * REQ-7-11/REQ-7-14/REQ-7-16/REQ-7-19/REQ-6-10/REQ-7-21/REQ-7-24/REQ-7-26/
 * REQ-7-28/REQ-7-32: applies one operation (already approved -- see
 * rules.ts) to the state before it, and checks that the result conforms
 * to Section 6 (REQ-6-7/REQ-8-1 step 5.4). Purely mechanical otherwise:
 * it does not check approvals or signatures.
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
      state = { ...stateBefore, guardians: [...stateBefore.guardians, op.entry] };
      break;
    case "updateGuardian": {
      if (stateBefore.successor && stateBefore.successor.did === op.guardian) {
        state = { ...stateBefore, successor: { ...stateBefore.successor, keys: op.keys } };
      } else {
        state = { ...stateBefore, guardians: stateBefore.guardians.map((g) => (g.did === op.guardian ? { ...g, keys: op.keys } : g)) };
      }
      break;
    }
    case "removeGuardian":
      state = applyOrphan({ ...stateBefore, guardians: stateBefore.guardians.filter((g) => g.did !== op.guardian) });
      break;
    case "setPolicy":
      state = { ...stateBefore, policy: op.policy, successor: op.successor };
      break;
    case "acceptWard":
      state = { ...stateBefore, wards: [...stateBefore.wards, op.ward] };
      break;
    case "releaseWard":
      state = { ...stateBefore, wards: stateBefore.wards.filter((w) => w.did !== op.ward) };
      break;
    case "deactivate":
      state = { ...stateBefore, deactivated: true };
      break;
  }

  state = applyCritical(state, op as { critical?: string[] });

  const conforms = checkStateShape(did, state);
  if (!conforms.valid) return { valid: false, reason: conforms.reason };

  return { valid: true, state };
}

/** REQ-6-7: the state conforms to REQ-6-1 through REQ-6-6 and Section 6.3. */
function checkStateShape(did: Did, state: State): ShapeResult {
  const keysShape = checkKeysShape(state.keys);
  if (!keysShape.valid) return keysShape;
  const guardiansShape = checkGuardiansShape(state.guardians, did);
  if (!guardiansShape.valid) return guardiansShape;
  if (state.successor) {
    if (state.successor.did === did) return invalid("REQ-6-5: an identity's DID must not appear in its own successor");
    if (state.guardians.some((g) => g.did === (state.successor as Entry).did)) return invalid("REQ-6-5: the DID of successor must not appear in guardians");
  }
  const wardsShape = checkWardsShape(state.wards, did);
  if (!wardsShape.valid) return wardsShape;
  const policyShape = checkPolicyShape(state.policy, state.successor !== null);
  if (!policyShape.valid) return policyShape;
  if (state.policy.maxWards !== undefined && state.wards.length > state.policy.maxWards) return invalid("REQ-6-15: wards must not contain more than maxWards records");
  const servicesShape = checkServiceShape(state.services);
  if (!servicesShape.valid) return servicesShape;
  const alsoKnownAsShape = checkAlsoKnownAsShape(state.alsoKnownAs);
  if (!alsoKnownAsShape.valid) return alsoKnownAsShape;
  const keyOverlap = checkKeyOverlap(state.keys, state.guardians, state.successor);
  if (!keyOverlap.valid) return keyOverlap;
  const minKeysShape = checkMinKeysExtension(state);
  if (!minKeysShape.valid) return minKeysShape;
  return VALID;
}

export interface DidDocument {
  "@context": string[];
  id: Did;
  verificationMethod?: { id: string; type: "Multikey"; controller: Did; publicKeyMultibase: string }[];
  authentication?: string[];
  assertionMethod?: string[];
  capabilityInvocation?: string[];
  service?: { id: string; type: string; serviceEndpoint: string }[];
  alsoKnownAs?: string[];
}

/** REQ-9-1/REQ-9-2/REQ-9-3: the DID document derived from the state after the last operation of the log. */
export function toDidDocument(did: Did, state: State): DidDocument {
  if (state.deactivated) {
    return { "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"], id: did };
  }
  const verificationMethod = state.keys.map((key, n) => ({ id: `${did}#key-${n}`, type: "Multikey" as const, controller: did, publicKeyMultibase: key }));
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
  anchor: string;
  deactivated?: true;
}

/** REQ-9-4. */
export function toResolutionMetadata(version: string, anchor: string, state: State): ResolutionMetadata {
  return state.deactivated ? { versionId: version, anchor, deactivated: true } : { versionId: version, anchor };
}
