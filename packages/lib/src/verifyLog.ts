import { apply } from "./document.js";
import {
  checkOperationShape,
  isPlainObject,
  isSupportedCryptosuite,
  isSupportedOperationType,
  keyOfVerificationMethod,
  operationHash,
  permittedKeys,
  verifyProofSignature,
} from "./operations.js";
import { checkApprovals } from "./rules.js";
import type { DataIntegrityProof, Did, Key, Log, Operation, State } from "./types.js";

export type VerifyOutcome = "valid" | "invalid" | "unsupported";

export interface VerifyResult {
  result: VerifyOutcome;
  reason?: string;
  state?: State;
}

function result(outcome: VerifyOutcome, reason?: string, state?: State): VerifyResult {
  return { result: outcome, reason, state };
}

/**
 * REQ-8-1's unsupported condition, checked before the ordinary steps:
 * an unrecognized operation type, an unrecognized cryptosuite on one of
 * `proof`'s entries (never `attestation`, which REQ-11-2 checks during
 * resolution, not verification), or an extension name -- from the state's
 * `critical` before this operation, or from the operation's own
 * `critical` -- not in `implementedExtensions`.
 */
function unsupportedReason(op: unknown, criticalBefore: string[], implementedExtensions: ReadonlySet<string>): string | undefined {
  if (!isPlainObject(op)) return undefined; // not even an object -- REQ-5-1 catches this as invalid
  if (typeof op.type !== "string") return undefined; // REQ-5-1/7-2 catches this as invalid
  if (!isSupportedOperationType(op.type)) return `REQ-8-1: operation type "${op.type}" is not implemented`;

  const ownCritical = Array.isArray(op.critical) ? op.critical.filter((c): c is string => typeof c === "string") : [];
  for (const name of [...criticalBefore, ...ownCritical]) {
    if (!implementedExtensions.has(name)) return `REQ-8-1: extension "${name}" is not implemented`;
  }

  if (Array.isArray(op.proof)) {
    for (const p of op.proof) {
      if (isPlainObject(p) && typeof p.cryptosuite === "string" && !isSupportedCryptosuite(p.cryptosuite)) {
        return `REQ-8-1: cryptosuite "${p.cryptosuite}" is not implemented`;
      }
    }
  }
  return undefined;
}

/** REQ-5-14: every proof's signature verifies with the key in its own verificationMethod. Returns the set of keys that approved (REQ-5-16), or a failure reason. */
async function verifyProofs(op: object, proofs: DataIntegrityProof[]): Promise<{ validKeys?: Set<Key>; reason?: string }> {
  const validKeys = new Set<Key>();
  for (const proof of proofs) {
    const key = keyOfVerificationMethod(proof.verificationMethod);
    if (!key) return { reason: "REQ-5-11: verificationMethod must be a did:key reference" };
    const ok = await verifyProofSignature(op, proof, key);
    if (!ok) return { reason: "REQ-5-14: the signature does not verify with that key" };
    validKeys.add(key);
  }
  return { validKeys };
}

/**
 * REQ-8-1: verifies the log of `did`, reporting valid, invalid or
 * unsupported (REQ-8-2: depends only on this log). `implementedExtensions`
 * defaults to empty -- production code implements no extensions; a
 * caller opts into one (e.g. the toy `min-keys` extension, for
 * conformance testing only) by naming it explicitly.
 */
export async function verifyLog(did: Did, log: Log, implementedExtensions: ReadonlySet<string> = new Set()): Promise<VerifyResult> {
  if (!Array.isArray(log) || log.length === 0) return result("invalid", "REQ-8-1: the log must be a non-empty array of operations");

  let state: State | undefined;
  let previousHash: string | null = null;

  for (let i = 0; i < log.length; i++) {
    const op: unknown = log[i];

    // REQ-8-1 step 4: no operation follows a state in which deactivated is true.
    if (state?.deactivated) return result("invalid", "REQ-8-1: no operation may follow a deactivate", state);

    // REQ-8-1 intro: unsupported conditions are checked before the steps.
    const unsupported = unsupportedReason(op, state?.critical ?? [], implementedExtensions);
    if (unsupported) return result("unsupported", unsupported, state);

    // REQ-8-1 step 5.1 (Sections 5 and 7).
    const shape = checkOperationShape(op);
    if (!shape.valid) return result("invalid", shape.reason, state);
    const operation = op as Operation;

    // REQ-8-1 step 2/REQ-7-3/REQ-7-4.
    if (i === 0) {
      if (operation.type !== "create") return result("invalid", "REQ-7-3: the first operation must be a create");
      if (operation.did !== did) return result("invalid", "REQ-8-1: the first operation's did must equal the DID being verified");
    } else {
      if (operation.type === "create") return result("invalid", "REQ-7-3: a later operation must not be a create");
      // REQ-8-1 step 3.
      if (operation.prev !== previousHash) return result("invalid", "REQ-8-1: prev must equal the operation hash of the preceding operation", state);
    }

    // REQ-8-1 step 5.2 (REQ-5-14 proof validity; REQ-7-5 permitted keys).
    const proofsResult = await verifyProofs(operation, operation.proof);
    if (!proofsResult.validKeys) return result("invalid", proofsResult.reason, state);
    const allowed = permittedKeys(operation, state ?? { keys: [], guardians: [], successor: null });
    for (const key of proofsResult.validKeys) {
      if (!allowed.has(key)) return result("invalid", `REQ-7-5: no permitted signer includes ${key}`, state);
    }

    // REQ-8-1 step 5.3 (REQ-7-6). `state` is defined for every operation but the first (checkApprovals ignores it for create).
    const approvals = checkApprovals(operation, state as State, proofsResult.validKeys);
    if (!approvals.valid) return result("invalid", approvals.reason, state);

    // REQ-8-1 step 5.4 (REQ-6-7).
    const applied = apply(did, state as State, operation);
    if (!applied.valid) return result("invalid", applied.reason, state);
    state = applied.state;
    previousHash = await operationHash(operation);
  }

  return result("valid", undefined, state);
}
