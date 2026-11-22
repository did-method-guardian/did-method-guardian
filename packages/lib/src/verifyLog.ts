import { apply, toDidDocument, toResolutionMetadata } from "./document.js";
import { checkOperationShape, operationHash, parseVerificationMethod, verifyProofSignature } from "./operations.js";
import { checkApprovals, type ValidSigners } from "./rules.js";
import type { DataIntegrityProof, Did, Log, LogResolver, Operation, State } from "./types.js";

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  state?: State;
}

function failure(reason: string): VerifyResult {
  return { valid: false, reason };
}

async function findByHash(log: Log, hash: string): Promise<number> {
  for (let i = 0; i < log.length; i++) {
    if ((await operationHash(log[i])) === hash) return i;
  }
  return -1;
}

/** REQ-5-13/REQ-5-14: one proof's validity. `ancestors` is REQ-8-3's cycle guard -- the (did, versionId) pairs whose verification is already pending somewhere in the current call chain. */
async function verifyProof(unsecuredDoc: unknown, proof: DataIntegrityProof, resolveLog: LogResolver, ancestors: Set<string>): Promise<VerifyResult> {
  const ref = parseVerificationMethod(proof.verificationMethod);
  if (!ref) return failure("REQ-5-12: unrecognized verificationMethod");

  if (ref.kind === "key") {
    const ok = await verifyProofSignature(unsecuredDoc, proof, ref.key);
    return ok ? { valid: true } : failure("REQ-5-13: the signature does not verify with that key");
  }

  const ancestorKey = `${ref.did}#${ref.versionId}`;
  if (ancestors.has(ancestorKey)) return failure("REQ-8-3: verifying this proof requires verifying the operation that contains it");

  const log = await resolveLog(ref.did);
  if (!log) return failure("REQ-8-4: could not retrieve the referenced log");

  const index = await findByHash(log, ref.versionId);
  if (index === -1) return failure("REQ-5-14: the referenced operation hash does not appear in that DID's log");

  const prefixResult = await verifyLogInternal(ref.did, log.slice(0, index + 1), resolveLog, new Set([...ancestors, ancestorKey]));
  if (!prefixResult.valid) return failure(prefixResult.reason!);

  const state = prefixResult.state!;
  if (state.deactivated) return failure("REQ-5-14: the state after that operation is deactivated");
  if (ref.index < 0 || ref.index >= state.keys.length) return failure("REQ-5-14: the state after that operation has no key at that index");

  const ok = await verifyProofSignature(unsecuredDoc, proof, state.keys[ref.index]);
  return ok ? { valid: true } : failure("REQ-5-14: the signature does not verify with that key");
}

/** REQ-7-14: `evidence` is a deactivate operation hash in `guardian`'s own log, and that log verifies up to and including it. */
async function checkEvidence(guardian: Did, evidence: string, resolveLog: LogResolver, ancestors: Set<string>): Promise<VerifyResult> {
  const ancestorKey = `${guardian}#${evidence}`;
  if (ancestors.has(ancestorKey)) return failure("REQ-8-3: verifying this evidence requires verifying the operation that contains it");

  const log = await resolveLog(guardian);
  if (!log) return failure("REQ-8-4: could not retrieve the referenced log");

  const index = await findByHash(log, evidence);
  if (index === -1) return failure("REQ-7-14: evidence does not match an operation in that guardian's log");
  if (log[index].type !== "deactivate") return failure("REQ-7-14: evidence must be the hash of a deactivate operation");

  const prefixResult = await verifyLogInternal(guardian, log.slice(0, index + 1), resolveLog, new Set([...ancestors, ancestorKey]));
  if (!prefixResult.valid) return failure(prefixResult.reason!);
  return { valid: true };
}

async function verifySigners(unsecuredDoc: unknown, proofs: DataIntegrityProof[], resolveLog: LogResolver, ancestors: Set<string>): Promise<{ signers?: ValidSigners; reason?: string }> {
  const signers: ValidSigners = { keys: new Set(), dids: new Set() };
  for (const proof of proofs) {
    const result = await verifyProof(unsecuredDoc, proof, resolveLog, ancestors);
    if (!result.valid) return { reason: result.reason };
    const ref = parseVerificationMethod(proof.verificationMethod)!;
    if (ref.kind === "key") signers.keys.add(ref.key);
    else signers.dids.add(ref.did);
  }
  return { signers };
}

/** REQ-8-1: verifies `log` as the log of `did`, assuming it is already known to be a prefix-or-whole log worth checking structurally from its own start. Used both for a top-level `verifyLog` call and, recursively, for REQ-5-14's "log up to and including that operation". */
async function verifyLogInternal(did: Did, log: Log, resolveLog: LogResolver, ancestors: Set<string>): Promise<VerifyResult> {
  // REQ-8-1 step 1.
  if (!Array.isArray(log) || log.length === 0) return failure("REQ-8-1: the log must be a non-empty array of operations");

  // REQ-8-1 step 2.
  const first = log[0];
  if (first.type !== "create") return failure("REQ-8-1: the first operation must be a create");
  if (first.did !== did) return failure("REQ-8-1: the first operation's did must equal the DID being verified");

  // REQ-8-1 step 4 (checked up front, over the whole log -- a later per-operation walk would otherwise still apply an operation after a deactivate before noticing).
  for (let i = 0; i < log.length - 1; i++) {
    if (log[i].type === "deactivate") return failure("REQ-8-1: no operation may follow a deactivate");
  }

  let state: State | undefined;
  let previousHash: string | null = null;

  for (let i = 0; i < log.length; i++) {
    const op = log[i];

    // REQ-8-1 step 5.1.
    const shape = checkOperationShape(op);
    if (!shape.valid) return failure(shape.reason!);

    // REQ-8-1 step 3.
    if (i === 0) {
      if (op.prev !== null) return failure("REQ-7-3: a create operation's prev must be null");
    } else if (op.prev !== previousHash) {
      return failure("REQ-8-1: prev must equal the operation hash of the preceding operation");
    }

    const hash = await operationHash(op);
    const opAncestors = new Set([...ancestors, `${did}#${hash}`]);

    if (op.type === "removeGuardian" && op.evidence !== undefined) {
      const evidenceResult = await checkEvidence(op.guardian, op.evidence, resolveLog, opAncestors);
      if (!evidenceResult.valid) return failure(evidenceResult.reason!);
    }

    // REQ-8-1 step 5.2.
    const unsecuredDoc = { ...op };
    delete (unsecuredDoc as { proof?: unknown }).proof;
    const signersResult = await verifySigners(unsecuredDoc, op.proof, resolveLog, opAncestors);
    if (!signersResult.signers) return failure(signersResult.reason!);

    // REQ-8-1 step 5.3. `state` is defined for every operation but the first (checkApprovals ignores it for `create`, which has no state before it).
    const approvals = checkApprovals(op, state as State, signersResult.signers);
    if (!approvals.valid) return failure(approvals.reason!);

    // REQ-8-1 steps 5.4/5.5.
    const applied = apply(did, state as State, op as Operation);
    if (!applied.valid) return failure(applied.reason!);
    state = applied.state!;
    previousHash = hash;
  }

  return { valid: true, state };
}

/** REQ-8-1/REQ-8-2: verifies the log of `did`. Depends only on this log and the logs `resolveLog` returns for the DIDs its proofs reference -- never on the time of verification. */
export async function verifyLog(did: Did, log: Log, resolveLog: LogResolver): Promise<VerifyResult> {
  return verifyLogInternal(did, log, resolveLog, new Set());
}

/** REQ-9-1: a DID's document and resolution metadata, from an already-verified log's final state. Call `verifyLog` first -- this does not re-verify. */
export function toResolutionResult(did: Did, state: State, lastOperationHash: string) {
  return { document: toDidDocument(did, state), metadata: toResolutionMetadata(lastOperationHash, state) };
}
