// Multi-signer proof collection (handoff #9): "each signer adds only its
// own proof. The registrar submits the operation once the approvals are
// met." `checkAcceptance` is the single oracle for "is this enough" --
// there is no separate per-type threshold rule to maintain here.
import { checkAcceptance, sortProofs, type DataIntegrityProof, type Did, type Operation } from "@did-guardian/lib";
import { deletePendingProof, getLog, getPendingProof, insertPendingProof, appendPendingProof, listAllPendingProofs, listPendingProofsForDid, type PendingProofRow } from "./db.js";
import { makeResolveLog } from "./logResolver.js";
import { submitOperation } from "./registrar.js";
import { RegistrarError } from "./registrarError.js";
import type { Env } from "./env.js";

const EXPIRY_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

export type PendingOutcome =
  | { status: "finalized"; operation: Operation }
  | { status: "collecting"; id: string; reason?: string };

function candidateFrom(row: PendingProofRow, proofs: DataIntegrityProof[]): Operation {
  return { ...(JSON.parse(row.operation) as object), proof: sortProofs(proofs) } as Operation;
}

/**
 * Proposes a candidate operation (its `prev` already set against the
 * current log) with the proposer's own proof already attached. Finalizes
 * immediately if that one proof is already enough.
 */
export async function proposeOperation(env: Env, did: Did, candidateWithoutProof: Omit<Operation, "proof">, proposerProof: DataIntegrityProof): Promise<PendingOutcome> {
  const proofs = [proposerProof];
  const candidate = { ...candidateWithoutProof, proof: sortProofs(proofs) } as Operation;
  const existingLog = await getLog(env, did);
  const result = await checkAcceptance(did, existingLog, candidate, makeResolveLog(env));
  if (result.accepted) {
    const operation = await submitOperation(env, did, candidate);
    return { status: "finalized", operation };
  }

  const id = crypto.randomUUID();
  const now = new Date();
  await insertPendingProof(env, {
    id,
    did,
    operation: JSON.stringify(candidateWithoutProof),
    proofs: JSON.stringify(proofs),
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + EXPIRY_MS).toISOString(),
  });
  return { status: "collecting", id, reason: result.reason };
}

/** Adds one more signer's own proof (REQ-5-12: each proof secures the operation independently, so signers never coordinate), then checks whether that's now enough. */
export async function contributeProof(env: Env, id: string, proof: DataIntegrityProof): Promise<PendingOutcome> {
  const row = await getPendingProof(env, id);
  if (!row) throw new RegistrarError("no such pending operation", 404);
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await deletePendingProof(env, id);
    throw new RegistrarError("this pending operation has expired", 410);
  }

  await appendPendingProof(env, id, proof);
  const updated = (await getPendingProof(env, id))!;
  const proofs = JSON.parse(updated.proofs) as DataIntegrityProof[];
  const candidate = candidateFrom(updated, proofs);

  const existingLog = await getLog(env, row.did);
  const result = await checkAcceptance(row.did, existingLog, candidate, makeResolveLog(env));
  if (result.accepted) {
    const operation = await submitOperation(env, row.did, candidate);
    await deletePendingProof(env, id);
    return { status: "finalized", operation };
  }
  return { status: "collecting", id, reason: result.reason };
}

/** Withdraws a proposal outright -- there is no separate "declined" record kept; a withdrawn or declined proposal is simply gone. */
export async function cancelPendingOperation(env: Env, id: string): Promise<void> {
  const row = await getPendingProof(env, id);
  if (!row) throw new RegistrarError("no such pending operation", 404);
  await deletePendingProof(env, id);
}

export async function getPendingOperationStatus(env: Env, id: string): Promise<{ did: Did; operation: object; proofs: DataIntegrityProof[]; expiresAt: string }> {
  const row = await getPendingProof(env, id);
  if (!row) throw new RegistrarError("no such pending operation", 404);
  return { did: row.did as Did, operation: JSON.parse(row.operation), proofs: JSON.parse(row.proofs), expiresAt: row.expires_at };
}

/** Every proposal collecting on `did`'s own log -- the account dashboard's own "needs a signature" list. */
export async function listPendingForDid(env: Env, did: Did): Promise<Array<{ id: string; did: Did; operation: object; proofs: DataIntegrityProof[] }>> {
  const rows = await listPendingProofsForDid(env, did);
  return rows.map((row) => ({ id: row.id, did: row.did as Did, operation: JSON.parse(row.operation), proofs: JSON.parse(row.proofs) }));
}

/** The daily sweep: removes every proposal past its own expiry. */
export async function expirePendingOperations(env: Env): Promise<void> {
  const rows = await listAllPendingProofs(env);
  for (const row of rows) {
    if (new Date(row.expires_at).getTime() < Date.now()) await deletePendingProof(env, row.id);
  }
}
