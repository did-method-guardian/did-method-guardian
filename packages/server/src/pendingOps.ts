// Asynchronous signature collection -- the orchestration layer around
// pendingOpMachine.ts. Every async/crypto/DB-dependent decision (is this
// signature valid, does the threshold the formal spec defines now count as
// met, can the resulting operation actually be appended) is computed HERE,
// then fed into the machine as plain, already-decided event data. The
// machine itself never performs any of that work -- see its own header
// comment for why.

import {
  replay,
  verifySignerSig,
  OPERATION_RULES,
  type Did,
  type Operation,
  type RuleGovernedOpType,
  type VerificationContext,
} from "@did-guardian/lib";
import { createActor } from "xstate";
import { pendingOperationMachine } from "./pendingOpMachine.js";
import type { Env } from "./env.js";
import {
  findWard,
  loadLog,
  makeExternalResolver,
  makeGuardianLivenessResolver,
  resolveDocument,
  submitOperation,
  RegistrarError,
} from "./registrar.js";
import { getPendingOperation, getWardByDid, insertPendingOperation, listPendingOperationsForSigner, updatePendingOperationState } from "./db.js";
import type { PendingOperationRow } from "./db.js";
import { notifyRequiredSigner } from "./email.js";
import { randomSecret } from "./secretBox.js";

const PROPOSAL_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days -- a reasonable fixed window, not itself a protocol requirement
const TERMINAL_STATES = ["finalized", "declined", "expired"];

function isRuleGoverned(type: string): type is RuleGovernedOpType {
  return type in OPERATION_RULES;
}

async function buildContextForWard(env: Env, wardDid: Did): Promise<VerificationContext> {
  const log = await loadLog(env, wardDid);
  const state = replay(wardDid, log);
  return {
    wardDid,
    state,
    resolveKey: makeExternalResolver(env),
    isGuardianLive: makeGuardianLivenessResolver(env),
  };
}

/** `wards.name` uses `""` as the bare-domain root's own sentinel (registrar.ts); submitOperation/resolveDocument take `null` for that same identity. */
async function nameForWardDid(env: Env, wardDid: Did): Promise<string | null> {
  const ward = await getWardByDid(env, wardDid);
  if (!ward) throw new RegistrarError(`ward ${wardDid} is not hosted by this registrar`, 404);
  return ward.name === "" ? null : ward.name;
}

export interface ProposeResult {
  id: string;
  state: string;
  document?: unknown;
}

/**
 * Registers a new multi-signer proposal. `op` already carries the
 * proposer's own signature in its `sigs` map (the "propose" endpoint's
 * whole point -- it's not a bare shape, it's a real, already-partially-
 * signed candidate). Immediately finalizes if that one signature already
 * satisfies the operation's own rule (e.g. a 1-of-N threshold); otherwise
 * persists it as `collecting` and notifies whichever other required
 * signers this registrar can reach.
 */
export async function proposeOperation(env: Env, name: string | null, op: Operation): Promise<ProposeResult> {
  if (!isRuleGoverned(op.type)) {
    throw new RegistrarError(`operation type "${op.type}" does not support asynchronous proposal`, 400);
  }
  const rule = OPERATION_RULES[op.type];
  const ward = await findWard(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const ctx = await buildContextForWard(env, ward.did as Did);

  const shape = await rule.checkShape(op as any, ctx);
  if (!shape.valid) throw new RegistrarError(shape.reason ?? "invalid operation shape", 400);

  const sigs = (op as { sigs?: Record<Did, string> }).sigs ?? {};
  if (Object.keys(sigs).length === 0) throw new RegistrarError("a proposal must already carry at least the proposer's own signature", 400);
  let anyValid = false;
  for (const did of Object.keys(sigs)) {
    if (await verifySignerSig(op, did, sigs[did], ctx.resolveKey)) anyValid = true;
  }
  if (!anyValid) throw new RegistrarError("none of the attached signatures are valid", 400);

  const satisfiedAtPropose = await rule.isSatisfied(op as any, [], ctx);
  const requiredSigners = await rule.requiredSigners(op as any, ctx);

  const actor = createActor(pendingOperationMachine, { input: { collectedSigs: sigs, satisfiedAtPropose } }).start();
  const id = randomSecret();
  const now = new Date();
  const row: PendingOperationRow = {
    id,
    ward_did: ward.did,
    op_type: op.type,
    partial_op: JSON.stringify(op),
    required_signers: JSON.stringify(requiredSigners),
    collected_sigs: JSON.stringify(actor.getSnapshot().context.collectedSigs),
    state: actor.getSnapshot().value as string,
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + PROPOSAL_TTL_MS).toISOString(),
  };
  await insertPendingOperation(env, row);

  if (actor.getSnapshot().value === "satisfied") {
    const final = await finalize(env, name, id, op, actor.getSnapshot().context.collectedSigs);
    return { id, state: final.state, document: final.document };
  }

  const alreadySigned = new Set(Object.keys(sigs));
  for (const signerDid of requiredSigners) {
    if (!alreadySigned.has(signerDid)) await notifyRequiredSigner(env, signerDid, id, op.type);
  }
  return { id, state: "collecting" };
}

export interface ContributeResult {
  state: string;
  document?: unknown;
}

/** A later required signer adds their own signature to an already-proposed operation. */
export async function contributeToOperation(env: Env, id: string, signerDid: Did, sig: string): Promise<ContributeResult> {
  const row = await getPendingOperation(env, id);
  if (!row) throw new RegistrarError(`no pending operation "${id}"`, 404);
  if (TERMINAL_STATES.includes(row.state)) {
    throw new RegistrarError(`pending operation "${id}" is already ${row.state}`, 409);
  }
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await updatePendingOperationState(env, id, "expired", row.collected_sigs);
    throw new RegistrarError(`pending operation "${id}" has expired`, 409);
  }

  const op = JSON.parse(row.partial_op) as Operation;
  if (!isRuleGoverned(op.type)) throw new RegistrarError(`operation type "${op.type}" does not support asynchronous proposal`, 500);
  const rule = OPERATION_RULES[op.type];
  const ctx = await buildContextForWard(env, row.ward_did as Did);

  if (row.state === "satisfied") {
    // Already met -- nothing a new signature could add. Most likely a retry after a prior FINALIZE_FAILED; just re-attempt rather than silently dropping this signer's contribution (the machine itself has no CONTRIBUTE handler in `satisfied`, so sending one would be a no-op).
    const collectedSigs = JSON.parse(row.collected_sigs) as Record<Did, string>;
    const name = await nameForWardDid(env, row.ward_did as Did);
    const final = await finalize(env, name, id, op, collectedSigs);
    return { state: final.state, document: final.document };
  }

  if (!(await verifySignerSig(op, signerDid, sig, ctx.resolveKey))) {
    throw new RegistrarError("invalid signature", 400);
  }

  const collectedSigs = JSON.parse(row.collected_sigs) as Record<Did, string>;
  const candidateOp = { ...op, sigs: { ...collectedSigs, [signerDid]: sig } } as Operation;
  const satisfiedNow = await rule.isSatisfied(candidateOp as any, [], ctx);

  const resolved = pendingOperationMachine.resolveState({
    value: row.state,
    context: { collectedSigs, satisfiedAtPropose: false },
  });
  const actor = createActor(pendingOperationMachine, { snapshot: resolved, input: { collectedSigs, satisfiedAtPropose: false } }).start();
  actor.send({ type: "CONTRIBUTE", did: signerDid, sig, satisfiedNow });

  const newState = actor.getSnapshot().value as string;
  const newCollectedSigs = actor.getSnapshot().context.collectedSigs;
  await updatePendingOperationState(env, id, newState, JSON.stringify(newCollectedSigs));

  if (newState === "satisfied") {
    const name = await nameForWardDid(env, row.ward_did as Did);
    const final = await finalize(env, name, id, op, newCollectedSigs);
    return { state: final.state, document: final.document };
  }
  return { state: newState };
}

/** Only valid while still `collecting` -- once `satisfied`, the operation is already cryptographically valid and ready to finalize; a late decline from some other party can no longer retroactively invalidate signatures that already meet the rule. */
export async function declineOperation(env: Env, id: string): Promise<{ state: string }> {
  const row = await getPendingOperation(env, id);
  if (!row) throw new RegistrarError(`no pending operation "${id}"`, 404);
  if (row.state !== "collecting") {
    throw new RegistrarError(`pending operation "${id}" is ${row.state}, not collecting -- it can no longer be declined`, 409);
  }
  const collectedSigs = JSON.parse(row.collected_sigs) as Record<Did, string>;
  const resolved = pendingOperationMachine.resolveState({ value: row.state, context: { collectedSigs, satisfiedAtPropose: false } });
  const actor = createActor(pendingOperationMachine, { snapshot: resolved, input: { collectedSigs, satisfiedAtPropose: false } }).start();
  actor.send({ type: "DECLINE" });
  await updatePendingOperationState(env, id, actor.getSnapshot().value as string, row.collected_sigs);
  return { state: actor.getSnapshot().value as string };
}

export async function listPendingForSigner(env: Env, signerDid: Did): Promise<PendingOperationRow[]> {
  const rows = await listPendingOperationsForSigner(env, signerDid);
  const active: PendingOperationRow[] = [];
  for (const row of rows) {
    if (new Date(row.expires_at).getTime() < Date.now()) {
      await updatePendingOperationState(env, row.id, "expired", row.collected_sigs);
      continue;
    }
    active.push(row);
  }
  return active;
}

async function finalize(env: Env, name: string | null, id: string, op: Operation, collectedSigs: Record<Did, string>): Promise<{ state: string; document?: unknown }> {
  const fullOp = { ...op, sigs: collectedSigs } as Operation;
  const result = await submitOperation(env, name, fullOp);
  if (result.accepted) {
    await updatePendingOperationState(env, id, "finalized", JSON.stringify(collectedSigs));
    const document = await resolveDocument(env, name);
    return { state: "finalized", document };
  }
  // Retriable -- the signatures collected are still valid; only the append attempt failed (e.g. the log head moved).
  await updatePendingOperationState(env, id, "satisfied", JSON.stringify(collectedSigs));
  throw new RegistrarError(`collected enough signatures, but finalizing failed: ${result.reason}`, 409);
}
