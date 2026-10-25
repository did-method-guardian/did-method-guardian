// Asynchronous signature collection -- the orchestration layer around
// pendingOpMachine.ts. Every async/crypto/DB-dependent decision (is this
// signature valid, does the threshold the formal spec defines now count as
// met, can the resulting operation actually be appended) is computed HERE,
// then fed into the machine as plain, already-decided event data. The
// machine itself never performs any of that work -- see its own header
// comment for why.

import {
  replay,
  verifyPayload,
  verifySignerSig,
  liveGuardians,
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
import {
  getPendingOperation,
  getPendingOperationByToken,
  getPendingOperationToken,
  getWardByDid,
  insertPendingOperation,
  listPendingOperationsCollecting,
  listPendingOperationsForSigner,
  updatePendingOperationState,
} from "./db.js";
import type { PendingOperationRow } from "./db.js";
import { notifyAwaitingSignature, notifyVoteRecorded, notifyProgress, notifyDeclined, notifyWithdrawn, notifyFinalized, notifyReminder } from "./email.js";
import { randomSecret } from "./secretBox.js";

const REMINDER_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

const PROPOSAL_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days -- a reasonable fixed window, not itself a protocol requirement

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

async function verifyDidSignature(did: Did, payload: unknown, sig: string, ctx: VerificationContext): Promise<boolean> {
  const keys = await ctx.resolveKey(did);
  if (!keys) return false;
  for (const pk of keys) {
    if (await verifyPayload(payload, sig, pk)) return true;
  }
  return false;
}

/**
 * Resolves who is acting (decline/withdraw), one of two ways: a signed
 * assertion over `{action, pending_operation_id}` (works for anyone who can
 * produce a signature, local or external), or an email-delivered token
 * (works for anyone with a verified email on file, local or external,
 * proven by possession rather than by key custody -- see email.ts's own
 * header comment). Either is equally valid; which one a given request uses
 * depends only on whether it arrived via a clicked email link or an
 * API/CLI call.
 */
export type ActorAuth = { signerDid: Did; sig: string } | { token: string };

async function resolveActor(env: Env, pendingOpId: string, action: "decline" | "withdraw", auth: ActorAuth, ctx: VerificationContext): Promise<Did> {
  if ("token" in auth) {
    const row = await getPendingOperationByToken(env, auth.token);
    if (!row || row.pending_op_id !== pendingOpId) throw new RegistrarError("invalid or expired link", 400);
    return row.signer_did as Did;
  }
  const payload = { action, pending_operation_id: pendingOpId };
  if (!(await verifyDidSignature(auth.signerDid, payload, auth.sig, ctx))) {
    throw new RegistrarError("invalid signature", 400);
  }
  return auth.signerDid;
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
  const wardName = ward.name === "" ? "_" : ward.name;
  const ctx = await buildContextForWard(env, ward.did as Did);

  const shape = await rule.checkShape(op as any, ctx);
  if (!shape.valid) throw new RegistrarError(shape.reason ?? "invalid operation shape", 400);

  const sigs = (op as { sigs?: Record<Did, string> }).sigs ?? {};
  if (Object.keys(sigs).length === 0) throw new RegistrarError("a proposal must already carry at least the proposer's own signature", 400);
  let proposerDid: Did | null = null;
  for (const did of Object.keys(sigs)) {
    if (await verifySignerSig(op, did, sigs[did], ctx.resolveKey)) proposerDid = did as Did;
  }
  if (!proposerDid) throw new RegistrarError("none of the attached signatures are valid", 400);

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
    const final = await finalize(env, name, id, op, actor.getSnapshot().context.collectedSigs, requiredSigners);
    return { id, state: final.state, document: final.document };
  }

  await notifyVoteRecorded(env, wardName, proposerDid, id, op.type);
  for (const signerDid of requiredSigners) {
    if (signerDid !== proposerDid) await notifyAwaitingSignature(env, wardName, signerDid, id, op.type);
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
  if (row.state !== "collecting" && row.state !== "satisfied") {
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
  const wardName = await nameForWardDid(env, row.ward_did as Did);
  const requiredSigners = JSON.parse(row.required_signers) as Did[];

  if (row.state === "satisfied") {
    // Already met -- nothing a new signature could add. Most likely a retry after a prior FINALIZE_FAILED; just re-attempt rather than silently dropping this signer's contribution (the machine itself has no CONTRIBUTE handler in `satisfied`, so sending one would be a no-op).
    const collectedSigs = JSON.parse(row.collected_sigs) as Record<Did, string>;
    const final = await finalize(env, wardName, id, op, collectedSigs, requiredSigners);
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
    const final = await finalize(env, wardName, id, op, newCollectedSigs, requiredSigners);
    return { state: final.state, document: final.document };
  }

  await notifyVoteRecorded(env, wardName!, signerDid, id, op.type);
  for (const other of requiredSigners) {
    if (other !== signerDid && !(other in newCollectedSigs)) await notifyProgress(env, wardName!, other, id, op.type, signerDid);
  }
  return { state: newState };
}

/** Veto -- any current, live guardian of the ward can kill a proposal outright, whether or not they'd already signed. Allowed while `collecting` or `satisfied` (not yet actually finalized); rejected once finalized/declined/expired -- nothing undoes those. */
export async function declineOperation(env: Env, id: string, auth: ActorAuth): Promise<{ state: string }> {
  const row = await getPendingOperation(env, id);
  if (!row) throw new RegistrarError(`no pending operation "${id}"`, 404);
  if (row.state !== "collecting" && row.state !== "satisfied") {
    throw new RegistrarError(`pending operation "${id}" is ${row.state} -- it can no longer be declined`, 409);
  }

  const ctx = await buildContextForWard(env, row.ward_did as Did);
  const actorDid = await resolveActor(env, id, "decline", auth, ctx);
  const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
  if (!live.includes(actorDid)) {
    throw new RegistrarError(`${actorDid} is not a current guardian of this ward -- only a current guardian may veto a proposal`, 403);
  }

  const collectedSigs = JSON.parse(row.collected_sigs) as Record<Did, string>;
  const resolved = pendingOperationMachine.resolveState({ value: row.state, context: { collectedSigs, satisfiedAtPropose: false } });
  const actor = createActor(pendingOperationMachine, { snapshot: resolved, input: { collectedSigs, satisfiedAtPropose: false } }).start();
  actor.send({ type: "DECLINE" });
  await updatePendingOperationState(env, id, actor.getSnapshot().value as string, row.collected_sigs);

  const wardName = await nameForWardDid(env, row.ward_did as Did);
  const requiredSigners = JSON.parse(row.required_signers) as Did[];
  const op = JSON.parse(row.partial_op) as Operation;
  for (const other of requiredSigners) {
    if (other !== actorDid) await notifyDeclined(env, wardName!, other, id, op.type, actorDid);
  }
  return { state: actor.getSnapshot().value as string };
}

/** Opt-out -- "don't wait on me." Never blocks anyone else; only valid while still `collecting`. Removes the withdrawing party's own signature from consideration if they'd already contributed one. */
export async function withdrawFromOperation(env: Env, id: string, auth: ActorAuth): Promise<{ state: string }> {
  const row = await getPendingOperation(env, id);
  if (!row) throw new RegistrarError(`no pending operation "${id}"`, 404);
  if (row.state !== "collecting") {
    throw new RegistrarError(`pending operation "${id}" is ${row.state}, not collecting -- withdrawal no longer has anything to affect`, 409);
  }

  const ctx = await buildContextForWard(env, row.ward_did as Did);
  const actorDid = await resolveActor(env, id, "withdraw", auth, ctx);

  const collectedSigs = JSON.parse(row.collected_sigs) as Record<Did, string>;
  const resolved = pendingOperationMachine.resolveState({ value: row.state, context: { collectedSigs, satisfiedAtPropose: false } });
  const actor = createActor(pendingOperationMachine, { snapshot: resolved, input: { collectedSigs, satisfiedAtPropose: false } }).start();
  actor.send({ type: "WITHDRAW", did: actorDid });
  const newState = actor.getSnapshot().value as string;
  await updatePendingOperationState(env, id, newState, JSON.stringify(actor.getSnapshot().context.collectedSigs));

  const wardName = await nameForWardDid(env, row.ward_did as Did);
  const requiredSigners = JSON.parse(row.required_signers) as Did[];
  const op = JSON.parse(row.partial_op) as Operation;
  for (const other of requiredSigners) {
    if (other !== actorDid) await notifyWithdrawn(env, wardName!, other, id, op.type, actorDid);
  }
  return { state: newState };
}

export interface PendingOperationStatus {
  id: string;
  op_type: string;
  state: string;
  required_signers: Did[];
  signed: Did[];
  created_at: string;
  expires_at: string;
}

/** GET .../pending/<id> (registrar API spec §3) -- ward-scoped: `wardDid` must match the proposal's own, same defensive check every other ward-path endpoint makes. */
export async function getPendingOperationStatus(env: Env, wardDid: Did, id: string): Promise<PendingOperationStatus> {
  const row = await getPendingOperation(env, id);
  if (!row || row.ward_did !== wardDid) throw new RegistrarError(`no pending operation "${id}" for this ward`, 404);
  return {
    id: row.id,
    op_type: row.op_type,
    state: row.state,
    required_signers: JSON.parse(row.required_signers) as Did[],
    signed: Object.keys(JSON.parse(row.collected_sigs) as Record<Did, string>),
    created_at: row.created_at,
    expires_at: row.expires_at,
  };
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

async function finalize(
  env: Env,
  name: string | null,
  id: string,
  op: Operation,
  collectedSigs: Record<Did, string>,
  requiredSigners: Did[],
): Promise<{ state: string; document?: unknown }> {
  const fullOp = { ...op, sigs: collectedSigs } as Operation;
  const result = await submitOperation(env, name, fullOp);
  if (result.accepted) {
    await updatePendingOperationState(env, id, "finalized", JSON.stringify(collectedSigs));
    const document = await resolveDocument(env, name);
    const wardName = name ?? "_";
    for (const signerDid of requiredSigners) {
      await notifyFinalized(env, wardName, signerDid, id, op.type);
    }
    return { state: "finalized", document };
  }
  // Retriable -- the signatures collected are still valid; only the append attempt failed (e.g. the log head moved).
  await updatePendingOperationState(env, id, "satisfied", JSON.stringify(collectedSigs));
  throw new RegistrarError(`collected enough signatures, but finalizing failed: ${result.reason}`, 409);
}

/**
 * Daily reminder cron (index.ts's own `scheduled` handler). For every
 * still-`collecting` proposal, reminds whichever required signers haven't
 * yet contributed and haven't been reminded in the last 24h -- gated per
 * signer via pending_operation_tokens' own last_notified_at, not per
 * proposal, since different signers can be at different points (one just
 * got a "you voted" confirmation moments ago, another has been waiting
 * since propose time days back).
 */
export async function sendDailyReminders(env: Env): Promise<void> {
  const proposals = await listPendingOperationsCollecting(env);
  const cutoff = new Date(Date.now() - REMINDER_INTERVAL_MS).toISOString();
  for (const row of proposals) {
    const requiredSigners = JSON.parse(row.required_signers) as Did[];
    const collected = new Set(Object.keys(JSON.parse(row.collected_sigs) as Record<Did, string>));
    const stillNeeded = requiredSigners.filter((d) => !collected.has(d));
    if (stillNeeded.length === 0) continue;

    let wardName: string | null;
    try {
      wardName = await nameForWardDid(env, row.ward_did as Did);
    } catch {
      continue; // the ward row is gone somehow -- nothing sensible to remind anyone about
    }
    const wardNameForUrl = wardName ?? "_";

    for (const signerDid of stillNeeded) {
      const tokenRow = await getPendingOperationToken(env, row.id, signerDid);
      if (tokenRow && tokenRow.last_notified_at >= cutoff) continue; // reminded recently enough
      await notifyReminder(env, wardNameForUrl, signerDid, row.id, row.op_type, row.expires_at);
    }
  }
}
