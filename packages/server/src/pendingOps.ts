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
  parseDid,
  wellKnownPath,
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
  upsertRelayInboxEntry,
} from "./db.js";
import type { PendingOperationRow } from "./db.js";
import {
  notifyAwaitingSignature,
  notifyVoteRecorded,
  notifyProgress,
  notifyDeclined,
  notifyWithdrawn,
  notifyFinalized,
  notifyReminder,
  notifyRelaySignatureRequested,
} from "./email.js";
import { randomSecret } from "./secretBox.js";

const REMINDER_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

const PROPOSAL_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days -- a reasonable fixed window, not itself a protocol requirement

function isRuleGoverned(type: string): type is RuleGovernedOpType {
  return type in OPERATION_RULES;
}

/**
 * Best-effort companion to `notifyAwaitingSignature`/`notifyProgress` for a
 * required signer this registrar doesn't custody: that signer's own
 * registrar has no way to know this pending operation exists at all, so its
 * own `notifyAwaitingSignature` (which looks up email forwarding in *its*
 * own D1) silently finds nothing and never fires -- a foreign guardian got
 * zero notification before this, not just no way to sign.
 *
 * This push is purely advisory, never trusted: the receiving registrar
 * (relay-notify's own handler) always re-fetches this op's real status from
 * here before acting on it. A failure here (unreachable peer, peer doesn't
 * implement the endpoint) is silently swallowed -- the ward can still share
 * the pending-op link by hand, the same fallback that's always existed for
 * a self-held-key external guardian.
 */
async function pushRelayNotify(env: Env, wardDid: Did, signerDid: Did, pendingOpId: string): Promise<void> {
  const local = await getWardByDid(env, signerDid);
  if (local) return; // handled by the ordinary local email path instead
  let domain: string;
  try {
    ({ domain } = parseDid(signerDid));
  } catch {
    return;
  }
  try {
    await fetch(`https://${domain}/.well-known/guardian/relay-notify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ward_did: wardDid, pending_operation_id: pendingOpId, signer_did: signerDid }),
    });
  } catch {
    // best-effort -- see doc comment above
  }
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
  const sigTimestamps: Record<Did, string> = {};
  for (const did of Object.keys(sigs)) sigTimestamps[did as Did] = now.toISOString();
  const row: PendingOperationRow = {
    id,
    ward_did: ward.did,
    op_type: op.type,
    partial_op: JSON.stringify(op),
    required_signers: JSON.stringify(requiredSigners),
    collected_sigs: JSON.stringify(actor.getSnapshot().context.collectedSigs),
    sig_timestamps: JSON.stringify(sigTimestamps),
    state: actor.getSnapshot().value as string,
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + PROPOSAL_TTL_MS).toISOString(),
  };
  await insertPendingOperation(env, row);

  if (actor.getSnapshot().value === "satisfied") {
    const final = await finalize(env, name, id, op, actor.getSnapshot().context.collectedSigs, requiredSigners, sigTimestamps);
    return { id, state: final.state, document: final.document };
  }

  await notifyVoteRecorded(env, wardName, proposerDid, id, op.type);
  for (const signerDid of requiredSigners) {
    if (signerDid !== proposerDid) {
      await notifyAwaitingSignature(env, wardName, signerDid, id, op.type);
      await pushRelayNotify(env, ward.did as Did, signerDid, id);
    }
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
    await updatePendingOperationState(env, id, "expired", row.collected_sigs, row.sig_timestamps);
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
    const sigTimestamps = JSON.parse(row.sig_timestamps) as Record<Did, string>;
    const final = await finalize(env, wardName, id, op, collectedSigs, requiredSigners, sigTimestamps);
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
  const sigTimestamps = { ...(JSON.parse(row.sig_timestamps) as Record<Did, string>) };
  if (signerDid in newCollectedSigs) sigTimestamps[signerDid] = new Date().toISOString();
  await updatePendingOperationState(env, id, newState, JSON.stringify(newCollectedSigs), JSON.stringify(sigTimestamps));

  if (newState === "satisfied") {
    const final = await finalize(env, wardName, id, op, newCollectedSigs, requiredSigners, sigTimestamps);
    return { state: final.state, document: final.document };
  }

  await notifyVoteRecorded(env, wardName!, signerDid, id, op.type);
  for (const other of requiredSigners) {
    if (other !== signerDid && !(other in newCollectedSigs)) {
      await notifyProgress(env, wardName!, other, id, op.type, signerDid);
      await pushRelayNotify(env, row.ward_did as Did, other, id);
    }
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
  const op = JSON.parse(row.partial_op) as Operation;
  // Veto power is normally reserved for a current, live guardian -- but
  // guardian_add's own `incoming` party is, by construction (rules.ts'
  // guardianAddRule), never live yet and always a required signer whose
  // own consent the operation can never be satisfied without (true at
  // genesis and when adding to an already-populated set alike). Declining
  // your own nomination is a refusal, not an exercise of governance power
  // over someone else's proposal -- allow it as the same single verb
  // rather than needing a different one (withdraw) for a case that's
  // already functionally equivalent to a veto for this specific op type.
  const isOwnNomination = op.type === "guardian_add" && op.incoming === actorDid;
  if (!isOwnNomination) {
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    if (!live.includes(actorDid)) {
      throw new RegistrarError(`${actorDid} is not a current guardian of this ward -- only a current guardian may veto a proposal`, 403);
    }
  }

  const collectedSigs = JSON.parse(row.collected_sigs) as Record<Did, string>;
  const resolved = pendingOperationMachine.resolveState({ value: row.state, context: { collectedSigs, satisfiedAtPropose: false } });
  const actor = createActor(pendingOperationMachine, { snapshot: resolved, input: { collectedSigs, satisfiedAtPropose: false } }).start();
  actor.send({ type: "DECLINE" });
  await updatePendingOperationState(env, id, actor.getSnapshot().value as string, row.collected_sigs, row.sig_timestamps);

  const wardName = await nameForWardDid(env, row.ward_did as Did);
  const requiredSigners = JSON.parse(row.required_signers) as Did[];
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
  const sigTimestamps = { ...(JSON.parse(row.sig_timestamps) as Record<Did, string>) };
  delete sigTimestamps[actorDid];
  await updatePendingOperationState(env, id, newState, JSON.stringify(actor.getSnapshot().context.collectedSigs), JSON.stringify(sigTimestamps));

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
  /**
   * The op minus `sig`/`sigs` -- exactly the bytes `signPayload` would sign,
   * same shape `votingPage.ts`'s own `signAsSelf` already destructures out
   * of a pending op inline. Present so a *different* registrar (relaying a
   * signature for a foreign guardian it custodies -- see relaySign.ts) can
   * reproduce the same canonicalized payload independently, rather than
   * trusting anything handed to it out of band.
   */
  unsigned_payload: unknown;
}

/** GET .../pending/<id> (registrar API spec §3) -- ward-scoped: `wardDid` must match the proposal's own, same defensive check every other ward-path endpoint makes. */
export async function getPendingOperationStatus(env: Env, wardDid: Did, id: string): Promise<PendingOperationStatus> {
  const row = await getPendingOperation(env, id);
  if (!row || row.ward_did !== wardDid) throw new RegistrarError(`no pending operation "${id}" for this ward`, 404);
  const op = JSON.parse(row.partial_op) as { sig?: unknown; sigs?: unknown };
  const { sig: _sig, sigs: _sigs, ...unsignedPayload } = op;
  return {
    id: row.id,
    op_type: row.op_type,
    state: row.state,
    required_signers: JSON.parse(row.required_signers) as Did[],
    signed: Object.keys(JSON.parse(row.collected_sigs) as Record<Did, string>),
    created_at: row.created_at,
    expires_at: row.expires_at,
    unsigned_payload: unsignedPayload,
  };
}

export async function listPendingForSigner(env: Env, signerDid: Did): Promise<PendingOperationRow[]> {
  const rows = await listPendingOperationsForSigner(env, signerDid);
  const active: PendingOperationRow[] = [];
  for (const row of rows) {
    if (new Date(row.expires_at).getTime() < Date.now()) {
      await updatePendingOperationState(env, row.id, "expired", row.collected_sigs, row.sig_timestamps);
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
  sigTimestamps: Record<Did, string>,
): Promise<{ state: string; document?: unknown }> {
  const fullOp = { ...op, sigs: collectedSigs } as Operation;
  const result = await submitOperation(env, name, fullOp, sigTimestamps);
  if (result.accepted) {
    await updatePendingOperationState(env, id, "finalized", JSON.stringify(collectedSigs), JSON.stringify(sigTimestamps));
    const document = await resolveDocument(env, name);
    const wardName = name ?? "_";
    for (const signerDid of requiredSigners) {
      await notifyFinalized(env, wardName, signerDid, id, op.type);
    }
    return { state: "finalized", document };
  }
  // Retriable -- the signatures collected are still valid; only the append attempt failed (e.g. the log head moved).
  await updatePendingOperationState(env, id, "satisfied", JSON.stringify(collectedSigs), JSON.stringify(sigTimestamps));
  throw new RegistrarError(`collected enough signatures, but finalizing failed: ${result.reason}`, 409);
}

/**
 * POST /.well-known/guardian/relay-notify (index.ts) -- the receiving side
 * of `pushRelayNotify` above, on whichever registrar actually custodies the
 * named signer. Never trusts the push's own content: `ward_did` and
 * `pending_operation_id` are only ever used to independently re-fetch the
 * real status from the ward's own registrar (the same no-auth, read-only
 * endpoint `getPendingOperationStatus` already serves), and nothing is
 * acted on unless that live fetch confirms the operation is real, still
 * collectible, and this signer genuinely required. A caller supplying a
 * `signer_did` this registrar doesn't custody, or a bogus/stale pointer, is
 * silently ignored either way -- worst case is a skipped notification, the
 * same as the push never arriving at all.
 */
export async function handleRelayNotify(env: Env, body: { ward_did?: string; pending_operation_id?: string; signer_did?: string }): Promise<void> {
  const { ward_did: wardDid, pending_operation_id: pendingOpId, signer_did: signerDid } = body;
  if (!wardDid || !pendingOpId || !signerDid) return;

  const local = await getWardByDid(env, signerDid);
  if (!local) return; // not one of ours -- nothing to do

  let name: string | null, domain: string;
  try {
    ({ name, domain } = parseDid(wardDid as Did));
  } catch {
    return;
  }
  let status: PendingOperationStatus;
  try {
    const resp = await fetch(`https://${domain}${wellKnownPath(name)}/pending/${pendingOpId}`, { headers: { accept: "application/json" } });
    if (!resp.ok) return;
    status = (await resp.json()) as PendingOperationStatus;
  } catch {
    return;
  }

  if (status.state !== "collecting" && status.state !== "satisfied") return;
  if (!status.required_signers.includes(signerDid as Did)) return;
  if (status.signed.includes(signerDid as Did)) return; // already signed -- nothing to notify

  // Durable record first (migration 0010) -- this is now the signer's own
  // discoverable "needs your signature elsewhere" inbox entry (account
  // dashboard), independent of whether the email below ever lands.
  await upsertRelayInboxEntry(env, {
    signer_did: signerDid,
    pending_operation_id: pendingOpId,
    ward_did: wardDid,
    op_type: status.op_type,
    created_at: new Date().toISOString(),
  });
  await notifyRelaySignatureRequested(env, signerDid, wardDid, pendingOpId, status.op_type);
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
