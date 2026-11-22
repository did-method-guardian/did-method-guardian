import { guardianAddRule, guardianRemoveRule, policyUpdateRule, rotateRule, verifyByRules, withinRecoveryWindow } from "./rules.js";
import type { VerificationContext } from "./rules.js";
import { receiptCreatedAt, verificationMethodDid } from "./operations.js";
import { parseDid } from "./resolve.js";
import { DEFAULT_GUARDIAN_POLICY } from "./types.js";
import type { CustodialCreateOp, DataIntegrityProof, Did, GuardianPolicy, LogEntry, ResolvedState } from "./types.js";

/**
 * Reconstructs the actual chain order from a log in storage/acceptance
 * order (REQ-6-6/6-10). Ordinarily storage order already equals chain
 * order -- each entry's `prev` names the immediately preceding entry's own
 * cid. A nullifying `custodial_rotate` (REQ-6-8) is the one case where a
 * later-accepted entry's `prev` instead names an EARLIER cid still present
 * in the current chain; when that happens, every entry between the named
 * `prev` and the then-current head is excluded from the chain going
 * forward (REQ-6-10), and the nullifying entry becomes the new head. A
 * later entry can itself nullify a nullification (REQ-6-11) -- the same
 * per-entry check, applied uniformly, handles that without special-casing.
 */
export function reconstructChain(log: LogEntry[]): LogEntry[] {
  if (log.length === 0) return [];
  let chain: LogEntry[] = [log[0]];
  for (let i = 1; i < log.length; i++) {
    const entry = log[i];
    const headCid = chain[chain.length - 1].cid;
    const prev = (entry.op as { prev: string | null }).prev;
    if (prev === headCid) {
      chain.push(entry);
      continue;
    }
    const targetIdx = chain.findIndex((e) => e.cid === prev);
    if (targetIdx === -1) {
      throw new Error(`operation ${entry.cid} names prev ${prev}, which is not in the current chain`);
    }
    chain = [...chain.slice(0, targetIdx + 1), entry];
  }
  return chain;
}

export interface NullificationCheck {
  ok: boolean;
  reason?: string;
  /** The entry that would be superseded if this nullification is accepted. */
  nullifiedEntry?: LogEntry;
}

/**
 * WS-4.2(d) (audit): whether `entry` is itself the product of an earlier
 * nullification -- found by comparing its own `prev` against the cid of
 * whichever entry immediately precedes it in storage/acceptance order
 * (not chain order). An ordinary append always names the immediately
 * preceding entry; only a nullification ever names an earlier one. A
 * nullifying operation can't itself be nullified (one level only) -- this
 * is the tie-break that stops two "any"-threshold guardians from
 * nullifying each other forever.
 */
function isNullifyingEntry(log: LogEntry[], entry: LogEntry): boolean {
  const idx = log.findIndex((e) => e.cid === entry.cid);
  if (idx <= 0) return false;
  const prev = (entry.op as { prev: string | null }).prev;
  return prev !== log[idx - 1].cid;
}

/**
 * REQ-6-8/6-9: whether `op` (an already shape/signature-valid, guardian-
 * signed `custodial_rotate` naming a `prev` earlier than the current head)
 * is still eligible to nullify the branch that followed it. Call this only
 * once ordinary prev-matches-head validation has already failed -- it is
 * the one exception to REQ-6-2, not a replacement for it.
 *
 * Audit WS-1.4/4.2(a): authorized against the state AT `prev`, not the
 * current head -- a guardian set or policy that changed between `prev`
 * and now never retroactively authorizes (or blocks) a nullification that
 * reaches back before those changes. `verifyByRules` runs the FULL rule
 * (PoP, the policy-version gate, and the signer requirement) rather than
 * just `isSatisfied` alone, closing the bypass where a nullifying rotation
 * could install a key with no proof of possession.
 */
export async function checkNullification(
  log: LogEntry[],
  op: { type: string; prev: string | null; proof?: DataIntegrityProof[] },
  ctx: VerificationContext,
  now: Date = new Date(),
): Promise<NullificationCheck> {
  if (op.type !== "custodial_rotate") return { ok: false, reason: "only custodial_rotate may nullify (REQ-6-8)" };
  const hasWardProof = (op.proof ?? []).some((p) => verificationMethodDid(p.verificationMethod) === ctx.wardDid);
  if (hasWardProof) return { ok: false, reason: "nullification requires a guardian-signed rotation, not the ward's own key (REQ-6-8)" };

  const chain = reconstructChain(log);
  const targetIdx = chain.findIndex((e) => e.cid === op.prev);
  if (targetIdx === -1) return { ok: false, reason: `prev ${op.prev} does not name any operation in the current chain` };
  const nullifiedEntry = chain[targetIdx + 1];
  if (!nullifiedEntry) return { ok: false, reason: "prev already names the current head -- not a nullification" };

  // WS-4.2(d): one level only -- a nullification can't itself be nullified.
  if (isNullifyingEntry(log, nullifiedEntry)) {
    return { ok: false, reason: "the operation this would nullify is itself a nullification -- a nullifying operation can't itself be nullified (REQ-6-11 is one level only)" };
  }

  const stateAtPrev = replay(ctx.wardDid, chain.slice(0, targetIdx + 1));
  const ctxAtPrev: VerificationContext = { ...ctx, state: stateAtPrev };
  const satisfiesGuardianPath = await verifyByRules(op, ctxAtPrev);
  if (!satisfiesGuardianPath.valid) return { ok: false, reason: satisfiesGuardianPath.reason ?? "recovery_threshold not met" };

  // WS-4.1: the nullification window (REQ-6-9) is evaluated against the
  // nullified entry's own registrar-signed RECEIPT, never the unsigned
  // storage-layer `acceptedAt` it supersedes and never a signer's own
  // self-reported `created` (a rotated-away guardian key could backdate
  // one to whenever it was still valid).
  const registrarDid = stateAtPrev.registrarDid;
  const receiptAt = registrarDid ? receiptCreatedAt(nullifiedEntry.op as any, registrarDid) : undefined;
  if (!receiptAt) return { ok: false, reason: "the operation this would nullify has no registrar receipt to check its acceptance time against (REQ-6-9)" };
  if (!withinRecoveryWindow(new Date(receiptAt), now)) {
    return { ok: false, reason: "the operation this would nullify was accepted more than 72 hours ago (REQ-6-9)" };
  }
  return { ok: true, nullifiedEntry };
}

/**
 * WS-1.7/4.4 (audit): the registrar DID for `genesis` -- derived
 * STRUCTURALLY from `genesis.did`'s own domain (`did:guardian:<domain>`),
 * never scanned for out of the proof set by "whichever proof isn't a PoP
 * or an incoming guardian's." That scan previously let a stray, unrelated
 * extra proof (e.g. an attacker-injected `did:guardian:evil.example#key-0`)
 * be picked up as the registrar's own attestation and poison L1 anchor/
 * registrar-key pinning -- verifyCustodialCreate (WS-1.7's own other
 * half) now separately rejects any genesis carrying such an unexplained
 * proof at submission time, but replay() computing this the same
 * structural way regardless means it's correct even for a log this
 * particular check hasn't (yet) been run against. Fails soft (undefined)
 * on a `did` that doesn't parse under REQ-2-2's current grammar -- a v0.1
 * log entry (guardian_transfer-era, kept replayable for already-accepted
 * history, see this file's own header comment) never had `did` checked
 * against this grammar in the first place, and the registrar DID is only
 * ever used for L1 pinning, not for anything replay() itself needs to
 * compute correctly.
 */
function extractRegistrarDid(genesis: CustodialCreateOp): Did | undefined {
  try {
    const { domain } = parseDid(genesis.did);
    return `did:guardian:${domain}` as Did;
  } catch {
    return undefined;
  }
}

/**
 * Replays a full operation log into the current resolved state. Does not
 * itself verify signatures -- callers should validate each operation (see
 * operations.ts/rules.ts) before trusting a log, the same way the spec's
 * own resolution section (§8) separates "replay" from "full validation".
 * Nullified branches (REQ-6-10) are excluded automatically via
 * reconstructChain.
 */
export function replay(did: Did, log: LogEntry[]): ResolvedState {
  if (log.length === 0 || log[0].op.type !== "custodial_create") {
    throw new Error("log must start with a custodial_create operation");
  }
  const chain = reconstructChain(log);

  const genesis = chain[0].op;
  if (genesis.type !== "custodial_create") throw new Error("log must start with a custodial_create operation");
  const state: ResolvedState = {
    did,
    operationalKeys: [...genesis.operationalKeys],
    services: { ...genesis.services },
    guardians: [...genesis.incoming], // MAY be non-empty when each named guardian co-signed genesis (REQ-7.1-1)
    guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, ...(genesis.policy ?? {}) } as GuardianPolicy,
    registrarDid: extractRegistrarDid(genesis),
    deactivated: false,
    alsoKnownAs: [...(genesis.alsoKnownAs ?? [])],
  };

  for (const entry of chain.slice(1)) {
    const op = entry.op;
    switch (op.type) {
      case "custodial_rotate":
        Object.assign(state, rotateRule.applyToState(op, state));
        break;
      case "guardian_transfer": // v0.1, superseded -- kept only to replay already-accepted history
        state.guardians = [...op.incoming];
        break;
      case "guardian_add":
        Object.assign(state, guardianAddRule.applyToState(op, state));
        break;
      case "guardian_remove":
        Object.assign(state, guardianRemoveRule.applyToState(op, state));
        break;
      case "guardian_relinquish":
        state.guardians = [];
        break;
      case "policy_update":
        Object.assign(state, policyUpdateRule.applyToState(op, state));
        break;
      case "custodial_tombstone":
        state.deactivated = true;
        break;
      default:
        throw new Error(`unknown operation type in log: ${(op as { type: string }).type}`);
    }
  }

  return state;
}

/**
 * The W3C DID Core document derived from resolved state -- guardians/
 * policy/registrar stay method-internal (spec §3). REQ-3-1, Fix 1:
 * verificationMethod derives directly from `operationalKeys`, index by
 * index (`#key-0`, `#key-1`, ...) -- there is no separate map that
 * could ever name a key this identity hasn't itself proven possession
 * of (REQ-7.1-8/7.2-12); the presented document and the cryptographic
 * control chain are the same list, by construction, not by a check
 * that they happen to agree.
 */
export function toDidDocument(state: ResolvedState) {
  const vmIds = state.operationalKeys.map((_, i) => `${state.did}#key-${i}`);
  return {
    // WS-1.16 (audit): the base DID context alone never defines "Multikey"
    // as a verification method type -- a strict JSON-LD processor has no
    // term to resolve it against without this. https://w3id.org/security/
    // multikey/v1 is the W3C-published context for exactly this term;
    // verified directly against the Multikey specification, not assumed.
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: state.did,
    verificationMethod: state.operationalKeys.map((key, i) => ({
      id: `${state.did}#key-${i}`,
      type: "Multikey",
      controller: state.did,
      publicKeyMultibase: key,
    })),
    authentication: vmIds,
    assertionMethod: vmIds,
    capabilityInvocation: vmIds, // REQ-3-2: an operational key is exactly what invokes the capability to update this document
    service: Object.entries(state.services).map(([id, svc]) => ({
      id: `${state.did}#${id}`,
      type: svc.type,
      serviceEndpoint: svc.endpoint,
    })),
    // WS-5.8 (audit, DECIDED): previously always hardcoded to [] here,
    // regardless of what the log itself declared -- the "link, don't move"
    // domain-migration story (spec §9) names alsoKnownAs as its own
    // mechanism, but nothing ever surfaced a declared value into the
    // actual resolved document until now.
    alsoKnownAs: [...state.alsoKnownAs],
    // WS-1.16 (audit): state.deactivated was already computed by replay()
    // but never surfaced anywhere in the presented document -- a resolver
    // had no way to learn REQ-6-5's own deactivated state short of
    // independently fetching and replaying the full log itself. Reuses
    // the W3C DID Resolution spec's own didDocumentMetadata.deactivated
    // term (rather than inventing a new one), embedded directly in the
    // document instead of a separate resolution-result envelope -- this
    // method's own wire format has never wrapped the document that way,
    // and changing that now would be a breaking change to every existing
    // consumer for a problem an additive field already solves. Always
    // present, not just when true, so its absence never has to be
    // interpreted as "not deactivated" versus "this registrar doesn't
    // support surfacing it."
    didDocumentMetadata: { deactivated: state.deactivated },
  };
}
