// Declarative description of every v0.2 operation's acceptance rule --
// required shape, signer formula, which GuardianPolicy field (if any)
// governs it, and its replay() state-transition effect. One source,
// checkable line-by-line against the formal spec
// (website/content/docs/did-guardian-spec-v0.2.0/), used by this package's
// tests (rules.test.ts) and by the reference registrar's real acceptance
// path (packages/server/src/registrar.ts's submitOperation, via
// verifyByRules below) for every operation type except custodial_create --
// genesis's cryptographic checks (incoming guardian sigs, keySigs, the
// registrar attestation) live in operations.ts's verifyCustodialCreate
// instead, with checkGenesisShape (below) covering genesis's structural
// requirements only, called directly by registrar.ts's acceptGenesis
// (document.ts's replay() still needs the v0.1 guardian_transfer case for
// already-accepted history -- see its comment -- which is why that type
// isn't retired from the Operation union, only from new-submission
// acceptance).

import { unsecuredDocument, verificationMethodDid, verifyAgainstKeys, verifyPop, verifySignerProof } from "./operations.js";
import type { KeyResolver } from "./operations.js";
import { meetsThreshold } from "./quorum.js";
import { MAX_SUPPORTED_POLICY_VERSION, validatePolicy } from "./types.js";
import type {
  CustodialRotateOp,
  CustodialTombstoneOp,
  DataIntegrityProof,
  Did,
  GuardianAddOp,
  GuardianPolicy,
  GuardianRelinquishOp,
  GuardianRemoveOp,
  PolicyUpdateOp,
  ResolvedState,
} from "./types.js";

/** REQ-6-9: 72 hours, matching did:plc's own recovery window exactly. */
export const RECOVERY_WINDOW_MS = 72 * 60 * 60 * 1000;

/** REQ-6-8: whether a guardian-signed recovery rotation may still nullify the operation that followed `nulledOpAcceptedAt`. */
export function withinRecoveryWindow(nulledOpAcceptedAt: Date, now: Date): boolean {
  return now.getTime() - nulledOpAcceptedAt.getTime() < RECOVERY_WINDOW_MS;
}

/**
 * REQ-4-4: a guardian whose own identity is currently deactivated is excluded
 * from the current guardian set for every purpose this document defines.
 * `isGuardianLive` resolves that live, per-signer -- a stand-in for actually
 * replaying each guardian's own log, which is cross-DID and out of scope for
 * a single ward's own `replay()`.
 */
export type GuardianLivenessResolver = (did: Did) => boolean | Promise<boolean>;

export async function liveGuardians(state: ResolvedState, isGuardianLive: GuardianLivenessResolver): Promise<Did[]> {
  const live: Did[] = [];
  for (const g of state.guardians) {
    if (await isGuardianLive(g)) live.push(g);
  }
  return live;
}

export interface VerificationContext {
  wardDid: Did;
  /** Resolved state as of this operation's own `prev` -- never post-application. */
  state: ResolvedState;
  resolveKey: KeyResolver;
  isGuardianLive: GuardianLivenessResolver;
  /**
   * REQ-4-2: when a signer's own signature was actually collected by this
   * registrar, keyed by signer DID (ISO timestamp) -- so a signature that
   * outlives its own signer's later key rotation still verifies against the
   * key that was valid when it was produced, not whatever's current now.
   * Only meaningful for a signature collected asynchronously and verified
   * again later (registrar API spec §3); absent for any signer means
   * "assume now," correct for the ordinary case where signing and
   * verification happen in the same call.
   */
  sigTimestamps?: Record<Did, string>;
}

/** Every DID a proof in `proofs` claims to be signed by, excluding self-contained `did:key:` PoP proofs -- the candidates `validSignersOf` below checks, not yet known to actually verify. */
function candidateProofDids(proofs: DataIntegrityProof[]): Did[] {
  const dids = new Set<Did>();
  for (const p of proofs) {
    if (!p.verificationMethod.startsWith("did:key:")) dids.add(verificationMethodDid(p.verificationMethod));
  }
  return [...dids];
}

async function validSignersOf(op: { proof?: DataIntegrityProof[] }, ctx: VerificationContext): Promise<Did[]> {
  const proofs = op.proof ?? [];
  const unsecuredDoc = unsecuredDocument(op as any);
  const valid: Did[] = [];
  for (const did of candidateProofDids(proofs)) {
    // Audit WS-1.1/1.2: the ward's own proof is checked directly against
    // ctx.state.operationalKeys (the state this operation is being
    // verified against), never through ctx.resolveKey -- an external
    // resolver function is for OTHER identities (guardians), never this
    // same ward, whose current keys ctx.state already states authoritatively.
    if (did === ctx.wardDid) {
      if (await verifyAgainstKeys(unsecuredDoc, proofs, did, ctx.state.operationalKeys)) valid.push(did);
      continue;
    }
    const ts = ctx.sigTimestamps?.[did];
    if (await verifySignerProof(unsecuredDoc, proofs, did, ctx.resolveKey, ts ? new Date(ts) : undefined)) valid.push(did);
  }
  return valid;
}

export interface ShapeResult {
  valid: boolean;
  reason?: string;
}

/**
 * REQ-7.1-1/7.1-2/7.1-3/7.1-4/7.1-7: genesis's structural requirements --
 * shape only, no cryptographic verification (an incoming guardian's sig,
 * when `incoming` is non-empty, is checked for VALIDITY by
 * `verifyCustodialCreate`, same as keySigs and the registrar attestation
 * are; this only checks that a slot for it exists at all).
 *
 * `incoming` MAY be non-empty (relaxed from always-`[]` -- REQ-7.1-1,
 * v0.3): a genesis establishing a guardian directly, as long as every
 * named guardian co-signs. Doing this at genesis instead of via a
 * separate `guardian_add` halves the operations an identity that's
 * always born with a guardian needs (an ephemeral agent fleet under one
 * long-lived guardian, say), and removes the "self-held identities are
 * always born guardian-less" trap for anyone who wants a guardian from
 * the start.
 */
export function checkGenesisShape(op: {
  did: Did;
  incoming: Did[];
  proof: DataIntegrityProof[];
  prev: unknown;
  operationalKeys: unknown[];
  services: Record<string, unknown>;
  creator?: Did;
}): ShapeResult {
  if (!op.did) return { valid: false, reason: "Fix 2: did must be present" };
  for (const did of op.incoming) {
    if (!op.proof.some((p) => verificationMethodDid(p.verificationMethod) === did)) {
      return { valid: false, reason: `REQ-7.1-1: incoming guardian ${did} must co-sign genesis` };
    }
  }
  if (op.prev !== null) return { valid: false, reason: "REQ-7.1-2: genesis prev must be null" };
  if (!op.operationalKeys || !op.services) {
    return { valid: false, reason: "REQ-7.1-3: operationalKeys/services must be present" };
  }
  if (!op.creator) return { valid: false, reason: "REQ-7.1-4: creator must be present" };
  return { valid: true };
}

/** REQ-2-1: name syntax -- lowercase ALPHA/DIGIT/"-", 3-32 chars, starts/ends ALPHA/DIGIT, no "--". Availability (REQ-7.1-6) is registrar-level, not checkable here. */
export const NAME_RE = /^[a-z0-9](?:-?[a-z0-9])*$/;
export function isValidName(name: string): boolean {
  return name.length >= 3 && name.length <= 32 && NAME_RE.test(name);
}

interface OperationRule<Op> {
  reqIds: string[];
  governingPolicyField: keyof GuardianPolicy | null;
  checkShape(op: Op, ctx: VerificationContext): Promise<ShapeResult> | ShapeResult;
  /** The actual acceptance gate. Some formulas are an OR of independently-satisfiable sets (rotate, guardian_add) -- a flat "required signers" list can't express that, so this is the one source of truth, not `requiredSigners` below. */
  isSatisfied(op: Op, validSigners: Did[], ctx: VerificationContext): Promise<boolean> | boolean;
  /** Documentation/signing-helper aid only -- a sufficient signer set, not necessarily the only one `isSatisfied` would accept. */
  requiredSigners(op: Op, ctx: VerificationContext): Promise<Did[]> | Did[];
  applyToState(op: Op, state: ResolvedState): ResolvedState;
}

export const rotateRule: OperationRule<CustodialRotateOp> = {
  reqIds: ["REQ-7.2-1", "REQ-7.2-2", "REQ-5-2", "REQ-7.2-12"],
  governingPolicyField: "recovery_threshold",
  // REQ-7.2-2 holds by construction -- the type carries no guardian/policy
  // fields. REQ-7.2-12: every key being installed proves it's actually
  // held, checked here rather than in isSatisfied -- this is about the
  // operation's validity, not about who authorized installing it.
  checkShape: (op) => verifyPop(unsecuredDocument(op as any), op.operationalKeys, op.proof),
  async isSatisfied(op, _validSigners, ctx) {
    const unsecuredDoc = unsecuredDocument(op as any);
    // Audit WS-1.1/1.2: checked directly against ctx.state.operationalKeys
    // (the state at this operation's own prev), never through
    // ctx.resolveKey -- the ward's own current keys are already stated
    // authoritatively there, so a second, external resolution can only
    // ever introduce a way to disagree with it (the stale `wards.
    // public_key` DB column bug this closes, on the server side).
    const wardSigned = await verifyAgainstKeys(unsecuredDoc, op.proof, ctx.wardDid, ctx.state.operationalKeys);
    if (wardSigned) return true; // REQ-7.2-1(a)
    const validGuardianSigs = await validSignersOf(op, ctx);
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    if (meetsThreshold(ctx.state.guardianPolicy.recovery_threshold, validGuardianSigs, live)) return true; // REQ-7.2-1(b)
    return false;
  },
  // Either the ward's own key (REQ-7.2-1a) OR enough of the guardian
  // committee (REQ-7.2-1b) can satisfy this -- listing only the ward here
  // (as a previous version of this rule did) meant the real guardian
  // committee, when that's the path actually in use, was never a "required
  // signer" at all: never notified, never shown a sign option on the
  // voting page. Over-inclusive (lists everyone who COULD be part of a
  // satisfying set, not just however many the threshold strictly needs) is
  // the safe direction to err in here.
  requiredSigners: async (_op, ctx) => [ctx.wardDid, ...(await liveGuardians(ctx.state, ctx.isGuardianLive))],
  applyToState: (op, state) => ({
    ...state,
    operationalKeys: [...op.operationalKeys],
    services: { ...op.services },
  }),
};

export const guardianAddRule: OperationRule<GuardianAddOp> = {
  reqIds: ["REQ-7.2-3", "REQ-7.2-4", "REQ-7.2-5", "REQ-7.2-11", "REQ-5-5", "REQ-4-4"],
  governingPolicyField: "addition_threshold",
  checkShape(op, ctx) {
    // Checked against the LIVE set -- REQ-4-4's "every purpose this document defines" covers this check too.
    if (op.incoming === ctx.wardDid) return { valid: false, reason: "REQ-7.2-11: a ward cannot name itself as its own guardian" };
    return { valid: true }; // live-membership check needs ctx, done in isSatisfied's own live computation below to avoid double resolution
  },
  async isSatisfied(op, _validSigners, ctx) {
    if (op.incoming === ctx.wardDid) return false; // REQ-7.2-11
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    if (live.includes(op.incoming)) return false; // REQ-7.2-3
    const validSigners = await validSignersOf(op, ctx);
    if (!validSigners.includes(op.incoming)) return false;
    if (live.length === 0) return validSigners.includes(ctx.wardDid); // REQ-7.2-5
    return meetsThreshold(ctx.state.guardianPolicy.addition_threshold, validSigners, live); // REQ-7.2-4
  },
  // Zero-to-one (REQ-7.2-5) needs the ward's own key; the ordinary,
  // non-empty case (REQ-7.2-4) needs enough of the CURRENT committee
  // instead, never the ward itself -- a previous version of this rule
  // always listed [incoming, wardDid] regardless, which meant the real
  // committee was never notified and never shown a sign option on the
  // voting page for the (much more common) non-empty case.
  requiredSigners: async (op, ctx) => {
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    return live.length === 0 ? [op.incoming, ctx.wardDid] : [op.incoming, ...live];
  },
  applyToState: (op, state) => ({ ...state, guardians: [...state.guardians, op.incoming] }),
};

export const guardianRemoveRule: OperationRule<GuardianRemoveOp> = {
  reqIds: ["REQ-7.2-6", "REQ-7.2-7", "REQ-5-4", "REQ-5-7", "REQ-4-4"],
  governingPolicyField: "removal_threshold",
  checkShape: () => ({ valid: true }), // membership/min_guardian_count checks need live state -- folded into isSatisfied
  async isSatisfied(op, _validSigners, ctx) {
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    if (!live.includes(op.outgoing)) return false; // REQ-7.2-6
    if (live.length <= 1) return false; // REQ-7.2-6: can't remove the only guardian
    if (live.length - 1 < ctx.state.guardianPolicy.min_guardian_count) return false; // REQ-5-7/REQ-7.2-7's own min_guardian_count clause
    const validSigners = await validSignersOf(op, ctx);
    if (validSigners.includes(op.outgoing)) return true; // REQ-7.2-7(a) voluntary
    return meetsThreshold(ctx.state.guardianPolicy.removal_threshold, validSigners, live); // REQ-7.2-7(b), evaluated against the FULL live set, not live-minus-outgoing
  },
  // Voluntary (REQ-7.2-7a) needs only outgoing's own key; forced
  // (REQ-7.2-7b) needs enough of the OTHERS instead -- listing only
  // outgoing (as a previous version of this rule did) meant the other
  // guardians, whose approval the forced path actually needs, were never
  // notified or shown a sign option.
  requiredSigners: async (op, ctx) => [op.outgoing, ...(await liveGuardians(ctx.state, ctx.isGuardianLive))],
  applyToState: (op, state) => ({ ...state, guardians: state.guardians.filter((d) => d !== op.outgoing) }),
};

export const guardianRelinquishRule: OperationRule<GuardianRelinquishOp> = {
  reqIds: ["REQ-7.2-8", "REQ-5-4", "REQ-4-4"],
  governingPolicyField: "removal_threshold",
  checkShape: () => ({ valid: true }),
  async isSatisfied(op, _validSigners, ctx) {
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    const validSigners = await validSignersOf(op, ctx);
    return meetsThreshold(ctx.state.guardianPolicy.removal_threshold, validSigners, live);
  },
  requiredSigners: async (_op, ctx) => liveGuardians(ctx.state, ctx.isGuardianLive),
  applyToState: (_op, state) => ({ ...state, guardians: [] }),
};

export const policyUpdateRule: OperationRule<PolicyUpdateOp> = {
  reqIds: ["REQ-7.2-9", "REQ-7.2-10", "REQ-5-6"],
  governingPolicyField: "policy_threshold",
  async checkShape(op, ctx) {
    // WS-1.8: validatePolicy covers Fix 6's version-ceiling check (a
    // restrictive field a future version adds must never take effect
    // under cover of an old verifier that doesn't know to look for it)
    // plus every other field's well-formedness -- a malformed threshold,
    // a negative/non-integer version or min_guardian_count, a malformed
    // on_orphan, or an unexpected extra field, none of which the
    // previous version-only check caught.
    const policyCheck = validatePolicy(op.policy);
    if (!policyCheck.valid) return { valid: false, reason: `WS-1.8: ${policyCheck.reason}` };
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    if (live.length === 0) return { valid: false, reason: "REQ-7.2-10: policy_update rejected while the current guardian set is empty" };
    return { valid: true };
  },
  async isSatisfied(op, _validSigners, ctx) {
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    const validSigners = await validSignersOf(op, ctx);
    // REQ-5-6: evaluated against the CURRENT policy_threshold, never the proposed op.policy's own value.
    return meetsThreshold(ctx.state.guardianPolicy.policy_threshold, validSigners, live);
  },
  requiredSigners: async (_op, ctx) => liveGuardians(ctx.state, ctx.isGuardianLive),
  applyToState: (op, state) => ({ ...state, guardianPolicy: { ...op.policy } }),
};

export const tombstoneRule: OperationRule<CustodialTombstoneOp> = {
  reqIds: ["REQ-7.3-1", "REQ-5-3", "REQ-4-4"],
  governingPolicyField: "tombstone_threshold",
  checkShape: () => ({ valid: true }),
  async isSatisfied(op, _validSigners, ctx) {
    const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
    const eligible = [ctx.wardDid, ...live];
    const validSigners = await validSignersOf(op, ctx);
    return meetsThreshold(ctx.state.guardianPolicy.tombstone_threshold, validSigners, eligible);
  },
  // REQ-7.3-1's own union (ward's own key(s) OR current guardians) --
  // listing only the ward (as a previous version of this rule did) meant a
  // guardian-initiated tombstone (a real guardian wanting to end a ward it
  // guards, when tombstone_threshold is stricter than the default "any")
  // never notified or offered a sign option to the guardians whose
  // approval that path actually needs.
  requiredSigners: async (_op, ctx) => [ctx.wardDid, ...(await liveGuardians(ctx.state, ctx.isGuardianLive))],
  applyToState: (_op, state) => ({ ...state, deactivated: true }),
};

export const OPERATION_RULES = {
  custodial_rotate: rotateRule,
  guardian_add: guardianAddRule,
  guardian_remove: guardianRemoveRule,
  guardian_relinquish: guardianRelinquishRule,
  policy_update: policyUpdateRule,
  custodial_tombstone: tombstoneRule,
} as const;

export type RuleGovernedOpType = keyof typeof OPERATION_RULES;

/**
 * Generic verify entrypoint, driven entirely by OPERATION_RULES -- the one
 * place this table actually gets exercised by real verification code, not
 * just by rules.test.ts. Does not handle `custodial_create` (no rule entry;
 * see checkGenesisShape) or the v0.1 `guardian_transfer` (superseded, kept
 * in operations.ts only for replaying already-accepted history).
 */
export async function verifyByRules(op: { type: string }, ctx: VerificationContext): Promise<{ valid: boolean; reason?: string }> {
  // Fix 6: every rule below decides acceptance by reading some threshold
  // off ctx.state.guardianPolicy -- if this verifier doesn't recognize
  // the CURRENT policy's own version, it can't trust any of those reads
  // (an unrecognized, possibly-restrictive field could already be in
  // effect), so it must refuse everything outright rather than risk a
  // downgrade by evaluating only the fields it happens to understand.
  if (ctx.state.guardianPolicy.version > MAX_SUPPORTED_POLICY_VERSION) {
    return { valid: false, reason: `Fix 6: GuardianPolicy version ${ctx.state.guardianPolicy.version} is newer than this verifier understands (max ${MAX_SUPPORTED_POLICY_VERSION}) -- refusing rather than silently ignoring a field it doesn't recognize` };
  }
  const rule = (OPERATION_RULES as Record<string, OperationRule<any>>)[op.type];
  if (!rule) return { valid: false, reason: `operation type "${op.type}" has no rules-table entry` };
  const shape = await rule.checkShape(op, ctx);
  if (!shape.valid) return shape;
  const satisfied = await rule.isSatisfied(op, [], ctx);
  if (!satisfied) return { valid: false, reason: `signer requirement not met for ${op.type}` };
  return { valid: true };
}
