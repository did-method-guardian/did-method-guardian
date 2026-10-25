// Declarative description of every v0.2 operation's own acceptance rule --
// required shape, signer formula, which GuardianPolicy field (if any)
// governs it, and its replay() state-transition effect. One source,
// checkable line-by-line against the formal spec
// (website/content/docs/did-guardian-spec-v0.2.0/), imported by both this
// package's own tests (rules.test.ts) and, eventually, by operations.ts
// once task #107 wires real sign/verify functions through it.
//
// Deliberately NOT wired into operations.ts/document.ts yet -- this file
// and its tests stand alone so the existing (v0.1, guardian_transfer-based)
// implementation and its own test suite keep passing unmodified. Task #107
// is where this table actually replaces today's per-operation functions.

import { verifySignerSig } from "./operations.js";
import type { KeyResolver } from "./operations.js";
import { meetsThreshold } from "./quorum.js";
import type {
  CustodialRotateOp,
  CustodialTombstoneOp,
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

async function validSignersOf(op: { sigs?: Record<Did, string> }, ctx: VerificationContext): Promise<Did[]> {
  const sigs = op.sigs ?? {};
  const valid: Did[] = [];
  for (const did of Object.keys(sigs)) {
    const ts = ctx.sigTimestamps?.[did];
    if (await verifySignerSig(op as any, did, sigs[did], ctx.resolveKey, ts ? new Date(ts) : undefined)) valid.push(did);
  }
  return valid;
}

export interface ShapeResult {
  valid: boolean;
  reason?: string;
}

/** REQ-7.1-1/7.1-2/7.1-3/7.1-4/7.1-7: genesis's own structural requirements -- no signer formula, since `incoming` MUST be `[]` (nothing to sign). */
export function checkGenesisShape(op: {
  incoming: Did[];
  prev: unknown;
  operationalKeys: unknown[];
  verificationMethods: Record<string, unknown>;
  services: Record<string, unknown>;
  creator?: Did;
}): ShapeResult {
  if (op.incoming.length !== 0) return { valid: false, reason: "REQ-7.1-1: incoming must be [] -- establish a guardian via guardian_add instead" };
  if (op.prev !== null) return { valid: false, reason: "REQ-7.1-2: genesis prev must be null" };
  if (!op.operationalKeys || !op.verificationMethods || !op.services) {
    return { valid: false, reason: "REQ-7.1-3: operationalKeys/verificationMethods/services must be present" };
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
  reqIds: ["REQ-7.2-1", "REQ-7.2-2", "REQ-5-2"],
  governingPolicyField: "recovery_threshold",
  checkShape: () => ({ valid: true }), // REQ-7.2-2 holds by construction -- the type carries no guardian/policy fields
  async isSatisfied(op, _validSigners, ctx) {
    if (op.sig) {
      const wardTs = ctx.sigTimestamps?.[ctx.wardDid];
      const wardSigned = await verifySignerSig(op as any, ctx.wardDid, op.sig, ctx.resolveKey, wardTs ? new Date(wardTs) : undefined);
      if (wardSigned) return true; // REQ-7.2-1(a)
    }
    if (op.sigs) {
      const validGuardianSigs = await validSignersOf(op, ctx);
      const live = await liveGuardians(ctx.state, ctx.isGuardianLive);
      if (meetsThreshold(ctx.state.guardianPolicy.recovery_threshold, validGuardianSigs, live)) return true; // REQ-7.2-1(b)
    }
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
    verificationMethods: { ...op.verificationMethods },
    services: { ...op.services },
  }),
};

export const guardianAddRule: OperationRule<GuardianAddOp> = {
  reqIds: ["REQ-7.2-3", "REQ-7.2-4", "REQ-7.2-5", "REQ-5-5", "REQ-4-4"],
  governingPolicyField: "addition_threshold",
  checkShape(op, ctx) {
    // Checked against the LIVE set -- REQ-4-4's "every purpose this document defines" covers this check too.
    return { valid: true }; // live-membership check needs ctx, done in isSatisfied's own live computation below to avoid double resolution
  },
  async isSatisfied(op, _validSigners, ctx) {
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
  const rule = (OPERATION_RULES as Record<string, OperationRule<any>>)[op.type];
  if (!rule) return { valid: false, reason: `operation type "${op.type}" has no rules-table entry` };
  const shape = await rule.checkShape(op, ctx);
  if (!shape.valid) return shape;
  const satisfied = await rule.isSatisfied(op, [], ctx);
  if (!satisfied) return { valid: false, reason: `signer requirement not met for ${op.type}` };
  return { valid: true };
}
