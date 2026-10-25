import { guardianAddRule, guardianRemoveRule, policyUpdateRule, rotateRule, withinRecoveryWindow } from "./rules.js";
import type { VerificationContext } from "./rules.js";
import { DEFAULT_GUARDIAN_POLICY } from "./types.js";
import type { Did, GuardianPolicy, LogEntry, ResolvedState } from "./types.js";

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
 * REQ-6-8/6-9: whether `op` (an already shape/signature-valid, guardian-
 * signed `custodial_rotate` naming a `prev` earlier than the current head)
 * is still eligible to nullify the branch that followed it. Call this only
 * once ordinary prev-matches-head validation has already failed -- it is
 * the one exception to REQ-6-2, not a replacement for it.
 */
export async function checkNullification(
  log: LogEntry[],
  op: { type: string; prev: string | null; sig?: string; sigs?: Record<Did, string> },
  ctx: VerificationContext,
  now: Date = new Date(),
): Promise<NullificationCheck> {
  if (op.type !== "custodial_rotate") return { ok: false, reason: "only custodial_rotate may nullify (REQ-6-8)" };
  if (!op.sigs || op.sig) return { ok: false, reason: "nullification requires a guardian-signed rotation, not the ward's own key (REQ-6-8)" };
  const satisfiesGuardianPath = await rotateRule.isSatisfied(op as any, [], ctx);
  if (!satisfiesGuardianPath) return { ok: false, reason: "recovery_threshold not met" };

  const chain = reconstructChain(log);
  const targetIdx = chain.findIndex((e) => e.cid === op.prev);
  if (targetIdx === -1) return { ok: false, reason: `prev ${op.prev} does not name any operation in the current chain` };
  const nullifiedEntry = chain[targetIdx + 1];
  if (!nullifiedEntry) return { ok: false, reason: "prev already names the current head -- not a nullification" };
  if (!nullifiedEntry.acceptedAt) return { ok: false, reason: "the operation this would nullify has no recorded acceptance time" };
  if (!withinRecoveryWindow(new Date(nullifiedEntry.acceptedAt), now)) {
    return { ok: false, reason: "the operation this would nullify was accepted more than 72 hours ago (REQ-6-9)" };
  }
  return { ok: true, nullifiedEntry };
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
    verificationMethods: { ...genesis.verificationMethods },
    services: { ...genesis.services },
    guardians: [...genesis.incoming], // v0.1 compat -- REQ-7.1-1's always-empty enforcement lands with the genesis split (task #109)
    guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, ...(genesis.policy ?? {}) } as GuardianPolicy,
    registrar: genesis.registrar,
    deactivated: false,
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

/** The W3C DID Core document derived from resolved state -- guardians/policy/registrar stay method-internal (spec §3). */
export function toDidDocument(state: ResolvedState) {
  const vmIds = Object.keys(state.verificationMethods).map((id) => `${state.did}#${id}`);
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: state.did,
    verificationMethod: Object.entries(state.verificationMethods).map(([id, key]) => ({
      id: `${state.did}#${id}`,
      type: "Multikey",
      controller: state.did,
      publicKeyMultibase: key,
    })),
    authentication: vmIds,
    assertionMethod: vmIds,
    service: Object.entries(state.services).map(([id, svc]) => ({
      id: `${state.did}#${id}`,
      type: svc.type,
      serviceEndpoint: svc.endpoint,
    })),
    alsoKnownAs: [],
  };
}
