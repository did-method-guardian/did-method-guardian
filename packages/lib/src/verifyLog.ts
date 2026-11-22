// WS-2.1 (audit): one complete verifier for an entire operation log, from
// scratch, with no caller-supplied shortcuts. Before this, "verify a log"
// meant assembling the right calls to operations.ts/rules.ts/document.ts
// yourself -- registrar.ts's submitOperation did this correctly for
// accepting ONE new operation against an already-trusted stored log, but
// nothing did it for an arbitrary log handed to a verifier cold (the CLI,
// a relying party, the interop harness). The interop harness had grown its
// own ad hoc version that never recomputed cids, never checked prev
// linkage at all (it just walked entries in whatever order the fixture
// file happened to list them), and never ran a fork through
// checkNullification -- each a real gap this closes, not merely a
// duplicated implementation.
//
// Achieves exactly L0 (spec §12.2, REQ-12-1): "the log in hand replays,
// and every signature and threshold it claims checks out." Proves the log
// agrees with itself -- callers wanting L1 (anchor/registrar-key pinning)
// or above still do that themselves, on top of this.

import { checkGenesisShape, verifyByRules } from "./rules.js";
import type { VerificationContext, GuardianLivenessResolver } from "./rules.js";
import { cidFor, expectedRegistrarDid, verifyCustodialCreate, verifyGuardianTransfer } from "./operations.js";
import type { KeyResolver } from "./operations.js";
import { reconstructChain, checkNullification, replay } from "./document.js";
import type { CustodialCreateOp, Did, LogEntry, ResolvedState } from "./types.js";

export interface VerifyLogOpts {
  isGuardianLive?: GuardianLivenessResolver;
  sigTimestamps?: Record<Did, string>;
  /** For the 72h nullification window (REQ-6-9) -- defaults to the real current time; a caller re-verifying an older snapshot may want to pass the time it was actually captured at instead. */
  now?: Date;
}

export type VerifyLogResult = { valid: true; anchor: string; registrarDid: Did; state: ResolvedState } | { valid: false; reason: string };

/**
 * Verifies `log` is a valid operation log for `did`, from genesis through
 * its current head, recomputing and checking everything rather than
 * trusting any of it: every entry's own cid (REQ-6-4), prev linkage
 * (REQ-6-6), genesis's own shape/attestation/domain binding (REQ-7.1-*,
 * WS-4.4), every governed operation's signer/threshold/policy-version
 * requirements (rules.ts's own OPERATION_RULES, uniformly), every fork
 * through checkNullification and nowhere else (REQ-6-8/6-9/6-10/6-11),
 * and that nothing follows a tombstone (REQ-6-5).
 *
 * `resolve` is how an external (cross-registrar) guardian's key gets
 * resolved -- the caller's own concern (a live HTTP fetch for a real
 * registrar client, a fixture lookup for a test), same as every lower-
 * level verify function already takes it. `opts.isGuardianLive` defaults
 * to "assume live," the right default for a caller with no independent
 * way to check -- a real registrar-backed caller should pass its own.
 */
export async function verifyLog(did: Did, log: LogEntry[], resolve: KeyResolver, opts: VerifyLogOpts = {}): Promise<VerifyLogResult> {
  const isGuardianLive: GuardianLivenessResolver = opts.isGuardianLive ?? (() => true);
  const { sigTimestamps } = opts;
  const now = opts.now ?? new Date();

  if (log.length === 0) return { valid: false, reason: "log is empty" };
  const genesisEntry = log[0];
  const genesis = genesisEntry.op as CustodialCreateOp;
  if (genesis.type !== "custodial_create") return { valid: false, reason: "log must start with a custodial_create operation" };
  if (genesis.did !== did) return { valid: false, reason: `genesis.did "${genesis.did}" does not match the identifier being verified ("${did}")` };

  const genesisCid = await cidFor(genesis);
  if (genesisCid !== genesisEntry.cid) {
    return { valid: false, reason: `genesis cid mismatch -- stored "${genesisEntry.cid}", recomputed "${genesisCid}" (REQ-6-4)` };
  }

  if (!Array.isArray(genesis.incoming)) return { valid: false, reason: "genesis.incoming must be an array" };
  for (const incomingDid of genesis.incoming) {
    if (!incomingDid) return { valid: false, reason: "genesis.incoming must not contain an empty entry" };
  }
  if (genesis.incoming.includes(did)) return { valid: false, reason: "REQ-7.1-9: a genesis can't name itself as its own guardian" };
  if (new Set(genesis.incoming).size !== genesis.incoming.length) return { valid: false, reason: "genesis.incoming must not name the same guardian twice" };
  if (!Array.isArray(genesis.operationalKeys) || genesis.operationalKeys.length === 0) {
    return { valid: false, reason: "REQ-7.1-3: genesis.operationalKeys must be a non-empty array" };
  }

  const shape = checkGenesisShape(genesis);
  if (!shape.valid) return { valid: false, reason: shape.reason ?? "invalid genesis shape" };

  let registrarDid: Did;
  try {
    registrarDid = expectedRegistrarDid(genesis.did);
  } catch {
    return { valid: false, reason: `genesis.did "${genesis.did}" does not parse as a valid did:guardian identifier (REQ-2-2)` };
  }

  const genesisVerified = await verifyCustodialCreate(genesis, resolve, registrarDid);
  if (!genesisVerified.valid) return { valid: false, reason: genesisVerified.reason ?? "genesis verification failed" };

  for (let i = 1; i < log.length; i++) {
    const entry = log[i];
    const op = entry.op as { type: string; prev: string | null };

    const cid = await cidFor(entry.op as any);
    if (cid !== entry.cid) return { valid: false, reason: `operation at index ${i} has cid mismatch -- stored "${entry.cid}", recomputed "${cid}" (REQ-6-4)` };

    const priorLog = log.slice(0, i);
    let priorChain: LogEntry[];
    try {
      priorChain = reconstructChain(priorLog);
    } catch (e) {
      return { valid: false, reason: `operation at index ${i}: ${(e as Error).message}` };
    }
    const state = replay(did, priorChain);
    if (state.deactivated) return { valid: false, reason: `operation at index ${i}: REQ-6-5, an operation appears after this identity's own tombstone` };

    const headCid = priorChain[priorChain.length - 1].cid;
    const opPrev = op.prev ?? null;
    const ctx: VerificationContext = { wardDid: did, state, resolveKey: resolve, isGuardianLive, sigTimestamps };

    if (op.type === "guardian_transfer") {
      // v0.1, superseded -- still verifiable for already-accepted history, but (same as every other type) only ever as an ordinary append; it never had a nullification mechanism of its own.
      if (opPrev !== headCid) return { valid: false, reason: `operation at index ${i}: guardian_transfer has no nullification mechanism of its own` };
      const result = await verifyGuardianTransfer(entry.op as any, did, state.guardians, resolve);
      if (!result.valid) return { valid: false, reason: `operation at index ${i}: ${result.reason}` };
    } else if (opPrev === headCid) {
      const result = await verifyByRules(entry.op as any, ctx);
      if (!result.valid) return { valid: false, reason: `operation at index ${i}: ${result.reason}` };
    } else {
      const nullCheck = await checkNullification(priorLog, entry.op as any, ctx, now);
      if (!nullCheck.ok) return { valid: false, reason: `operation at index ${i}: ${nullCheck.reason}` };
    }
  }

  let finalChain: LogEntry[];
  try {
    finalChain = reconstructChain(log);
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }
  const finalState = replay(did, finalChain);
  return { valid: true, anchor: genesisEntry.cid, registrarDid, state: finalState };
}
