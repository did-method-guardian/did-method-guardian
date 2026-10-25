import { contentRef, signPayload, verifyPayload } from "./crypto.js";
import { meetsThreshold, requiredTransferSigners } from "./quorum.js";
import type {
  CustodialCreateOp,
  CustodialRotateOp,
  CustodialTombstoneOp,
  Did,
  GuardianAddOp,
  GuardianPolicy,
  GuardianRelinquishOp,
  GuardianRemoveOp,
  GuardianTransferOp,
  Operation,
  PolicyUpdateOp,
} from "./types.js";

/**
 * Resolves a DID's current, authoritative public key(s) at verification time
 * -- live, never a frozen snapshot (spec §4.8). Async: a real deployment
 * resolves external DIDs over the network (spec §5), not just from local
 * state.
 */
export type KeyResolver = (did: Did) => string[] | undefined | Promise<string[] | undefined>;

function payloadWithoutSig<T extends { sig?: unknown; sigs?: unknown }>(op: T): Omit<T, "sig" | "sigs"> {
  const { sig: _sig, sigs: _sigs, ...rest } = op;
  return rest;
}

/** Registrar attestation (REQ-7.1-5) has to exclude its own field entirely, not just `sig`/`sigs` -- a signature can't cover its own not-yet-computed value. */
function payloadWithoutSigOrRegistrar<T extends { sig?: unknown; sigs?: unknown; registrar?: unknown }>(op: T): Omit<T, "sig" | "sigs" | "registrar"> {
  const { sig: _sig, sigs: _sigs, registrar: _registrar, ...rest } = op;
  return rest;
}

/** Verifies one party's signature over an operation, checked against that party's own resolved keys. */
export async function verifySignerSig(op: Operation, signerDid: Did, sigB64: string, resolve: KeyResolver): Promise<boolean> {
  const keys = await resolve(signerDid);
  if (!keys || keys.length === 0) return false;
  const payload = payloadWithoutSig(op as any);
  for (const pk of keys) {
    if (await verifyPayload(payload, sigB64, pk)) return true;
  }
  return false;
}

async function filterValidSigners(op: Operation, dids: Did[], resolve: KeyResolver, sigs: Record<Did, string>): Promise<Did[]> {
  const valid: Did[] = [];
  for (const did of dids) {
    const sig = sigs[did];
    if (sig && (await verifySignerSig(op, did, sig, resolve))) valid.push(did);
  }
  return valid;
}

export async function signCustodialCreate(
  partial: Omit<CustodialCreateOp, "sigs">,
  incomingKeys: Record<Did, string>, // private key per `incoming` DID
): Promise<CustodialCreateOp> {
  const payload = payloadWithoutSig(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of partial.incoming) {
    const pk = incomingKeys[did];
    if (!pk) throw new Error(`missing private key for incoming guardian ${did}`);
    sigs[did] = await signPayload(payload, pk);
  }
  return { ...partial, sigs };
}

/**
 * REQ-7.1-4: who initiated this registration -- a plain fact, carries no
 * signature requirement of its own (same standing as genesis's optional
 * `policy`, REQ-7.1-7). Signs a registrar attestation
 * (`signRegistrarAttestation`) for the exact same op content a consuming
 * caller will build, including `creator` -- genesis's own payload is
 * otherwise complete the moment `operationalKeys`/`verificationMethods`/
 * `services`/`creator` are decided, before an attestation even exists.
 */
export async function signRegistrarAttestation(
  partial: Omit<CustodialCreateOp, "sigs" | "registrar">,
  registrarDid: Did,
  registrarPrivateKey: string,
): Promise<{ did: Did; sig: string }> {
  const payload = payloadWithoutSigOrRegistrar(partial as any);
  return { did: registrarDid, sig: await signPayload(payload, registrarPrivateKey) };
}

export async function verifyCustodialCreate(op: CustodialCreateOp, resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  if (op.prev !== null) return { valid: false, reason: "genesis must have prev: null" };
  for (const did of op.incoming) {
    const sig = op.sigs[did];
    if (!sig || !(await verifySignerSig(op, did, sig, resolve))) {
      return { valid: false, reason: `missing or invalid signature from incoming guardian ${did}` };
    }
  }
  if (op.registrar) {
    const keys = await resolve(op.registrar.did);
    const payload = payloadWithoutSigOrRegistrar(op as any);
    const ok = !!keys && (await Promise.all(keys.map((pk) => verifyPayload(payload, op.registrar!.sig, pk)))).some(Boolean);
    if (!ok) return { valid: false, reason: "invalid registrar attestation signature" };
  }
  return { valid: true };
}

export async function signCustodialRotate(partial: Omit<CustodialRotateOp, "sig">, privateKey: string): Promise<CustodialRotateOp> {
  const payload = payloadWithoutSig(partial as any);
  return { ...partial, sig: await signPayload(payload, privateKey) };
}

/** REQ-7.2-1(b): guardian-initiated recovery rotation -- signed by `sigs` (guardian DIDs), never the ward's own key. Nullification eligibility (REQ-6-8) is checked at the log/registrar level (see document.ts), not here. */
export async function signCustodialRotateByGuardians(
  partial: Omit<CustodialRotateOp, "sig" | "sigs">,
  signerKeys: Record<Did, string>,
  signers: Did[],
): Promise<CustodialRotateOp> {
  const payload = payloadWithoutSig(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of signers) {
    const pk = signerKeys[did];
    if (!pk) throw new Error(`missing private key for required signer ${did}`);
    sigs[did] = await signPayload(payload, pk);
  }
  return { ...partial, sigs };
}

export async function verifyCustodialRotate(op: CustodialRotateOp, currentOperationalKeys: string[], resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  if (!op.sig) return { valid: false, reason: "rotation not signed by a current operational key" };
  const payload = payloadWithoutSig(op as any);
  for (const pk of currentOperationalKeys) {
    if (await verifyPayload(payload, op.sig, pk)) return { valid: true };
  }
  return { valid: false, reason: "rotation not signed by a current operational key" };
}

export async function signGuardianTransfer(
  partial: Omit<GuardianTransferOp, "sigs">,
  wardDid: Did,
  currentGuardians: Did[],
  signerKeys: Record<Did, string>,
): Promise<GuardianTransferOp> {
  const required = requiredTransferSigners(wardDid, currentGuardians, partial.outgoing, partial.incoming);
  const payload = payloadWithoutSig(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of required) {
    const pk = signerKeys[did];
    if (!pk) throw new Error(`missing private key for required signer ${did}`);
    sigs[did] = await signPayload(payload, pk);
  }
  return { ...partial, sigs };
}

export async function verifyGuardianTransfer(
  op: GuardianTransferOp,
  wardDid: Did,
  currentGuardians: Did[],
  resolve: KeyResolver,
): Promise<{ valid: boolean; reason?: string }> {
  if (op.incoming.length === 0) return { valid: false, reason: "incoming must be non-empty (use guardian_relinquish for full removal)" };
  if (!op.outgoing.every((d) => currentGuardians.includes(d))) {
    return { valid: false, reason: "outgoing includes a party that is not a current guardian" };
  }
  const required = requiredTransferSigners(wardDid, currentGuardians, op.outgoing, op.incoming);
  for (const did of required) {
    const sig = op.sigs[did];
    if (!sig || !(await verifySignerSig(op, did, sig, resolve))) {
      return { valid: false, reason: `missing or invalid signature from required party ${did}` };
    }
  }
  return { valid: true };
}

export async function signGuardianRelinquish(partial: Omit<GuardianRelinquishOp, "sigs">, signerKeys: Record<Did, string>, signers: Did[]): Promise<GuardianRelinquishOp> {
  const payload = payloadWithoutSig(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of signers) {
    const pk = signerKeys[did];
    if (!pk) throw new Error(`missing private key for guardian ${did}`);
    sigs[did] = await signPayload(payload, pk);
  }
  return { ...partial, sigs };
}

export async function verifyGuardianRelinquish(
  op: GuardianRelinquishOp,
  currentGuardians: Did[],
  removalThreshold: GuardianPolicy["removal_threshold"],
  resolve: KeyResolver,
): Promise<{ valid: boolean; reason?: string }> {
  const validSigners = await filterValidSigners(op, currentGuardians, resolve, op.sigs);
  if (!meetsThreshold(removalThreshold, validSigners, currentGuardians)) {
    return { valid: false, reason: "removal_threshold not met for guardian_relinquish" };
  }
  return { valid: true };
}

/** v0.2. Shared by guardian_add/guardian_remove/policy_update -- each just needs a `sigs` map over whichever signers it names, same shape signGuardianRelinquish already uses. */
async function signSigsMap<Op extends { sigs?: Record<Did, string> }>(partial: Omit<Op, "sigs">, signerKeys: Record<Did, string>, signers: Did[]): Promise<Op> {
  const payload = payloadWithoutSig(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of signers) {
    const pk = signerKeys[did];
    if (!pk) throw new Error(`missing private key for required signer ${did}`);
    sigs[did] = await signPayload(payload, pk);
  }
  return { ...partial, sigs } as Op;
}

export function signGuardianAdd(partial: Omit<GuardianAddOp, "sigs">, signerKeys: Record<Did, string>, signers: Did[]): Promise<GuardianAddOp> {
  return signSigsMap(partial, signerKeys, signers);
}

export function signGuardianRemove(partial: Omit<GuardianRemoveOp, "sigs">, signerKeys: Record<Did, string>, signers: Did[]): Promise<GuardianRemoveOp> {
  return signSigsMap(partial, signerKeys, signers);
}

export function signPolicyUpdate(partial: Omit<PolicyUpdateOp, "sigs">, signerKeys: Record<Did, string>, signers: Did[]): Promise<PolicyUpdateOp> {
  return signSigsMap(partial, signerKeys, signers);
}

export async function signCustodialTombstone(partial: Omit<CustodialTombstoneOp, "sigs">, signerKeys: Record<Did, string>, signers: Did[]): Promise<CustodialTombstoneOp> {
  const payload = payloadWithoutSig(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of signers) {
    sigs[did] = await signPayload(payload, signerKeys[did]);
  }
  return { ...partial, sigs };
}

export async function verifyCustodialTombstone(
  op: CustodialTombstoneOp,
  eligibleSigners: Did[], // operational key holder(s) treated as their own "did" for this check, plus current guardians
  tombstoneThreshold: GuardianPolicy["tombstone_threshold"],
  resolve: KeyResolver,
): Promise<{ valid: boolean; reason?: string }> {
  const validSigners = await filterValidSigners(op, eligibleSigners, resolve, op.sigs);
  if (!meetsThreshold(tombstoneThreshold, validSigners, eligibleSigners)) {
    return { valid: false, reason: "tombstone_threshold not met" };
  }
  return { valid: true };
}

export async function cidFor(op: Operation): Promise<string> {
  return contentRef(op);
}
