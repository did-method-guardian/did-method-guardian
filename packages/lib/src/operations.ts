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
 * Resolves a DID's authoritative public key(s) -- live, never a frozen
 * snapshot (spec §4.8). Async: a real deployment resolves external DIDs
 * over the network (spec §5), not just from local state.
 *
 * `asOf`, when given, asks for whichever key(s) were valid for that DID at
 * that point in time -- REQ-4-2's own point-in-time requirement for a
 * guardian signature, determined by replaying that guardian's own log up to
 * `asOf` rather than asking what its key is right now. Omitted means "now"
 * -- the ordinary case for a signature that's verified immediately, in the
 * same call it was produced in (every self-contained convenience endpoint).
 * A signature collected asynchronously (registrar API spec §3) and verified
 * again later, after its own signer has since rotated, is exactly the case
 * this parameter exists for.
 */
export type KeyResolver = (did: Did, asOf?: Date) => string[] | undefined | Promise<string[] | undefined>;

/**
 * Every signature field an operation can carry -- ward/guardian `sig`/
 * `sigs`, v0.3's key-possession `keySigs`, and the registrar `attestation`
 * -- is stripped before computing the payload any of them signs. None can
 * cover its not-yet-computed value, and critically, none of them cover
 * each other either: ward keySigs, guardian sigs, and the registrar
 * attestation are parallel, independent signatures over the identical
 * stripped content, not nested in signing order. That's what lets a client
 * sign first and a registrar attest afterward without the client ever
 * re-signing (registrar API spec, genesis submission).
 */
export function corePayload<T extends { sig?: unknown; sigs?: unknown; keySigs?: unknown; registrar?: unknown }>(
  op: T,
): Omit<T, "sig" | "sigs" | "keySigs" | "registrar"> {
  const { sig: _sig, sigs: _sigs, keySigs: _keySigs, registrar: _registrar, ...rest } = op;
  return rest;
}

/** Produces `keySigs` for every entry in `keys` (REQ-7.1-8/REQ-7.2-12) -- the party declaring a key signs the core payload with that key's matching private half, proving possession. */
async function signKeySigs(payload: unknown, keys: string[], privateKeys: Record<string, string>): Promise<Record<string, string>> {
  const keySigs: Record<string, string> = {};
  for (const pubKey of keys) {
    const pk = privateKeys[pubKey];
    if (!pk) throw new Error(`missing private key for operational key ${pubKey}`);
    keySigs[pubKey] = await signPayload(payload, pk);
  }
  return keySigs;
}

/** Checks `op.keySigs` carries a valid signature, over the core payload, from every key in `keys` -- each key verified against itself, no DID resolution involved (an operational key isn't an independently resolvable identity). */
export async function verifyKeySigs(payload: unknown, keys: string[], keySigs: Record<string, string> | undefined): Promise<{ valid: boolean; reason?: string }> {
  for (const pubKey of keys) {
    const sig = keySigs?.[pubKey];
    if (!sig || !(await verifyPayload(payload, sig, pubKey))) {
      return { valid: false, reason: `missing or invalid proof of possession for operational key ${pubKey}` };
    }
  }
  return { valid: true };
}

/** Verifies one party's signature over an operation, checked against that party's own resolved keys -- as of `asOf` if given, see `KeyResolver`. */
export async function verifySignerSig(op: Operation, signerDid: Did, sigB64: string, resolve: KeyResolver, asOf?: Date): Promise<boolean> {
  const keys = await resolve(signerDid, asOf);
  if (!keys || keys.length === 0) return false;
  const payload = corePayload(op as any);
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
  partial: Omit<CustodialCreateOp, "sigs" | "keySigs">,
  incomingKeys: Record<Did, string>, // private key per `incoming` DID
  operationalPrivateKeys: Record<string, string>, // v0.3, REQ-7.1-8: private key per entry in operationalKeys
): Promise<CustodialCreateOp> {
  const payload = corePayload(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of partial.incoming) {
    const pk = incomingKeys[did];
    if (!pk) throw new Error(`missing private key for incoming guardian ${did}`);
    sigs[did] = await signPayload(payload, pk);
  }
  const keySigs = await signKeySigs(payload, partial.operationalKeys, operationalPrivateKeys);
  return { ...partial, sigs, keySigs };
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
  partial: Omit<CustodialCreateOp, "sigs" | "registrar" | "keySigs">,
  registrarDid: Did,
  registrarPrivateKey: string,
): Promise<{ did: Did; sig: string }> {
  const payload = corePayload(partial as any);
  return { did: registrarDid, sig: await signPayload(payload, registrarPrivateKey) };
}

export async function verifyCustodialCreate(op: CustodialCreateOp, resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  if (op.prev !== null) return { valid: false, reason: "genesis must have prev: null" };
  const payload = corePayload(op as any);
  const pop = await verifyKeySigs(payload, op.operationalKeys, op.keySigs); // REQ-7.1-8
  if (!pop.valid) return pop;
  for (const did of op.incoming) {
    const sig = op.sigs[did];
    if (!sig || !(await verifySignerSig(op, did, sig, resolve))) {
      return { valid: false, reason: `missing or invalid signature from incoming guardian ${did}` };
    }
  }
  if (!op.registrar) return { valid: false, reason: "registrar attestation is required (REQ-7.1-5)" };
  const keys = await resolve(op.registrar.did);
  const ok = !!keys && (await Promise.all(keys.map((pk) => verifyPayload(payload, op.registrar!.sig, pk)))).some(Boolean);
  if (!ok) return { valid: false, reason: "invalid registrar attestation signature" };
  return { valid: true };
}

/** `newKeyPrivateKeys`, v0.3 (REQ-7.2-12): private key per entry in `partial.operationalKeys` -- the NEW keys being installed, proving the ward actually holds whatever it's rotating to, not just the old key authorizing the change. */
export async function signCustodialRotate(
  partial: Omit<CustodialRotateOp, "sig" | "keySigs">,
  privateKey: string,
  newKeyPrivateKeys: Record<string, string>,
): Promise<CustodialRotateOp> {
  const payload = corePayload(partial as any);
  const keySigs = await signKeySigs(payload, partial.operationalKeys, newKeyPrivateKeys);
  return { ...partial, sig: await signPayload(payload, privateKey), keySigs };
}

/** REQ-7.2-1(b): guardian-initiated recovery rotation -- signed by `sigs` (guardian DIDs), never the ward's own key. Nullification eligibility (REQ-6-8) is checked at the log/registrar level (see document.ts), not here. `newKeyPrivateKeys`, v0.3 (REQ-7.2-12): same proof-of-possession requirement as self-rotation -- a guardian can authorize installing a key, but the key itself still has to prove it's held by whoever's about to operate it. */
export async function signCustodialRotateByGuardians(
  partial: Omit<CustodialRotateOp, "sig" | "sigs" | "keySigs">,
  signerKeys: Record<Did, string>,
  signers: Did[],
  newKeyPrivateKeys: Record<string, string>,
): Promise<CustodialRotateOp> {
  const payload = corePayload(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of signers) {
    const pk = signerKeys[did];
    if (!pk) throw new Error(`missing private key for required signer ${did}`);
    sigs[did] = await signPayload(payload, pk);
  }
  const keySigs = await signKeySigs(payload, partial.operationalKeys, newKeyPrivateKeys);
  return { ...partial, sigs, keySigs };
}

export async function verifyCustodialRotate(op: CustodialRotateOp, currentOperationalKeys: string[], resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  const payload = corePayload(op as any);
  const pop = await verifyKeySigs(payload, op.operationalKeys, op.keySigs); // REQ-7.2-12
  if (!pop.valid) return pop;
  if (!op.sig) return { valid: false, reason: "rotation not signed by a current operational key" };
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
  const payload = corePayload(partial as any);
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
  const payload = corePayload(partial as any);
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
  const payload = corePayload(partial as any);
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
  const payload = corePayload(partial as any);
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
