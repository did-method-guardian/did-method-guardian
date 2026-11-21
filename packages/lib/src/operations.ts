import { canonicalize, assertJCSSafe, sha256Bytes, signRawBytes, verifyRawBytes, contentRef, signPayload, verifyPayload } from "./crypto.js";
import { meetsThreshold, requiredTransferSigners } from "./quorum.js";
import type {
  CustodialCreateOp,
  CustodialRotateOp,
  CustodialTombstoneOp,
  DataIntegrityProof,
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
 * Fix 5: the content every proof in an operation's `proof` set signs --
 * the operation with `proof` itself removed. `sigs` is stripped too,
 * purely for `GuardianTransferOp` (the only type that still carries it,
 * v0.1, replay-only -- see its own comment in types.ts); no current
 * type has both fields at once, so stripping both uniformly needs no
 * per-type branching. Per the W3C Data Integrity spec's own proof-set
 * semantics (confirmed directly against the spec text, not assumed):
 * every proof in a set signs the SAME unsecuredDocument, with every
 * proof removed -- never "every other proof," which would make each
 * proof's signing input depend on what order proofs were added in.
 */
export function unsecuredDocument<T extends { proof?: unknown; sigs?: unknown }>(op: T): Omit<T, "proof" | "sigs"> {
  const { proof: _proof, sigs: _sigs, ...rest } = op as any;
  return rest;
}

const PROOF_CONFIG_PURPOSE = "assertionMethod" as const;

/**
 * ecdsa-jcs-2019 (W3C Data Integrity ECDSA Cryptosuites v1.0): signing
 * input = SHA-256(JCS(proof config, no proofValue)) || SHA-256(JCS(the
 * unsecured document)) -- raw hash bytes concatenated, not re-hashed
 * before being handed to ECDSA-with-SHA-256 itself (which hashes its
 * own input as part of the ordinary signing operation, one level
 * deeper). Verified directly against the W3C spec text, not assumed.
 */
export async function createProof(unsecuredDoc: unknown, verificationMethod: string, privateKeyB64url: string, created: string = new Date().toISOString()): Promise<DataIntegrityProof> {
  assertJCSSafe(unsecuredDoc);
  const proofConfig = { type: "DataIntegrityProof" as const, cryptosuite: "ecdsa-jcs-2019" as const, verificationMethod, proofPurpose: PROOF_CONFIG_PURPOSE, created };
  const proofConfigHash = await sha256Bytes(new TextEncoder().encode(canonicalize(proofConfig)));
  const documentHash = await sha256Bytes(new TextEncoder().encode(canonicalize(unsecuredDoc)));
  const signingInput = new Uint8Array(proofConfigHash.length + documentHash.length);
  signingInput.set(proofConfigHash, 0);
  signingInput.set(documentHash, proofConfigHash.length);
  const proofValue = await signRawBytes(signingInput, privateKeyB64url);
  return { ...proofConfig, proofValue };
}

/** The inverse of createProof, checked against one specific candidate public key -- the caller (verifySignerProof, PoP checks below) decides which key(s) are worth trying. */
async function verifyProof(unsecuredDoc: unknown, proof: DataIntegrityProof, publicKeyMultikey: string): Promise<boolean> {
  try {
    assertJCSSafe(unsecuredDoc);
    const { proofValue, ...proofConfig } = proof;
    const proofConfigHash = await sha256Bytes(new TextEncoder().encode(canonicalize(proofConfig)));
    const documentHash = await sha256Bytes(new TextEncoder().encode(canonicalize(unsecuredDoc)));
    const signingInput = new Uint8Array(proofConfigHash.length + documentHash.length);
    signingInput.set(proofConfigHash, 0);
    signingInput.set(documentHash, proofConfigHash.length);
    return await verifyRawBytes(signingInput, proofValue, publicKeyMultikey);
  } catch {
    return false;
  }
}

export function verificationMethodDid(vm: string): Did {
  const i = vm.indexOf("#");
  return i >= 0 ? vm.slice(0, i) : vm;
}

/**
 * REQ-7.1-8/REQ-7.2-12: a key proving it holds itself, via a
 * self-contained `did:key:<multikey>#<multikey>` verification method --
 * no DID resolution needed, the public key the proof is checked against
 * is embedded in the verification method itself.
 */
export function popVerificationMethod(multikeyPublicKey: string): string {
  return `did:key:${multikeyPublicKey}#${multikeyPublicKey}`;
}

function findPopProof(proofs: DataIntegrityProof[], multikeyPublicKey: string): DataIntegrityProof | undefined {
  return proofs.find((p) => p.verificationMethod === popVerificationMethod(multikeyPublicKey));
}

/**
 * Checks every entry in `keys` carries a valid proof of possession in
 * `proofs` -- each proof's own `did:key:` verification method embeds
 * the key it's checked against directly, so this never resolves
 * anything externally (an operational key isn't an independently
 * resolvable identity the way a guardian DID is).
 */
export async function verifyPop(unsecuredDoc: unknown, keys: string[], proofs: DataIntegrityProof[]): Promise<{ valid: boolean; reason?: string }> {
  for (const pubKey of keys) {
    const proof = findPopProof(proofs, pubKey);
    if (!proof || !(await verifyProof(unsecuredDoc, proof, pubKey))) {
      return { valid: false, reason: `missing or invalid proof of possession for operational key ${pubKey}` };
    }
  }
  return { valid: true };
}

/**
 * Finds a proof in `proofs` whose verification method names `did`, and
 * checks it against `did`'s live-resolved key(s) -- as of `asOf` if
 * given (REQ-4-2). More than one proof can name the same `did` (a
 * resolver returning several candidate keys is handled the same way);
 * the first one that verifies wins.
 */
export async function verifySignerProof(unsecuredDoc: unknown, proofs: DataIntegrityProof[], did: Did, resolve: KeyResolver, asOf?: Date): Promise<boolean> {
  const candidates = proofs.filter((p) => verificationMethodDid(p.verificationMethod) === did);
  if (candidates.length === 0) return false;
  const keys = await resolve(did, asOf);
  if (!keys || keys.length === 0) return false;
  for (const proof of candidates) {
    for (const pk of keys) {
      if (await verifyProof(unsecuredDoc, proof, pk)) return true;
    }
  }
  return false;
}

async function filterValidSigners(unsecuredDoc: unknown, proofs: DataIntegrityProof[], dids: Did[], resolve: KeyResolver): Promise<Did[]> {
  const valid: Did[] = [];
  for (const did of dids) {
    if (await verifySignerProof(unsecuredDoc, proofs, did, resolve)) valid.push(did);
  }
  return valid;
}

/**
 * `operationalPrivateKeys`, keyed by Multikey public key: REQ-7.1-8,
 * every entry in `partial.operationalKeys` must prove possession.
 * `incomingKeys`, keyed by DID: v0.3 (REQ-7.1-1 relaxed), one proof per
 * `partial.incoming` entry, that guardian's own co-signed consent.
 */
export async function signCustodialCreate(
  partial: Omit<CustodialCreateOp, "proof">,
  incomingKeys: Record<Did, string>,
  operationalPrivateKeys: Record<string, string>,
): Promise<CustodialCreateOp> {
  const unsecuredDoc = unsecuredDocument(partial as any);
  const proof: DataIntegrityProof[] = [];
  for (const pubKey of partial.operationalKeys) {
    const pk = operationalPrivateKeys[pubKey];
    if (!pk) throw new Error(`missing private key for operational key ${pubKey}`);
    proof.push(await createProof(unsecuredDoc, popVerificationMethod(pubKey), pk));
  }
  for (const did of partial.incoming) {
    const pk = incomingKeys[did];
    if (!pk) throw new Error(`missing private key for incoming guardian ${did}`);
    proof.push(await createProof(unsecuredDoc, `${did}#key-0`, pk));
  }
  return { ...partial, proof };
}

/**
 * REQ-7.1-4/7.1-5: the accepting registrar's own attestation, one more
 * independent proof in the same set -- `created` here is this
 * attestation's own signed acceptance timestamp (closing the
 * previously-unsigned `acceptedAt` gap for genesis specifically; every
 * other operation type still relies on `LogEntry.acceptedAt`, unsigned,
 * since only genesis carries a registrar proof at all).
 */
export async function signRegistrarAttestation(partial: Omit<CustodialCreateOp, "proof">, registrarDid: Did, registrarPrivateKey: string, created?: string): Promise<DataIntegrityProof> {
  const unsecuredDoc = unsecuredDocument(partial as any);
  return createProof(unsecuredDoc, `${registrarDid}#key-0`, registrarPrivateKey, created);
}

/**
 * WS-4.1 (audit): the registrar's own signed acceptance receipt -- one
 * more independent proof in the same set as every other signer's,
 * appended by the registrar AFTER an operation is otherwise fully
 * verified, with `created` set to the actual acceptance instant. Every
 * non-genesis operation type has no registrar proof at all until this is
 * appended; for genesis, REQ-7.1-5's own attestation already fills this
 * role (one mechanism, not two -- see `receiptCreatedAt` below for the
 * matching read side).
 */
export async function signReceipt(unsecuredDoc: unknown, registrarDid: Did, registrarPrivateKey: string, acceptedAt: string): Promise<DataIntegrityProof> {
  return createProof(unsecuredDoc, `${registrarDid}#key-0`, registrarPrivateKey, acceptedAt);
}

/**
 * WS-4.1: the one trustworthy acceptance time for `op` -- the registrar's
 * own receipt proof's `created`, never a signer's self-reported `created`
 * (a rotated-away key could backdate it to whenever it was still valid)
 * and never an unsigned, storage-layer timestamp. Every time-sensitive
 * check (REQ-6-8/6-9's nullification window, REQ-4-4's cross-log
 * deactivation timing) MUST read this, not `LogEntry.acceptedAt` directly.
 *
 * Genesis is the one case with no separate registrar receipt proof at
 * all: REQ-7.1-5's attestation (`${registrarDid}#key-0`) already serves
 * this role for an ordinary genesis, and Fix 7's root self-attestation
 * (no separate attestation exists; the root's own PoP proof stands in
 * for it) is checked as a fallback here for exactly that case.
 *
 * Returns undefined when no receipt can be found at all -- callers MUST
 * treat that as "this operation's acceptance time can't be trusted,"
 * never "assume now."
 */
export function receiptCreatedAt(op: { type: string; proof?: DataIntegrityProof[]; did?: Did; operationalKeys?: string[] }, registrarDid: Did): string | undefined {
  const registrarProof = (op.proof ?? []).find((p) => p.verificationMethod === `${registrarDid}#key-0`);
  if (registrarProof) return registrarProof.created;
  if (op.type === "custodial_create" && op.did === registrarDid) {
    for (const key of op.operationalKeys ?? []) {
      const pop = findPopProof(op.proof ?? [], key);
      if (pop) return pop.created;
    }
  }
  return undefined;
}

export async function verifyCustodialCreate(op: CustodialCreateOp, resolve: KeyResolver, registrarDid: Did): Promise<{ valid: boolean; reason?: string }> {
  if (op.prev !== null) return { valid: false, reason: "genesis must have prev: null" };
  const unsecuredDoc = unsecuredDocument(op as any);
  const pop = await verifyPop(unsecuredDoc, op.operationalKeys, op.proof); // REQ-7.1-8
  if (!pop.valid) return pop;
  for (const did of op.incoming) {
    if (!(await verifySignerProof(unsecuredDoc, op.proof, did, resolve))) {
      return { valid: false, reason: `missing or invalid signature from incoming guardian ${did}` };
    }
  }
  // Fix 7: the bare-domain root identity attests its own genesis -- there
  // is no other party to vouch for the one identity a deployment
  // bootstraps on its own, so its proof of possession (already checked
  // above) IS the attestation, rather than a separate, impossible one.
  if (op.did === registrarDid) return { valid: true };
  if (!(await verifySignerProof(unsecuredDoc, op.proof, registrarDid, resolve))) {
    return { valid: false, reason: "registrar attestation is required (REQ-7.1-5)" };
  }
  return { valid: true };
}

/** `wardDid`: the verification method a self-authorized rotation's own proof names (REQ-7.2-1a). `newKeyPrivateKeys`, keyed by Multikey: REQ-7.2-12, proof of possession for every entry in `partial.operationalKeys`, the NEW keys being installed. */
export async function signCustodialRotate(
  partial: Omit<CustodialRotateOp, "proof">,
  wardDid: Did,
  privateKey: string,
  newKeyPrivateKeys: Record<string, string>,
): Promise<CustodialRotateOp> {
  const unsecuredDoc = unsecuredDocument(partial as any);
  const proof: DataIntegrityProof[] = [];
  for (const pubKey of partial.operationalKeys) {
    const pk = newKeyPrivateKeys[pubKey];
    if (!pk) throw new Error(`missing private key for operational key ${pubKey}`);
    proof.push(await createProof(unsecuredDoc, popVerificationMethod(pubKey), pk));
  }
  proof.push(await createProof(unsecuredDoc, `${wardDid}#key-0`, privateKey));
  return { ...partial, proof };
}

/** REQ-7.2-1(b): guardian-initiated recovery rotation. Nullification eligibility (REQ-6-8) is checked at the log/registrar level (see document.ts), not here. `newKeyPrivateKeys`: same proof-of-possession requirement as self-rotation (REQ-7.2-12) -- a guardian can authorize installing a key, but the key itself still has to prove it's held by whoever's about to operate it. */
export async function signCustodialRotateByGuardians(
  partial: Omit<CustodialRotateOp, "proof">,
  signerKeys: Record<Did, string>,
  signers: Did[],
  newKeyPrivateKeys: Record<string, string>,
): Promise<CustodialRotateOp> {
  const unsecuredDoc = unsecuredDocument(partial as any);
  const proof: DataIntegrityProof[] = [];
  for (const pubKey of partial.operationalKeys) {
    const pk = newKeyPrivateKeys[pubKey];
    if (!pk) throw new Error(`missing private key for operational key ${pubKey}`);
    proof.push(await createProof(unsecuredDoc, popVerificationMethod(pubKey), pk));
  }
  for (const did of signers) {
    const pk = signerKeys[did];
    if (!pk) throw new Error(`missing private key for required signer ${did}`);
    proof.push(await createProof(unsecuredDoc, `${did}#key-0`, pk));
  }
  return { ...partial, proof };
}

/** The v0.1-era interop harness path: self-authorized rotation only (REQ-7.2-1a) against a known current-key list. Guardian-initiated rotation (REQ-7.2-1b) goes through rules.ts's rotateRule in the real server path, not this function -- see its own header comment. */
export async function verifyCustodialRotate(op: CustodialRotateOp, currentOperationalKeys: string[], resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  const unsecuredDoc = unsecuredDocument(op as any);
  const pop = await verifyPop(unsecuredDoc, op.operationalKeys, op.proof); // REQ-7.2-12
  if (!pop.valid) return pop;
  for (const pk of currentOperationalKeys) {
    for (const proof of op.proof) {
      if (proof.verificationMethod.startsWith("did:key:")) continue; // a PoP proof, not the authorizing signature
      if (await verifyProof(unsecuredDoc, proof, pk)) return { valid: true };
    }
  }
  return { valid: false, reason: "rotation not signed by a current operational key" };
}

export async function signGuardianTransfer(partial: Omit<GuardianTransferOp, "sigs">, wardDid: Did, currentGuardians: Did[], signerKeys: Record<Did, string>): Promise<GuardianTransferOp> {
  const required = requiredTransferSigners(wardDid, currentGuardians, partial.outgoing, partial.incoming);
  const payload = unsecuredDocument(partial as any);
  const sigs: Record<Did, string> = {};
  for (const did of required) {
    const pk = signerKeys[did];
    if (!pk) throw new Error(`missing private key for required signer ${did}`);
    sigs[did] = await signPayload(payload, pk);
  }
  return { ...partial, sigs };
}

// v0.1, guardian_transfer-only: the pre-Data-Integrity raw signature
// scheme (signPayload/verifyPayload directly, no proof wrapper), kept
// solely so this one legacy type can still be constructed/checked for
// replay testing. Never used by any v0.2+ operation.
async function verifyLegacySignerSig(op: { sigs: Record<Did, string> }, signerDid: Did, resolve: KeyResolver, asOf?: Date): Promise<boolean> {
  const sigB64 = op.sigs[signerDid];
  if (!sigB64) return false;
  const keys = await resolve(signerDid, asOf);
  if (!keys || keys.length === 0) return false;
  const payload = unsecuredDocument(op as any);
  for (const pk of keys) {
    if (await verifyPayload(payload, sigB64, pk)) return true;
  }
  return false;
}

export async function verifyGuardianTransfer(op: GuardianTransferOp, wardDid: Did, currentGuardians: Did[], resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  if (op.incoming.length === 0) return { valid: false, reason: "incoming must be non-empty (use guardian_relinquish for full removal)" };
  if (!op.outgoing.every((d) => currentGuardians.includes(d))) {
    return { valid: false, reason: "outgoing includes a party that is not a current guardian" };
  }
  const required = requiredTransferSigners(wardDid, currentGuardians, op.outgoing, op.incoming);
  for (const did of required) {
    if (!(await verifyLegacySignerSig(op, did, resolve))) {
      return { valid: false, reason: `missing or invalid signature from required party ${did}` };
    }
  }
  return { valid: true };
}

/** v0.2+. Shared by guardian_add/guardian_remove/policy_update/guardian_relinquish/custodial_tombstone -- each just needs one proof per required signer, same shape. */
async function signProofSet<T extends { proof?: DataIntegrityProof[] }>(partial: Omit<T, "proof">, signerKeys: Record<Did, string>, signers: Did[]): Promise<T> {
  const unsecuredDoc = unsecuredDocument(partial as any);
  const proof: DataIntegrityProof[] = [];
  for (const did of signers) {
    const pk = signerKeys[did];
    if (!pk) throw new Error(`missing private key for required signer ${did}`);
    proof.push(await createProof(unsecuredDoc, `${did}#key-0`, pk));
  }
  return { ...partial, proof } as T;
}

export function signGuardianAdd(partial: Omit<GuardianAddOp, "proof">, signerKeys: Record<Did, string>, signers: Did[]): Promise<GuardianAddOp> {
  return signProofSet(partial, signerKeys, signers);
}

export function signGuardianRemove(partial: Omit<GuardianRemoveOp, "proof">, signerKeys: Record<Did, string>, signers: Did[]): Promise<GuardianRemoveOp> {
  return signProofSet(partial, signerKeys, signers);
}

export function signPolicyUpdate(partial: Omit<PolicyUpdateOp, "proof">, signerKeys: Record<Did, string>, signers: Did[]): Promise<PolicyUpdateOp> {
  return signProofSet(partial, signerKeys, signers);
}

export function signGuardianRelinquish(partial: Omit<GuardianRelinquishOp, "proof">, signerKeys: Record<Did, string>, signers: Did[]): Promise<GuardianRelinquishOp> {
  return signProofSet(partial, signerKeys, signers);
}

export async function verifyGuardianRelinquish(op: GuardianRelinquishOp, currentGuardians: Did[], removalThreshold: GuardianPolicy["removal_threshold"], resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  const unsecuredDoc = unsecuredDocument(op as any);
  const validSigners = await filterValidSigners(unsecuredDoc, op.proof, currentGuardians, resolve);
  if (!meetsThreshold(removalThreshold, validSigners, currentGuardians)) {
    return { valid: false, reason: "removal_threshold not met for guardian_relinquish" };
  }
  return { valid: true };
}

export function signCustodialTombstone(partial: Omit<CustodialTombstoneOp, "proof">, signerKeys: Record<Did, string>, signers: Did[]): Promise<CustodialTombstoneOp> {
  return signProofSet(partial, signerKeys, signers);
}

export async function verifyCustodialTombstone(
  op: CustodialTombstoneOp,
  eligibleSigners: Did[], // operational key holder(s) treated as their own "did" for this check, plus current guardians
  tombstoneThreshold: GuardianPolicy["tombstone_threshold"],
  resolve: KeyResolver,
): Promise<{ valid: boolean; reason?: string }> {
  const unsecuredDoc = unsecuredDocument(op as any);
  const validSigners = await filterValidSigners(unsecuredDoc, op.proof, eligibleSigners, resolve);
  if (!meetsThreshold(tombstoneThreshold, validSigners, eligibleSigners)) {
    return { valid: false, reason: "tombstone_threshold not met" };
  }
  return { valid: true };
}

/** REQ-6-4: this operation's entryHash/anchor -- the multihash of its content with every proof stripped (Fix 3: a signature is never deterministic, so hashing one in would make the result depend on which valid signature happened to be produced, not just on content). */
export async function cidFor(op: Operation): Promise<string> {
  return contentRef(unsecuredDocument(op as any));
}
