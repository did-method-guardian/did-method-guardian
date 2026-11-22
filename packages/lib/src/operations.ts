import { canonicalize, sha256Bytes, signRawBytes, verifyRawBytes, contentRef, signPayload, verifyPayload } from "./crypto.js";
import { meetsThreshold, requiredTransferSigners } from "./quorum.js";
import { parseDid } from "./resolve.js";
import { DEFAULT_GUARDIAN_POLICY, validatePolicy } from "./types.js";
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
 * the operation with `proof` itself removed. Per the W3C Data Integrity
 * spec's own proof-set semantics (confirmed directly against the spec
 * text, not assumed): every proof in a set signs the SAME
 * unsecuredDocument, with every proof removed -- never "every other
 * proof," which would make each proof's signing input depend on what
 * order proofs were added in.
 *
 * WS-1.10 (audit): `sigs` is excluded too, but ONLY for
 * `guardian_transfer` (v0.1, replay-only -- see its own comment in
 * types.ts) -- that's the one type whose own, separate signature scheme
 * (signPayload/verifyPayload, not a DataIntegrityProof) needs `sigs`
 * self-excluded from its signing input, the same way `proof` is self-
 * excluded for every current type. Stripping `sigs` unconditionally (as
 * a previous version of this function did) meant any OTHER operation
 * type could carry an arbitrary extra `sigs` field completely outside
 * both its cid (cidFor delegates to this same function) and every
 * signature's own coverage -- unauthenticated data riding along for
 * free, bound to neither.
 */
export function unsecuredDocument<T extends { proof?: unknown; sigs?: unknown; type?: unknown }>(op: T): Omit<T, "proof" | "sigs"> {
  const { proof: _proof, ...rest } = op as any;
  if (rest.type === "guardian_transfer") {
    const { sigs: _sigs, ...withoutSigs } = rest;
    return withoutSigs;
  }
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
  // WS-3.1 (audit): canonicalize now checks JCS-safety itself (crypto.ts), on everything it's given -- no separate call needed here.
  const proofConfig = { type: "DataIntegrityProof" as const, cryptosuite: "ecdsa-jcs-2019" as const, verificationMethod, proofPurpose: PROOF_CONFIG_PURPOSE, created };
  const proofConfigHash = await sha256Bytes(new TextEncoder().encode(canonicalize(proofConfig)));
  const documentHash = await sha256Bytes(new TextEncoder().encode(canonicalize(unsecuredDoc)));
  const signingInput = new Uint8Array(proofConfigHash.length + documentHash.length);
  signingInput.set(proofConfigHash, 0);
  signingInput.set(documentHash, proofConfigHash.length);
  const proofValue = await signRawBytes(signingInput, privateKeyB64url);
  return { ...proofConfig, proofValue };
}

const PROOF_FIELDS = ["type", "cryptosuite", "verificationMethod", "proofPurpose", "created", "proofValue"] as const;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;

/**
 * WS-1.9 (audit): every DataIntegrityProof's own fields, checked before
 * any cryptographic work. type/cryptosuite/proofPurpose/created aren't
 * just inputs the signing-input hash happens to cover (a mismatch there
 * already fails the signature on its own, since createProof's signer
 * hashed the real values) -- they carry meaning under the W3C Data
 * Integrity model, and createProof never produces anything but this
 * fixed shape. Without this, a proof with an unrecognized cryptosuite, a
 * proofPurpose other than this implementation's one current value (WS-
 * 5.4 decided a future per-role split -- update PROOF_CONFIG_PURPOSE's
 * use here to a per-role expected value once that split is actually
 * implemented in code, not just decided), a created that isn't a real
 * ISO-8601 UTC instant, or an unexpected extra field would only ever be
 * caught indirectly, by relying on the signature check to happen to fail
 * -- which it does today only because nothing has a reason to sign a
 * different shape, not because anything actually checks for one.
 */
export function validateProofShape(proof: DataIntegrityProof): { valid: boolean; reason?: string } {
  if (proof.type !== "DataIntegrityProof") return { valid: false, reason: `proof.type must be "DataIntegrityProof"` };
  if (proof.cryptosuite !== "ecdsa-jcs-2019") return { valid: false, reason: `proof.cryptosuite must be "ecdsa-jcs-2019"` };
  if (proof.proofPurpose !== PROOF_CONFIG_PURPOSE) return { valid: false, reason: `proof.proofPurpose must be "${PROOF_CONFIG_PURPOSE}"` };
  if (typeof proof.verificationMethod !== "string" || proof.verificationMethod.length === 0) {
    return { valid: false, reason: "proof.verificationMethod must be a non-empty string" };
  }
  if (typeof proof.created !== "string" || !ISO_INSTANT.test(proof.created)) {
    return { valid: false, reason: "proof.created must be an ISO-8601 UTC instant" };
  }
  if (typeof proof.proofValue !== "string" || proof.proofValue.length === 0) {
    return { valid: false, reason: "proof.proofValue must be a non-empty string" };
  }
  for (const key of Object.keys(proof)) {
    if (!(PROOF_FIELDS as readonly string[]).includes(key)) return { valid: false, reason: `proof has an unexpected field: ${key}` };
  }
  return { valid: true };
}

/** The inverse of createProof, checked against one specific candidate public key -- the caller (verifySignerProof, PoP checks below) decides which key(s) are worth trying. */
async function verifyProof(unsecuredDoc: unknown, proof: DataIntegrityProof, publicKeyMultikey: string): Promise<boolean> {
  try {
    if (!validateProofShape(proof).valid) return false;
    // WS-3.1 (audit): canonicalize checks JCS-safety itself now, on
    // proofConfig too (destructured straight from the wire-supplied
    // `proof`, fully attacker-controlled) -- not just on unsecuredDoc as
    // a previous version of this function only ever did.
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
  if (!proofs.some((p) => verificationMethodDid(p.verificationMethod) === did)) return false;
  const keys = await resolve(did, asOf);
  if (!keys || keys.length === 0) return false;
  return verifyAgainstKeys(unsecuredDoc, proofs, did, keys);
}

/**
 * The shared inner loop `verifySignerProof` uses once it has a key list in
 * hand -- also exported directly for callers that already KNOW the right
 * key set without needing to resolve it at all. Audit WS-1.1/1.2: the
 * ward's own current operational keys are exactly this case -- they're
 * already present in `ctx.state.operationalKeys` (the very state an
 * operation is being verified against), so resolving them a second time
 * through an external resolver function is both unnecessary and a risk
 * that resolver might disagree with `ctx.state` (the stale-cached-column
 * bug this closes). `proofs` is the operation's own full proof array --
 * this filters by `did` itself, same as `verifySignerProof`.
 */
export async function verifyAgainstKeys(unsecuredDoc: unknown, proofs: DataIntegrityProof[], did: Did, keys: string[]): Promise<boolean> {
  const candidates = proofs.filter((p) => verificationMethodDid(p.verificationMethod) === did);
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

/** WS-1.7/4.4 (audit): the only valid "accepting registrar" for a genesis is the bare-domain identity of `did`'s OWN domain -- never an arbitrary DID a caller happens to pass. Computed structurally from `did` itself, never scanned for out of a proof set (see WS-1.7's own fix below). Exported for WS-2.1's verifyLog, which needs the same derivation to check a whole log from scratch rather than trusting a caller-supplied registrarDid. */
export function expectedRegistrarDid(did: Did): Did {
  const { domain } = parseDid(did);
  return `did:guardian:${domain}` as Did;
}

export async function verifyCustodialCreate(op: CustodialCreateOp, resolve: KeyResolver, registrarDid: Did): Promise<{ valid: boolean; reason?: string }> {
  if (op.prev !== null) return { valid: false, reason: "genesis must have prev: null" };
  // WS-4.4: the passed-in `registrarDid` itself must actually be the
  // domain root of `op.did` -- defense in depth against a caller (this
  // registrar's own code is already correct, but the library can't
  // assume every caller is) passing an unrelated DID that happens to
  // resolve and sign correctly. "A genesis for acme.com:alice attested
  // by did:guardian:evil.com#key-0" must never pass, regardless of what
  // a caller claims the accepting registrar is.
  let expected: Did;
  try {
    expected = expectedRegistrarDid(op.did);
  } catch {
    return { valid: false, reason: `genesis.did "${op.did}" does not parse as a valid did:guardian identifier (REQ-2-2)` };
  }
  if (registrarDid !== expected) {
    return { valid: false, reason: `registrarDid "${registrarDid}" is not the domain root of genesis.did "${op.did}" -- expected "${expected}" (REQ-7.1-5/WS-4.4)` };
  }
  // WS-1.8: genesis's own `policy` (REQ-7.1-7) is Partial, so the check
  // runs against it merged with DEFAULT_GUARDIAN_POLICY -- the same
  // result document.ts's replay() will actually install into
  // ResolvedState.guardianPolicy. Without this, a genesis naming a
  // future policy version or a malformed threshold would be accepted
  // outright and leave the ward unverifiable from its very first
  // post-genesis operation onward.
  if (op.policy !== undefined) {
    const policyCheck = validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, ...op.policy });
    if (!policyCheck.valid) return { valid: false, reason: `genesis policy (REQ-7.1-7): ${policyCheck.reason}` };
  }
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
  const selfAttested = op.did === registrarDid;
  if (!selfAttested && !(await verifySignerProof(unsecuredDoc, op.proof, registrarDid, resolve))) {
    return { valid: false, reason: "registrar attestation is required (REQ-7.1-5)" };
  }
  // WS-1.7: every proof in the set must be ACCOUNTED FOR -- a PoP proof
  // for a declared operational key, an incoming guardian's own signature,
  // or the registrar's attestation (or, for self-attestation, the root's
  // own PoP again). An unexplained extra proof (e.g. a stray
  // `did:guardian:evil.example#key-0`) was previously accepted outright
  // and could later be picked up by document.ts's own registrarDid
  // extraction as if it were the real attestation, poisoning L1 pinning.
  const incomingSet = new Set(op.incoming);
  for (const proof of op.proof) {
    if (proof.verificationMethod.startsWith("did:key:")) {
      if (!op.operationalKeys.some((k) => proof.verificationMethod === popVerificationMethod(k))) {
        return { valid: false, reason: `unexplained proof of possession in genesis proof set: ${proof.verificationMethod}` };
      }
      continue;
    }
    const signerDid = verificationMethodDid(proof.verificationMethod);
    if (signerDid === registrarDid || incomingSet.has(signerDid)) continue;
    return { valid: false, reason: `unexplained proof in genesis proof set, from neither an incoming guardian nor the registrar: ${proof.verificationMethod}` };
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
