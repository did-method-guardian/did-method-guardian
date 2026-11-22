import { canonicalize, contentRef, sha256Bytes, signRawBytes, verifyRawBytes } from "./crypto.js";
import type { DataIntegrityProof, Did, Key, Operation, Service } from "./types.js";

/** REQ-5-6: strip `proof`, then the result is hashed in canonical form. Accepts a partial operation with no `proof` member yet -- building the content a proof will sign over -- as well as a complete one. */
export function unsecuredDocument<T extends object>(op: T): Omit<T, "proof"> {
  const { proof: _proof, ...rest } = op as T & { proof?: unknown };
  return rest;
}

/** REQ-5-6: the operation hash. */
export async function operationHash(op: Operation): Promise<string> {
  return contentRef(unsecuredDocument(op));
}

const PROOF_CONFIG = { type: "DataIntegrityProof" as const, cryptosuite: "ecdsa-jcs-2019" as const, proofPurpose: "capabilityInvocation" as const };

/**
 * REQ-5-10: ecdsa-jcs-2019's signing input is SHA-256(JCS(proof config))
 * concatenated with SHA-256(JCS(the secured document)) -- the secured
 * document is the operation with `proof` removed (REQ-5-6's own
 * definition, reused here: the operation hash and the signing input both
 * hash the proof-stripped operation in canonical form).
 */
async function signingInput(unsecuredDoc: unknown, verificationMethod: string): Promise<Uint8Array> {
  const proofConfig = { ...PROOF_CONFIG, verificationMethod };
  const configHash = await sha256Bytes(new TextEncoder().encode(canonicalize(proofConfig)));
  const docHash = await sha256Bytes(new TextEncoder().encode(canonicalize(unsecuredDoc)));
  const input = new Uint8Array(configHash.length + docHash.length);
  input.set(configHash, 0);
  input.set(docHash, configHash.length);
  return input;
}

/** REQ-5-9/REQ-5-10/REQ-5-11: builds a proof over `unsecuredDoc` for `verificationMethod`. */
export async function createProof(unsecuredDoc: unknown, verificationMethod: string, privateKeyB64url: string): Promise<DataIntegrityProof> {
  const proofValue = await signRawBytes(await signingInput(unsecuredDoc, verificationMethod), privateKeyB64url);
  return { ...PROOF_CONFIG, verificationMethod, proofValue };
}

/** REQ-5-13: the signature verifies with `publicKey`. Also used for REQ-5-14 clause 5, once the caller has resolved the key a DID reference names. */
export async function verifyProofSignature(unsecuredDoc: unknown, proof: DataIntegrityProof, publicKey: Key): Promise<boolean> {
  return verifyRawBytes(await signingInput(unsecuredDoc, proof.verificationMethod), proof.proofValue, publicKey);
}

/** REQ-5-12: a key reference. */
export interface KeyReference {
  kind: "key";
  key: Key;
}

/** REQ-5-12: a DID reference. */
export interface DidReference {
  kind: "did";
  did: Did;
  versionId: string;
  index: number;
}

const KEY_REFERENCE_RE = /^did:key:(z[^#]+)#(z[^#]+)$/;
const DID_REFERENCE_RE = /^(did:guardian:[^?#]+)\?versionId=([^#]+)#key-(\d+|0)$/;

/** REQ-5-12: parses a `verificationMethod`, or returns `undefined` if it matches neither form. */
export function parseVerificationMethod(vm: string): KeyReference | DidReference | undefined {
  const keyMatch = KEY_REFERENCE_RE.exec(vm);
  if (keyMatch) {
    if (keyMatch[1] !== keyMatch[2]) return undefined;
    return { kind: "key", key: keyMatch[1] };
  }
  const didMatch = DID_REFERENCE_RE.exec(vm);
  if (didMatch) {
    const indexText = didMatch[3];
    if (indexText !== "0" && indexText.startsWith("0")) return undefined; // REQ-5-12: no leading zeros
    return { kind: "did", did: didMatch[1], versionId: didMatch[2], index: Number(indexText) };
  }
  return undefined;
}

/** REQ-5-12: the key reference `verificationMethod` for a key proving possession of itself. */
export function keyReferenceVerificationMethod(key: Key): string {
  return `did:key:${key}#${key}`;
}

/** REQ-5-12: the DID reference `verificationMethod` for a guardian or root identity's approval. */
export function didReferenceVerificationMethod(did: Did, versionId: string, index: number): string {
  return `${did}?versionId=${versionId}#key-${index}`;
}

/**
 * REQ-5-16: the signer a valid proof approves as. A key reference's
 * signer is the key itself; a DID reference's signer is `<did>`.
 */
export function signerOf(vm: string): string | undefined {
  const ref = parseVerificationMethod(vm);
  if (!ref) return undefined;
  return ref.kind === "key" ? ref.key : ref.did;
}

export interface ShapeResult {
  valid: boolean;
  reason?: string;
}

const invalid = (reason: string): ShapeResult => ({ valid: false, reason });
const VALID: ShapeResult = { valid: true };

/** REQ-5-3. */
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function isUtf8SafeString(value: unknown): boolean {
  return typeof value === "string" && !LONE_SURROGATE_RE.test(value);
}

/** REQ-5-2. */
function isOperationInteger(value: unknown): boolean {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 2 ** 53 - 1;
}

/** REQ-5-9: every proof's own shape, independent of whether its signature verifies. */
export function checkProofShape(proof: unknown): ShapeResult {
  if (typeof proof !== "object" || proof === null) return invalid("a proof must be an object");
  const p = proof as Record<string, unknown>;
  const keys = Object.keys(p).sort();
  const expected = ["cryptosuite", "proofPurpose", "proofValue", "type", "verificationMethod"];
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    return invalid("REQ-5-9: a proof must contain exactly type, cryptosuite, verificationMethod, proofPurpose and proofValue");
  }
  if (p.type !== "DataIntegrityProof") return invalid("REQ-5-9: proof.type must be \"DataIntegrityProof\"");
  if (p.cryptosuite !== "ecdsa-jcs-2019") return invalid("REQ-5-9: proof.cryptosuite must be \"ecdsa-jcs-2019\"");
  if (p.proofPurpose !== "capabilityInvocation") return invalid("REQ-5-9: proof.proofPurpose must be \"capabilityInvocation\"");
  if (typeof p.verificationMethod !== "string" || !parseVerificationMethod(p.verificationMethod)) {
    return invalid("REQ-5-12: verificationMethod must be a key reference or a DID reference");
  }
  if (typeof p.proofValue !== "string") return invalid("REQ-5-9: proofValue must be a string");
  return VALID;
}

/** REQ-5-8/REQ-5-15: the `proof` member's own array shape, independent of each proof's own shape or validity. */
export function checkProofArrayShape(proof: unknown): ShapeResult {
  if (!Array.isArray(proof)) return invalid("REQ-5-8: proof must be an array");
  const signers = new Set<string>();
  for (const p of proof) {
    const shape = checkProofShape(p);
    if (!shape.valid) return shape;
    const signer = signerOf((p as DataIntegrityProof).verificationMethod);
    if (signer === undefined) return invalid("REQ-5-12: unrecognized verificationMethod");
    if (signers.has(signer)) return invalid("REQ-5-15: an operation must not contain two proofs from the same signer");
    signers.add(signer);
  }
  return VALID;
}

/** REQ-6-2. */
export function checkServiceShape(services: unknown): ShapeResult {
  if (!Array.isArray(services)) return invalid("services must be an array");
  if (services.length > 32) return invalid("REQ-6-1: services must contain at most 32 entries");
  const ids = new Set<string>();
  for (const s of services) {
    if (typeof s !== "object" || s === null) return invalid("REQ-6-2: a service must be an object");
    const svc = s as Record<string, unknown>;
    const keys = Object.keys(svc).sort();
    if (keys.length !== 3 || keys[0] !== "id" || keys[1] !== "serviceEndpoint" || keys[2] !== "type") {
      return invalid("REQ-6-2: a service must contain exactly id, type and serviceEndpoint");
    }
    if (typeof svc.id !== "string" || !svc.id.startsWith("#")) return invalid("REQ-6-2: service.id must be a string that begins with \"#\"");
    if (typeof svc.type !== "string") return invalid("REQ-6-2: service.type must be a string");
    if (typeof svc.serviceEndpoint !== "string") return invalid("REQ-6-2: service.serviceEndpoint must be a URI string");
    if (ids.has(svc.id)) return invalid("REQ-6-2: two services must not have the same id");
    ids.add(svc.id);
  }
  return VALID;
}

/** REQ-6-1: keys, 1 to 8 distinct entries. */
export function checkKeysShape(keys: unknown): ShapeResult {
  if (!Array.isArray(keys)) return invalid("keys must be an array");
  if (keys.length < 1 || keys.length > 8) return invalid("REQ-6-1: keys must contain 1 to 8 entries");
  if (keys.some((k) => typeof k !== "string")) return invalid("REQ-5-7: every key must be a Multikey string");
  if (new Set(keys).size !== keys.length) return invalid("REQ-6-1: keys must be distinct");
  return VALID;
}

/** REQ-6-1: guardians, 0 to 32 distinct DIDs. */
export function checkGuardiansShape(guardians: unknown, selfDid?: Did): ShapeResult {
  if (!Array.isArray(guardians)) return invalid("guardians must be an array");
  if (guardians.length > 32) return invalid("REQ-6-1: guardians must contain at most 32 entries");
  if (guardians.some((g) => typeof g !== "string")) return invalid("guardians must be DIDs");
  if (new Set(guardians).size !== guardians.length) return invalid("REQ-6-1: guardians must be distinct");
  if (selfDid !== undefined && guardians.includes(selfDid)) return invalid("REQ-6-3: an identity's DID must not appear in its own guardians");
  return VALID;
}

/** REQ-6-1: alsoKnownAs, 0 to 32 distinct URI strings. */
export function checkAlsoKnownAsShape(alsoKnownAs: unknown): ShapeResult {
  if (!Array.isArray(alsoKnownAs)) return invalid("alsoKnownAs must be an array");
  if (alsoKnownAs.length > 32) return invalid("REQ-6-1: alsoKnownAs must contain at most 32 entries");
  if (alsoKnownAs.some((a) => typeof a !== "string")) return invalid("alsoKnownAs must be URI strings");
  if (new Set(alsoKnownAs).size !== alsoKnownAs.length) return invalid("REQ-6-1: alsoKnownAs must be distinct");
  return VALID;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactMembers(op: Record<string, unknown>, members: readonly string[]): boolean {
  const keys = Object.keys(op).sort();
  const expected = [...members].sort();
  return keys.length === expected.length && keys.every((k, i) => k === expected[i]);
}

/** REQ-5-1/REQ-5-4/REQ-7-1/REQ-7-2/REQ-7-3: members common to every operation type, checked once. */
export function checkCommonShape(op: unknown): ShapeResult {
  if (!isPlainObject(op)) return invalid("REQ-5-1: an operation must be a JSON object");
  const o = op as Record<string, unknown>;
  if (typeof o.type !== "string" || !["create", "update", "addGuardian", "removeGuardian", "setPolicy", "deactivate"].includes(o.type)) {
    return invalid("REQ-7-2: type must be one of create, update, addGuardian, removeGuardian, setPolicy or deactivate");
  }
  if (o.type === "create") {
    if (o.prev !== null) return invalid("REQ-7-3: a create operation's prev must be null");
  } else if (typeof o.prev !== "string") {
    return invalid("REQ-7-3: prev must be the operation hash of the preceding operation");
  }
  return VALID;
}

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/;
const NAME_RE = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;

/** REQ-4-2: a fully qualified DNS hostname, lowercase, no trailing dot, no port. */
export function isValidDomain(domain: string): boolean {
  return DOMAIN_RE.test(domain) && domain.includes(".");
}

/** REQ-4-3: 3 to 32 characters from a-z, 0-9 and -, beginning and ending with a letter or digit. */
export function isValidName(name: string): boolean {
  return NAME_RE.test(name);
}

/** REQ-4-1/REQ-4-4: parses a did:guardian identifier into its domain and optional name. */
export function parseGuardianDid(did: string): { domain: string; name: string | null } | undefined {
  const parts = did.split(":");
  if (parts[0] !== "did" || parts[1] !== "guardian") return undefined;
  if (parts.length === 3) {
    return isValidDomain(parts[2]) ? { domain: parts[2], name: null } : undefined;
  }
  if (parts.length === 4) {
    return isValidDomain(parts[2]) && isValidName(parts[3]) ? { domain: parts[2], name: parts[3] } : undefined;
  }
  return undefined;
}

/** REQ-4-5: the path segment of an identity. */
export function pathSegment(name: string | null): string {
  return name ?? "_";
}

const SETTING_WITH_ANY = new Set(["any", "majority", "all"]);
const SETTING_NO_ANY = new Set(["majority", "all"]);

function isValidSetting(value: unknown, allowAny: boolean): boolean {
  if (typeof value === "number") return Number.isInteger(value) && value >= 1;
  if (typeof value !== "string") return false;
  return allowAny ? SETTING_WITH_ANY.has(value) : SETTING_NO_ANY.has(value);
}

/** REQ-6-4/REQ-6-5: a policy object's own shape, independent of any operation type. */
export function checkPolicyShape(policy: unknown): ShapeResult {
  if (!isPlainObject(policy)) return invalid("REQ-6-4: policy must be an object");
  const allowed = ["recovery", "membership", "removal", "deactivation"];
  for (const key of Object.keys(policy)) {
    if (!allowed.includes(key)) return invalid(`REQ-6-4: policy must not contain "${key}"`);
  }
  if ("recovery" in policy && !isValidSetting(policy.recovery, true)) return invalid("REQ-6-4: recovery must be \"any\", \"majority\", \"all\" or an integer k >= 1");
  if ("removal" in policy && !isValidSetting(policy.removal, true)) return invalid("REQ-6-4: removal must be \"any\", \"majority\", \"all\" or an integer k >= 1");
  if ("membership" in policy && !isValidSetting(policy.membership, false)) return invalid("REQ-6-4: membership must be \"majority\", \"all\" or an integer k >= 1");
  if ("deactivation" in policy) {
    const d = policy.deactivation;
    if (!isPlainObject(d) || !hasExactMembers(d, ["by", "threshold"])) return invalid("REQ-6-5: deactivation must contain exactly by and threshold");
    if (!["self", "guardians", "either", "both"].includes(d.by as string)) return invalid("REQ-6-5: deactivation.by must be self, guardians, either or both");
    if (!isValidSetting(d.threshold, false)) return invalid("REQ-6-5: deactivation.threshold must be \"majority\", \"all\" or an integer k >= 1");
  }
  return VALID;
}

/** REQ-7-5/REQ-7-6: a create operation's own members. */
export function checkCreateShape(op: Record<string, unknown>): ShapeResult {
  if (!hasExactMembers(op, ["type", "did", "keys", "guardians", "policy", "services", "alsoKnownAs", "prev", "proof"])) {
    return invalid("REQ-7-5: a create operation must contain exactly type, did, keys, guardians, policy, services, alsoKnownAs, prev and proof");
  }
  if (typeof op.did !== "string" || !parseGuardianDid(op.did)) return invalid("REQ-4-1: did must be a valid did:guardian identifier");
  const keysShape = checkKeysShape(op.keys);
  if (!keysShape.valid) return keysShape;
  const guardiansShape = checkGuardiansShape(op.guardians, op.did as Did);
  if (!guardiansShape.valid) return guardiansShape;
  const policyShape = checkPolicyShape(op.policy);
  if (!policyShape.valid) return policyShape;
  const servicesShape = checkServiceShape(op.services);
  if (!servicesShape.valid) return servicesShape;
  const alsoKnownAsShape = checkAlsoKnownAsShape(op.alsoKnownAs);
  if (!alsoKnownAsShape.valid) return alsoKnownAsShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-7/REQ-7-8: an update operation's own members. */
export function checkUpdateShape(op: Record<string, unknown>): ShapeResult {
  if (!hasExactMembers(op, ["type", "keys", "services", "alsoKnownAs", "prev", "proof"])) {
    return invalid("REQ-7-7: an update operation must contain exactly type, keys, services, alsoKnownAs, prev and proof");
  }
  const keysShape = checkKeysShape(op.keys);
  if (!keysShape.valid) return keysShape;
  const servicesShape = checkServiceShape(op.services);
  if (!servicesShape.valid) return servicesShape;
  const alsoKnownAsShape = checkAlsoKnownAsShape(op.alsoKnownAs);
  if (!alsoKnownAsShape.valid) return alsoKnownAsShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-9/REQ-7-10/REQ-7-11: an addGuardian operation's own members. `guardian` against the state before the operation (REQ-7-10) is checked by rules.ts, which has that state. */
export function checkAddGuardianShape(op: Record<string, unknown>): ShapeResult {
  if (!hasExactMembers(op, ["type", "guardian", "prev", "proof"])) {
    return invalid("REQ-7-9: an addGuardian operation must contain exactly type, guardian, prev and proof");
  }
  if (typeof op.guardian !== "string" || !parseGuardianDid(op.guardian)) return invalid("REQ-4-1: guardian must be a valid did:guardian identifier");
  return checkProofArrayShape(op.proof);
}

/** REQ-7-12/REQ-7-13/REQ-7-15: a removeGuardian operation's own members. `guardian` against the state before the operation (REQ-7-13) and `evidence` (REQ-7-14) are checked by rules.ts, which can resolve logs. */
export function checkRemoveGuardianShape(op: Record<string, unknown>): ShapeResult {
  const hasEvidence = "evidence" in op;
  const members = hasEvidence ? ["type", "guardian", "evidence", "prev", "proof"] : ["type", "guardian", "prev", "proof"];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-12: a removeGuardian operation must contain exactly type, guardian, prev and proof, and may contain evidence");
  }
  if (typeof op.guardian !== "string" || !parseGuardianDid(op.guardian)) return invalid("REQ-4-1: guardian must be a valid did:guardian identifier");
  if (hasEvidence && typeof op.evidence !== "string") return invalid("REQ-7-14: evidence must be an operation hash");
  return checkProofArrayShape(op.proof);
}

/** REQ-7-16/REQ-7-17: a setPolicy operation's own members. */
export function checkSetPolicyShape(op: Record<string, unknown>): ShapeResult {
  if (!hasExactMembers(op, ["type", "policy", "prev", "proof"])) {
    return invalid("REQ-7-16: a setPolicy operation must contain exactly type, policy, prev and proof");
  }
  const policyShape = checkPolicyShape(op.policy);
  if (!policyShape.valid) return policyShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-18/REQ-7-19: a deactivate operation's own members. */
export function checkDeactivateShape(op: Record<string, unknown>): ShapeResult {
  if (!hasExactMembers(op, ["type", "prev", "proof"])) {
    return invalid("REQ-7-18: a deactivate operation must contain exactly type, prev and proof");
  }
  return checkProofArrayShape(op.proof);
}

/** REQ-5-2/REQ-5-3: every number and every string anywhere in the value. */
function checkValuesShape(value: unknown): ShapeResult {
  if (typeof value === "number") return isOperationInteger(value) ? VALID : invalid("REQ-5-2: every number must be an integer between 0 and 2^53 - 1");
  if (typeof value === "string") return isUtf8SafeString(value) ? VALID : invalid("REQ-5-3: every string must be valid UTF-8 with no unpaired surrogates");
  if (Array.isArray(value)) {
    for (const v of value) {
      const r = checkValuesShape(v);
      if (!r.valid) return r;
    }
    return VALID;
  }
  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (!isUtf8SafeString(k)) return invalid("REQ-5-3: every string must be valid UTF-8 with no unpaired surrogates");
      const r = checkValuesShape(v);
      if (!r.valid) return r;
    }
  }
  return VALID;
}

/** REQ-5-1 through REQ-7-19: an operation's full shape, independent of signatures and approvals. */
export function checkOperationShape(op: unknown): ShapeResult {
  const common = checkCommonShape(op);
  if (!common.valid) return common;
  const values = checkValuesShape(op);
  if (!values.valid) return values;
  const o = op as Record<string, unknown>;
  switch (o.type) {
    case "create":
      return checkCreateShape(o);
    case "update":
      return checkUpdateShape(o);
    case "addGuardian":
      return checkAddGuardianShape(o);
    case "removeGuardian":
      return checkRemoveGuardianShape(o);
    case "setPolicy":
      return checkSetPolicyShape(o);
    case "deactivate":
      return checkDeactivateShape(o);
    default:
      return invalid("REQ-7-2: unrecognized operation type");
  }
}
