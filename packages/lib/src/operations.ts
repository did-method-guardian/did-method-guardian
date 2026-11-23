import { canonicalize, contentRef, fromMultibaseBase58btc, multikeyToSpki, sha256Bytes, signRawBytes, verifyRawBytes } from "./crypto.js";
import type { DataIntegrityProof, Did, Entry, Key, Operation, Service } from "./types.js";

/** REQ-5-12 step 1: the document every proof (and the attestation) secures -- the operation with `proof` and `attestation` removed. */
export function securedDocument<T extends object>(op: T): Omit<T, "proof" | "attestation"> {
  const { proof: _proof, attestation: _attestation, ...rest } = op as T & { proof?: unknown; attestation?: unknown };
  return rest;
}

/** REQ-5-10: proofs are sorted by verificationMethod in code-point order. JS string comparison is already UTF-16 code-unit order, which agrees with code-point order for this method's ASCII verificationMethod strings. */
export function sortProofs<P extends { verificationMethod: string }>(proofs: P[]): P[] {
  return [...proofs].sort((a, b) => (a.verificationMethod < b.verificationMethod ? -1 : a.verificationMethod > b.verificationMethod ? 1 : 0));
}

/** REQ-5-6: the hash of the complete operation (nothing removed). */
export function operationHash(op: Operation): Promise<string> {
  return contentRef(op);
}

/** REQ-5-7: the anchor of a log -- the hash of its first operation with proof, attestation, guardians and successor removed. */
export function anchorOf(create: { guardians?: unknown; successor?: unknown }): Promise<string> {
  const { guardians: _guardians, successor: _successor, ...rest } = securedDocument(create) as Record<string, unknown>;
  return contentRef(rest);
}

const PROOF_CONFIG = { type: "DataIntegrityProof" as const, cryptosuite: "ecdsa-jcs-2019" as const, proofPurpose: "capabilityInvocation" as const };

/** REQ-5-12 steps 2-4: the signed data for ecdsa-jcs-2019 -- SHA-256(JCS(proof config)) followed by SHA-256(JCS(secured document)). */
async function signingInput(securedDoc: unknown, verificationMethod: string, cryptosuite: string): Promise<Uint8Array> {
  const proofConfig = { type: "DataIntegrityProof" as const, cryptosuite, verificationMethod, proofPurpose: "capabilityInvocation" as const };
  const configHash = await sha256Bytes(new TextEncoder().encode(canonicalize(proofConfig)));
  const docHash = await sha256Bytes(new TextEncoder().encode(canonicalize(securedDoc)));
  const input = new Uint8Array(configHash.length + docHash.length);
  input.set(configHash, 0);
  input.set(docHash, configHash.length);
  return input;
}

/** REQ-5-11/REQ-5-12/REQ-5-13: builds a proof over `op`'s secured document for `key`. */
export async function createProof(op: unknown, key: Key, privateKeyB64url: string): Promise<DataIntegrityProof> {
  const verificationMethod = keyReferenceVerificationMethod(key);
  const proofValue = await signRawBytes(await signingInput(securedDocument(op as object), verificationMethod, PROOF_CONFIG.cryptosuite), privateKeyB64url);
  return { ...PROOF_CONFIG, verificationMethod, proofValue };
}

/** REQ-7-9: builds the registrar's attestation over `op`'s secured document, naming its own current version and key index. */
export async function createAttestation(op: unknown, rootDid: string, version: string, index: number, privateKeyB64url: string): Promise<DataIntegrityProof> {
  const verificationMethod = `${rootDid}?versionId=${version}#key-${index}`;
  const proofValue = await signRawBytes(await signingInput(securedDocument(op as object), verificationMethod, PROOF_CONFIG.cryptosuite), privateKeyB64url);
  return { ...PROOF_CONFIG, verificationMethod, proofValue };
}

/** REQ-5-14: the signature verifies with `key`, over `op`'s secured document. Also used to verify an attestation, given the resolved root key and version (REQ-11-2) -- cryptosuite is read from the proof itself since REQ-7-9 allows it to differ. */
export async function verifyProofSignature(op: unknown, proof: DataIntegrityProof, key: Key): Promise<boolean> {
  if (proof.cryptosuite !== "ecdsa-jcs-2019") return false; // this library implements only ecdsa-jcs-2019; REQ-8-1/REQ-11-2 report "unsupported" at the caller, before ever reaching this
  return verifyRawBytes(await signingInput(securedDocument(op as object), proof.verificationMethod, proof.cryptosuite), proof.proofValue, key);
}

const KEY_REFERENCE_RE = /^did:key:(z[^#]+)#(z[^#]+)$/;

/** REQ-5-11: an ordinary proof's verificationMethod is always a key reference. Returns the key, or undefined if it doesn't match that form. */
export function keyOfVerificationMethod(vm: string): Key | undefined {
  const m = KEY_REFERENCE_RE.exec(vm);
  if (!m || m[1] !== m[2]) return undefined;
  return m[1];
}

/** REQ-5-11: the key reference verificationMethod for `key`. */
export function keyReferenceVerificationMethod(key: Key): string {
  return `did:key:${key}#${key}`;
}

export interface ShapeResult {
  valid: boolean;
  reason?: string;
}

export const invalid = (reason: string): ShapeResult => ({ valid: false, reason });
export const VALID: ShapeResult = { valid: true };

const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** RFC 7493 (I-JSON) forbids an unpaired surrogate and a Unicode noncharacter (U+FDD0-U+FDEF, or any code point ending 0xFFFE/0xFFFF). */
function isNoncharacter(codePoint: number): boolean {
  return (codePoint >= 0xfdd0 && codePoint <= 0xfdef) || (codePoint & 0xfffe) === 0xfffe;
}

function isUtf8SafeString(value: unknown): boolean {
  if (typeof value !== "string") return false;
  if (LONE_SURROGATE_RE.test(value)) return false;
  for (const ch of value) if (isNoncharacter(ch.codePointAt(0)!)) return false;
  return true;
}

function isOperationInteger(value: unknown): boolean {
  // F-4 (audit): -0 passes `Number.isInteger` and `-0 >= 0` (both true
  // in JS, since -0 === 0 numerically), so this used to accept it here
  // only for assertJCSSafe to throw on it later, during
  // canonicalization -- turning a clean "invalid" into an uncaught
  // 500. Object.is distinguishes -0 from 0, which neither
  // Number.isInteger nor a plain >= comparison can.
  return typeof value === "number" && Number.isInteger(value) && !Object.is(value, -0) && value >= 0 && value <= 2 ** 53 - 1;
}

/** REQ-5-2/REQ-5-1 (I-JSON has no unpaired surrogates): every number and every string anywhere in the value. */
export function checkValuesShape(value: unknown): ShapeResult {
  if (typeof value === "number") return isOperationInteger(value) ? VALID : invalid("REQ-5-2: every number must be an integer between 0 and 2^53 - 1");
  if (typeof value === "string") return isUtf8SafeString(value) ? VALID : invalid("REQ-5-1: an operation must be I-JSON -- no unpaired surrogates");
  if (Array.isArray(value)) {
    for (const v of value) {
      const r = checkValuesShape(v);
      if (!r.valid) return r;
    }
    return VALID;
  }
  if (isPlainObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (!isUtf8SafeString(k)) return invalid("REQ-5-1: an operation must be I-JSON -- no unpaired surrogates");
      const r = checkValuesShape(v);
      if (!r.valid) return r;
    }
  }
  return VALID;
}

/** REQ-5-11: every proof's own shape, independent of whether its signature verifies. `allowAnyCryptosuite` is set for the attestation (REQ-7-9). */
export function checkProofShape(proof: unknown, allowAnyCryptosuite = false): ShapeResult {
  if (!isPlainObject(proof)) return invalid("REQ-5-11: a proof must be an object");
  const keys = Object.keys(proof).sort();
  const expected = ["cryptosuite", "proofPurpose", "proofValue", "type", "verificationMethod"];
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    return invalid("REQ-5-11: a proof must contain exactly type, cryptosuite, verificationMethod, proofPurpose and proofValue");
  }
  if (proof.type !== "DataIntegrityProof") return invalid('REQ-5-11: proof.type must be "DataIntegrityProof"');
  if (typeof proof.cryptosuite !== "string") return invalid("REQ-5-11: proof.cryptosuite must be a string");
  // A cryptosuite this library doesn't implement is a REQ-8-1 "unsupported"
  // condition, checked by the caller before the ordinary steps -- never a
  // shape violation (REQ-5-11 requires only that it be a string; the
  // specific value "ecdsa-jcs-2019" is this method's one defined
  // cryptosuite, not a shape constraint on every proof everywhere -- REQ-7-9
  // lets the attestation use another).
  if (proof.proofPurpose !== "capabilityInvocation") return invalid('REQ-5-11: proofPurpose must be "capabilityInvocation"');
  if (typeof proof.proofValue !== "string") return invalid("REQ-5-11: proofValue must be a string");
  if (typeof proof.verificationMethod !== "string") return invalid("REQ-5-11: verificationMethod must be a string");
  if (!allowAnyCryptosuite && !keyOfVerificationMethod(proof.verificationMethod)) {
    return invalid("REQ-5-11: verificationMethod must be a did:key reference");
  }
  return VALID;
}

/** REQ-8-1: this library implements only ecdsa-jcs-2019. A proof naming any other cryptosuite makes the operation it's on unsupported, never invalid. */
export const SUPPORTED_CRYPTOSUITE = "ecdsa-jcs-2019";
export function isSupportedCryptosuite(cryptosuite: string): boolean {
  return cryptosuite === SUPPORTED_CRYPTOSUITE;
}

/** REQ-8-1: the operation types this library implements. */
const SUPPORTED_OPERATION_TYPES = new Set(["create", "update", "addGuardian", "updateGuardian", "removeGuardian", "setPolicy", "acceptWard", "releaseWard", "deactivate"]);
export function isSupportedOperationType(type: string): boolean {
  return SUPPORTED_OPERATION_TYPES.has(type);
}

/**
 * REQ-7-29/REQ-7-33 through 7-35/REQ-8-1: a toy extension, for
 * conformance testing only (README: "the toy extension"). It is not
 * part of the did:guardian method, and production code never
 * implements it -- `verifyLog`/`resolve`/`checkAcceptance` all default
 * to implementing no extensions at all; a caller opts into this one by
 * passing `new Set([MIN_KEYS_EXTENSION])` explicitly, which only tests
 * do.
 */
export const MIN_KEYS_EXTENSION = "https://example.org/ext/min-keys";

/**
 * The toy extension's own rule (REQ-7-33/7-35), checked against a state
 * once `MIN_KEYS_EXTENSION` is in its `critical` (REQ-7-31): the state
 * MUST have at least `k` keys, and removing the configuration is
 * invalid -- so the configuration must still be present, shaped
 * `{"k": <integer 1-8>}`.
 */
export function checkMinKeysExtension(state: { critical: string[]; policy: { extensions?: Record<string, unknown> }; keys: Key[] }): ShapeResult {
  if (!state.critical.includes(MIN_KEYS_EXTENSION)) return VALID;
  const config = state.policy.extensions?.[MIN_KEYS_EXTENSION];
  if (config === undefined) return invalid(`REQ-7-35: ${MIN_KEYS_EXTENSION} -- removing the configuration is invalid`);
  if (!isPlainObject(config) || !hasExactMembers(config, ["k"]) || typeof config.k !== "number" || !Number.isInteger(config.k) || config.k < 1 || config.k > 8) {
    return invalid(`REQ-7-29: ${MIN_KEYS_EXTENSION} configuration must be {"k": <integer 1-8>}`);
  }
  if (state.keys.length < config.k) return invalid(`REQ-7-33: ${MIN_KEYS_EXTENSION} requires at least ${config.k} keys`);
  return VALID;
}

/** REQ-5-10/REQ-5-15: the `proof` member's own array shape (sorted, no duplicate keys), independent of each proof's own shape or validity. */
export function checkProofArrayShape(proof: unknown): ShapeResult {
  if (!Array.isArray(proof)) return invalid("REQ-5-10: proof must be an array");
  for (const p of proof) {
    const shape = checkProofShape(p);
    if (!shape.valid) return shape;
  }
  const vms = (proof as DataIntegrityProof[]).map((p) => p.verificationMethod);
  const sorted = [...vms].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (JSON.stringify(vms) !== JSON.stringify(sorted)) return invalid("REQ-5-10: proof must be sorted by verificationMethod in code-point order");
  const keys = (proof as DataIntegrityProof[]).map((p) => keyOfVerificationMethod(p.verificationMethod));
  if (new Set(keys).size !== keys.length) return invalid("REQ-5-15: an operation must not contain two proofs from the same key");
  return VALID;
}

/** REQ-5-8/REQ-5-9: a Multikey-encoded P-256 public key, decoding to a point on the curve. */
export function isValidKey(key: unknown): boolean {
  if (typeof key !== "string") return false;
  try {
    multikeyToSpki(key);
    return true;
  } catch {
    return false;
  }
}

/** REQ-5-6: a hash -- a sha2-256 multihash, base58btc-encoded with the multibase prefix "z". Used wherever a member is specifically a hash (entry.anchor, entry.consent, removeGuardian.evidence), as opposed to any opaque string. */
export function isValidHash(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const bytes = fromMultibaseBase58btc(value);
    return bytes.length === 34 && bytes[0] === 0x12 && bytes[1] === 0x20;
  } catch {
    return false;
  }
}

// F-7 (audit): RFC 3986's own grammar restricts every part of a URI
// (after the scheme) to unreserved characters, reserved (gen-delims +
// sub-delims) characters, and pct-encoded triplets -- `\S` (anything
// non-whitespace) and `[^\s#]` (the previous patterns here) both
// accepted far more than that: "{}", "|", "<", "\", """ and non-ASCII
// characters like "é" all matched, and a malformed pct-encoding like
// "%zz" was accepted outright rather than rejected for not being a
// real pct-encoded octet.
const PCT_ENCODED = "%[0-9A-Fa-f]{2}";
const URI_CHAR = `(?:${PCT_ENCODED}|[A-Za-z0-9\\-._~!$&'()*+,;=:/?#@\\[\\]])`;
const URI_RE = new RegExp(`^[a-zA-Z][a-zA-Z0-9+.-]*:${URI_CHAR}*$`);
const ABSOLUTE_URI_CHAR = `(?:${PCT_ENCODED}|[A-Za-z0-9\\-._~!$&'()*+,;=:/?@\\[\\]])`; // same, minus "#" -- an absolute URI has no fragment

/** A URI (RFC 3986) -- requires at least a scheme, since this library has no need to resolve relative references. */
export function isValidUri(value: unknown): value is string {
  return typeof value === "string" && URI_RE.test(value);
}

const FRAGMENT_CHAR = `(?:${PCT_ENCODED}|[A-Za-z0-9\\-._~!$&'()*+,;=:@/?])`;
const FRAGMENT_CHARS_RE = new RegExp(`^${FRAGMENT_CHAR}*$`);

/** A DID URL fragment (RFC 3986 fragment grammar, minus "#"): unreserved / pct-encoded / sub-delims / ":" / "@" / "/" / "?". RFC 3986's fragment is zero or more of these -- "#" alone (an empty fragment) is valid. */
export function isValidFragment(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("#") && FRAGMENT_CHARS_RE.test(value.slice(1));
}

/** REQ-6-1: keys, 1 to 8 distinct entries. */
export function checkKeysShape(keys: unknown): ShapeResult {
  if (!Array.isArray(keys)) return invalid("keys must be an array");
  if (keys.length < 1 || keys.length > 8) return invalid("REQ-6-1: keys must contain 1 to 8 entries");
  if (keys.some((k) => !isValidKey(k))) return invalid("REQ-5-8: every key must be a Multikey-encoded P-256 public key");
  if (new Set(keys).size !== keys.length) return invalid("REQ-6-1: keys must be distinct");
  return VALID;
}

/**
 * F-1 (audit): two entries are the same entry only if every member
 * matches -- `did` alone used to stand in for the whole entry when
 * deciding whether a `setPolicy` "names a new successor" (REQ-7-6) or
 * "adds or replaces an entry" (REQ-10-7). A same-DID entry with a
 * changed `anchor`, `consent` or `keys` IS a different entry (a
 * refreshed consent after a release, say, or new keys installed with
 * no proof of possession) and must go through the same checks a
 * genuinely new successor would. (Lives here, not alongside resolve.ts's
 * own sameKeys, because rules.ts needs it too and already sits
 * underneath resolve.ts in the import graph -- importing the other way
 * would cycle through verifyLog.ts.)
 */
export function sameEntry(a: Entry, b: Entry): boolean {
  if (a.did !== b.did || a.anchor !== b.anchor || a.consent !== b.consent) return false;
  if (a.keys.length !== b.keys.length) return false;
  const bKeys = new Set(b.keys);
  return a.keys.every((k) => bKeys.has(k));
}

/** REQ-6-2: an entry. */
export function checkEntryShape(entry: unknown): ShapeResult {
  if (!isPlainObject(entry)) return invalid("REQ-6-2: an entry must be an object");
  if (!hasExactMembers(entry, ["did", "anchor", "keys", "consent"])) return invalid("REQ-6-2: an entry must contain exactly did, anchor, keys and consent");
  const didShape = checkDidShape(entry.did, "entry.did");
  if (!didShape.valid) return didShape;
  if (!isValidHash(entry.anchor)) return invalid("REQ-6-2: entry.anchor must be a hash");
  const keysShape = checkKeysShape(entry.keys);
  if (!keysShape.valid) return keysShape;
  if (!isValidHash(entry.consent)) return invalid("REQ-6-2: entry.consent must be a hash");
  return VALID;
}

/** REQ-6-4: a ward record. */
export function checkWardRecordShape(record: unknown): ShapeResult {
  if (!isPlainObject(record)) return invalid("REQ-6-4: a ward record must be an object");
  if (!hasExactMembers(record, ["did", "anchor"])) return invalid("REQ-6-4: a ward record must contain exactly did and anchor");
  const didShape = checkDidShape(record.did, "ward.did");
  if (!didShape.valid) return didShape;
  if (!isValidHash(record.anchor)) return invalid("REQ-6-4: ward.anchor must be a hash");
  return VALID;
}

/** REQ-6-1/REQ-6-5: guardians, 0 to 32 entries with distinct DIDs, none equal to `selfDid`. */
export function checkGuardiansShape(guardians: unknown, selfDid?: Did): ShapeResult {
  if (!Array.isArray(guardians)) return invalid("guardians must be an array");
  if (guardians.length > 32) return invalid("REQ-6-1: guardians must contain at most 32 entries");
  const dids = new Set<string>();
  for (const g of guardians) {
    const shape = checkEntryShape(g);
    if (!shape.valid) return shape;
    const entry = g as Entry;
    if (dids.has(entry.did)) return invalid("REQ-6-1: guardians must have distinct DIDs");
    dids.add(entry.did);
    if (selfDid !== undefined && entry.did === selfDid) return invalid("REQ-6-5: an identity's DID must not appear in its own guardians");
  }
  return VALID;
}

/** REQ-6-1: wards, distinct DIDs, none equal to `selfDid`. */
export function checkWardsShape(wards: unknown, selfDid?: Did): ShapeResult {
  if (!Array.isArray(wards)) return invalid("wards must be an array");
  const dids = new Set<string>();
  for (const w of wards) {
    const shape = checkWardRecordShape(w);
    if (!shape.valid) return shape;
    const record = w as { did: Did };
    if (dids.has(record.did)) return invalid("REQ-6-1: wards must have distinct DIDs");
    dids.add(record.did);
    if (selfDid !== undefined && record.did === selfDid) return invalid("REQ-6-5: an identity's DID must not appear in its own wards");
  }
  return VALID;
}

/** REQ-6-6. */
export function checkServiceShape(services: unknown): ShapeResult {
  if (!Array.isArray(services)) return invalid("services must be an array");
  if (services.length > 32) return invalid("REQ-6-1: services must contain at most 32 entries");
  const ids = new Set<string>();
  for (const s of services) {
    if (!isPlainObject(s)) return invalid("REQ-6-6: a service must be an object");
    if (!hasExactMembers(s, ["id", "type", "serviceEndpoint"])) return invalid("REQ-6-6: a service must contain exactly id, type and serviceEndpoint");
    if (!isValidFragment(s.id)) return invalid('REQ-6-6: service.id must be "#" followed by a DID URL fragment');
    if (typeof s.type !== "string") return invalid("REQ-6-6: service.type must be a string");
    if (!isValidUri(s.serviceEndpoint)) return invalid("REQ-6-6: service.serviceEndpoint must be a URI");
    if (ids.has(s.id)) return invalid("REQ-6-1: two services must not have the same id");
    ids.add(s.id);
  }
  return VALID;
}

/** REQ-6-1: alsoKnownAs, 0 to 32 distinct URIs. */
export function checkAlsoKnownAsShape(alsoKnownAs: unknown): ShapeResult {
  if (!Array.isArray(alsoKnownAs)) return invalid("alsoKnownAs must be an array");
  if (alsoKnownAs.length > 32) return invalid("REQ-6-1: alsoKnownAs must contain at most 32 entries");
  if (alsoKnownAs.some((a) => !isValidUri(a))) return invalid("REQ-6-1: alsoKnownAs must be URIs");
  if (new Set(alsoKnownAs).size !== alsoKnownAs.length) return invalid("REQ-6-1: alsoKnownAs must be distinct");
  return VALID;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function hasExactMembers(op: Record<string, unknown>, members: readonly string[]): boolean {
  const keys = Object.keys(op).sort();
  const expected = [...members].sort();
  return keys.length === expected.length && keys.every((k, i) => k === expected[i]);
}

const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const LAST_LABEL_NUMERIC_RE = /^[0-9]+$/;
const NAME_RE = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;

/** REQ-4-2: a DNS hostname of two or more labels, lowercase, at most 253 characters, with a non-numeric last label. */
export function isValidDomain(domain: string): boolean {
  if (domain.length > 253) return false;
  const labels = domain.split(".");
  if (labels.length < 2) return false;
  if (labels.some((l) => !DOMAIN_RE.test(l))) return false;
  if (LAST_LABEL_NUMERIC_RE.test(labels[labels.length - 1])) return false;
  return true;
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

/** REQ-4-1/REQ-4-2/REQ-4-3: a did:guardian identifier's shape, reporting the specific requirement a malformed value violates. */
export function checkDidShape(value: unknown, member: string): ShapeResult {
  if (typeof value !== "string") return invalid(`REQ-4-1: ${member} must be a string`);
  const parts = value.split(":");
  if (parts[0] !== "did" || parts[1] !== "guardian" || (parts.length !== 3 && parts.length !== 4)) {
    return invalid(`REQ-4-1: ${member} must match did:guardian:<domain> or did:guardian:<domain>:<name>`);
  }
  if (!isValidDomain(parts[2])) return invalid(`REQ-4-2: ${member}'s domain must be a valid DNS hostname`);
  if (parts.length === 4 && !isValidName(parts[3])) return invalid(`REQ-4-3: ${member}'s name must be 3 to 32 characters from a-z, 0-9 and -, beginning and ending with a letter or digit`);
  return VALID;
}

const SETTING_WITH_ANY = new Set(["any", "majority", "all"]);
const SETTING_NO_ANY = new Set(["majority", "all"]);

function isValidSetting(value: unknown, allowAny: boolean): boolean {
  if (typeof value === "number") return Number.isInteger(value) && value >= 1 && value <= 32;
  if (typeof value !== "string") return false;
  return allowAny ? SETTING_WITH_ANY.has(value) : SETTING_NO_ANY.has(value);
}

// RFC 3986 absolute-URI: scheme ":" hier-part [ "?" query ] -- no fragment, unlike an ordinary URI reference. F-7 (audit): same character-class fix as isValidUri, above.
const ABSOLUTE_URI_RE = new RegExp(`^[a-zA-Z][a-zA-Z0-9+.-]*:${ABSOLUTE_URI_CHAR}*$`);

/** REQ-7-29: `extensions` is an object whose member names are absolute URIs. */
export function checkExtensionsShape(extensions: unknown): ShapeResult {
  if (!isPlainObject(extensions)) return invalid("REQ-7-29: extensions must be an object");
  for (const name of Object.keys(extensions)) {
    if (!ABSOLUTE_URI_RE.test(name)) return invalid("REQ-7-29: an extension name must be an absolute URI");
  }
  return VALID;
}

/** REQ-7-30: `critical` is a non-empty list of distinct extension names, each a member of this same operation's `policy.extensions`. */
export function checkCriticalShape(critical: unknown, policyExtensions: Record<string, unknown> | undefined): ShapeResult {
  if (!Array.isArray(critical) || critical.length === 0) return invalid("REQ-7-30: critical must be a non-empty list");
  if (critical.some((c) => typeof c !== "string")) return invalid("REQ-7-30: critical must be a list of extension names");
  if (new Set(critical).size !== critical.length) return invalid("REQ-7-30: critical must be a list of distinct names");
  for (const name of critical) {
    if (!policyExtensions || !(name in policyExtensions)) return invalid("REQ-7-30: each name in critical must be a member of this operation's policy.extensions");
  }
  return VALID;
}

/** REQ-6-11/REQ-6-12/REQ-6-13/REQ-6-14: a policy object's own shape, independent of any operation type. `hasSuccessor` is whether this operation's own `successor` is an entry (REQ-6-14). */
export function checkPolicyShape(policy: unknown, hasSuccessor: boolean): ShapeResult {
  if (!isPlainObject(policy)) return invalid("REQ-6-11: policy must be an object");
  const allowed = ["recovery", "membership", "removal", "deactivation", "orphan", "maxWards", "extensions"];
  for (const key of Object.keys(policy)) {
    if (!allowed.includes(key)) return invalid(`REQ-6-11: policy must not contain "${key}"`);
  }
  if ("recovery" in policy && !isValidSetting(policy.recovery, true)) return invalid("REQ-6-11/REQ-6-13: recovery must be \"any\", \"majority\", \"all\" or an integer k from 1 to 32");
  if ("removal" in policy && !isValidSetting(policy.removal, true)) return invalid("REQ-6-11/REQ-6-13: removal must be \"any\", \"majority\", \"all\" or an integer k from 1 to 32");
  if ("membership" in policy && !isValidSetting(policy.membership, false)) return invalid("REQ-6-11/REQ-6-13: membership must be \"majority\", \"all\" or an integer k from 1 to 32");
  if ("deactivation" in policy) {
    const d = policy.deactivation;
    if (!isPlainObject(d) || !hasExactMembers(d, ["by", "threshold"])) return invalid("REQ-6-12: deactivation must contain exactly by and threshold");
    if (!["self", "guardians", "either", "both"].includes(d.by as string)) return invalid("REQ-6-12: deactivation.by must be self, guardians, either or both");
    if (!isValidSetting(d.threshold, false)) return invalid("REQ-6-12/REQ-6-13: deactivation.threshold must be \"majority\", \"all\" or an integer k from 1 to 32");
  }
  const orphan = (policy as { orphan?: unknown }).orphan;
  if ("orphan" in policy && !["deactivate", "independent", "successor"].includes(orphan as string)) {
    return invalid("REQ-6-11: orphan must be deactivate, independent or successor");
  }
  const effectiveOrphan = orphan ?? "deactivate";
  if (hasSuccessor && effectiveOrphan !== "successor") return invalid("REQ-6-14: orphan must be successor if successor is an entry");
  if (!hasSuccessor && effectiveOrphan === "successor") return invalid("REQ-6-14: orphan must not be successor if successor is null");
  if ("maxWards" in policy) {
    const maxWards = (policy as { maxWards?: unknown }).maxWards;
    if (typeof maxWards !== "number" || !Number.isInteger(maxWards) || maxWards < 1) return invalid("REQ-6-11: maxWards must be an integer k >= 1");
  }
  if ("extensions" in policy) {
    const extShape = checkExtensionsShape((policy as { extensions?: unknown }).extensions);
    if (!extShape.valid) return extShape;
  }
  return VALID;
}

/** REQ-5-3: validates the optional extensions/critical members shared across operation types, given which members this op actually carries and which types may carry `critical` (REQ-7-30: only create and setPolicy). */
function checkSharedOptionalMembers(op: Record<string, unknown>, allowCritical: boolean, policyExtensions: Record<string, unknown> | undefined): ShapeResult {
  if ("extensions" in op) {
    const shape = checkExtensionsShape(op.extensions);
    if (!shape.valid) return shape;
  }
  if ("critical" in op) {
    if (!allowCritical) return invalid("REQ-7-30: only create or setPolicy may contain critical");
    const shape = checkCriticalShape(op.critical, policyExtensions);
    if (!shape.valid) return shape;
  }
  return VALID;
}

/** REQ-7-7/REQ-7-8/REQ-7-9. */
export function checkCreateShape(op: Record<string, unknown>): ShapeResult {
  const hasAttestation = "attestation" in op;
  const hasCritical = "critical" in op;
  const hasExtensions = "extensions" in op;
  const required = ["type", "did", "keys", "guardians", "successor", "policy", "services", "alsoKnownAs", "prev", "proof"];
  const members = [...required, ...(hasAttestation ? ["attestation"] : []), ...(hasCritical ? ["critical"] : []), ...(hasExtensions ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-7: a create operation must contain exactly type, did, keys, guardians, successor, policy, services, alsoKnownAs, prev and proof, and attestation unless it creates the root identity");
  }
  const didShape = checkDidShape(op.did, "did");
  if (!didShape.valid) return didShape;
  const keysShape = checkKeysShape(op.keys);
  if (!keysShape.valid) return keysShape;
  const guardiansShape = checkGuardiansShape(op.guardians, op.did as Did);
  if (!guardiansShape.valid) return guardiansShape;
  if (op.successor !== null) {
    const successorShape = checkEntryShape(op.successor);
    if (!successorShape.valid) return successorShape;
    const successor = op.successor as Entry;
    if (successor.did === (op.did as Did)) return invalid("REQ-6-5: an identity's DID must not appear in its own successor");
    if ((op.guardians as Entry[]).some((g) => g.did === successor.did)) return invalid("REQ-6-5: the DID of successor must not appear in guardians");
  }
  const policyShape = checkPolicyShape(op.policy, op.successor !== null);
  if (!policyShape.valid) return policyShape;
  const servicesShape = checkServiceShape(op.services);
  if (!servicesShape.valid) return servicesShape;
  const alsoKnownAsShape = checkAlsoKnownAsShape(op.alsoKnownAs);
  if (!alsoKnownAsShape.valid) return alsoKnownAsShape;
  const keyOverlap = checkKeyOverlap(op.keys as Key[], op.guardians as Entry[], op.successor as Entry | null);
  if (!keyOverlap.valid) return keyOverlap;
  const domain = parseGuardianDid(op.did as Did)!.domain;
  const isRoot = (op.did as Did) === `did:guardian:${domain}`;
  if (isRoot && hasAttestation) return invalid("REQ-7-7: the create of a root identity must not contain attestation");
  if (!isRoot && !hasAttestation) return invalid("REQ-7-7: the create of a non-root identity must contain attestation");
  if (hasAttestation) {
    const attestationShape = checkProofShape(op.attestation, true);
    if (!attestationShape.valid) return attestationShape;
    const vm = (op.attestation as DataIntegrityProof).verificationMethod;
    if (!new RegExp(`^did:guardian:${escapeRegExp(domain)}\\?versionId=[^#]+#key-(0|[1-9][0-9]*)$`).test(vm)) {
      return invalid("REQ-7-9: attestation.verificationMethod must be did:guardian:<domain-of-did>?versionId=<version>#key-<n>");
    }
  }
  const extensions = (op as { extensions?: Record<string, unknown> }).extensions;
  const policyExtensions = (op.policy as { extensions?: Record<string, unknown> }).extensions;
  const sharedShape = checkSharedOptionalMembers(op, true, policyExtensions);
  if (!sharedShape.valid) return sharedShape;
  void extensions;
  return checkProofArrayShape(op.proof);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** REQ-6-3: a key must not appear more than once across keys, the keys of every guardian entry, and the keys of successor. */
export function checkKeyOverlap(keys: Key[], guardians: Entry[], successor: Entry | null): ShapeResult {
  const seen = new Set<Key>();
  for (const k of keys) {
    if (seen.has(k)) return invalid("REQ-6-3: a key must not appear more than once");
    seen.add(k);
  }
  for (const g of guardians) {
    for (const k of g.keys) {
      if (seen.has(k)) return invalid("REQ-6-3: a key must not appear more than once");
      seen.add(k);
    }
  }
  if (successor) {
    for (const k of successor.keys) {
      if (seen.has(k)) return invalid("REQ-6-3: a key must not appear more than once");
      seen.add(k);
    }
  }
  return VALID;
}

/** REQ-7-10/REQ-7-11. */
export function checkUpdateShape(op: Record<string, unknown>): ShapeResult {
  const members = ["type", "keys", "services", "alsoKnownAs", "prev", "proof", ...("extensions" in op ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-10: an update operation must contain exactly type, keys, services, alsoKnownAs, prev and proof");
  }
  const keysShape = checkKeysShape(op.keys);
  if (!keysShape.valid) return keysShape;
  const servicesShape = checkServiceShape(op.services);
  if (!servicesShape.valid) return servicesShape;
  const alsoKnownAsShape = checkAlsoKnownAsShape(op.alsoKnownAs);
  if (!alsoKnownAsShape.valid) return alsoKnownAsShape;
  const sharedShape = checkSharedOptionalMembers(op, false, undefined);
  if (!sharedShape.valid) return sharedShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-12/REQ-7-14. REQ-7-13 (entry.did must not already be a guardian) needs the state before the operation; checked by document.ts/rules.ts. */
export function checkAddGuardianShape(op: Record<string, unknown>): ShapeResult {
  const members = ["type", "entry", "prev", "proof", ...("extensions" in op ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-12: an addGuardian operation must contain exactly type, entry, prev and proof");
  }
  const entryShape = checkEntryShape(op.entry);
  if (!entryShape.valid) return entryShape;
  const sharedShape = checkSharedOptionalMembers(op, false, undefined);
  if (!sharedShape.valid) return sharedShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-15/REQ-7-16. "guardian is the DID of a current guardian or of the successor" needs state; checked by document.ts/rules.ts. */
export function checkUpdateGuardianShape(op: Record<string, unknown>): ShapeResult {
  const members = ["type", "guardian", "keys", "prev", "proof", ...("extensions" in op ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-15: an updateGuardian operation must contain exactly type, guardian, keys, prev and proof");
  }
  const didShape = checkDidShape(op.guardian, "guardian");
  if (!didShape.valid) return didShape;
  const keysShape = checkKeysShape(op.keys);
  if (!keysShape.valid) return keysShape;
  const sharedShape = checkSharedOptionalMembers(op, false, undefined);
  if (!sharedShape.valid) return sharedShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-17/REQ-7-18. "guardian is the DID of a current guardian" needs state; checked by document.ts/rules.ts. */
export function checkRemoveGuardianShape(op: Record<string, unknown>): ShapeResult {
  const hasEvidence = "evidence" in op;
  const members = ["type", "guardian", "prev", "proof", ...(hasEvidence ? ["evidence"] : []), ...("extensions" in op ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-17: a removeGuardian operation must contain exactly type, guardian, prev and proof, and may contain evidence");
  }
  const didShape = checkDidShape(op.guardian, "guardian");
  if (!didShape.valid) return didShape;
  if (hasEvidence && !isValidHash(op.evidence)) return invalid("REQ-7-18: evidence must be an operation hash");
  const sharedShape = checkSharedOptionalMembers(op, false, undefined);
  if (!sharedShape.valid) return sharedShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-20/REQ-7-21. */
export function checkSetPolicyShape(op: Record<string, unknown>): ShapeResult {
  const hasCritical = "critical" in op;
  const hasExtensions = "extensions" in op;
  const members = ["type", "policy", "successor", "prev", "proof", ...(hasCritical ? ["critical"] : []), ...(hasExtensions ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-20: a setPolicy operation must contain exactly type, policy, successor, prev and proof");
  }
  if (op.successor !== null) {
    const successorShape = checkEntryShape(op.successor);
    if (!successorShape.valid) return successorShape;
  }
  const policyShape = checkPolicyShape(op.policy, op.successor !== null);
  if (!policyShape.valid) return policyShape;
  const policyExtensions = (op.policy as { extensions?: Record<string, unknown> }).extensions;
  const sharedShape = checkSharedOptionalMembers(op, true, policyExtensions);
  if (!sharedShape.valid) return sharedShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-22/REQ-7-23 (needs state, checked elsewhere). */
export function checkAcceptWardShape(op: Record<string, unknown>): ShapeResult {
  const members = ["type", "ward", "prev", "proof", ...("extensions" in op ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-22: an acceptWard operation must contain exactly type, ward, prev and proof");
  }
  const wardShape = checkWardRecordShape(op.ward);
  if (!wardShape.valid) return wardShape;
  const sharedShape = checkSharedOptionalMembers(op, false, undefined);
  if (!sharedShape.valid) return sharedShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-25 ("ward is the DID of a record in wards" needs state, checked elsewhere). */
export function checkReleaseWardShape(op: Record<string, unknown>): ShapeResult {
  const members = ["type", "ward", "prev", "proof", ...("extensions" in op ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-25: a releaseWard operation must contain exactly type, ward, prev and proof");
  }
  const didShape = checkDidShape(op.ward, "ward");
  if (!didShape.valid) return didShape;
  const sharedShape = checkSharedOptionalMembers(op, false, undefined);
  if (!sharedShape.valid) return sharedShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-27. */
export function checkDeactivateShape(op: Record<string, unknown>): ShapeResult {
  const members = ["type", "prev", "proof", ...("extensions" in op ? ["extensions"] : [])];
  if (!hasExactMembers(op, members)) {
    return invalid("REQ-7-27: a deactivate operation must contain exactly type, prev and proof");
  }
  const sharedShape = checkSharedOptionalMembers(op, false, undefined);
  if (!sharedShape.valid) return sharedShape;
  return checkProofArrayShape(op.proof);
}

/** REQ-7-1/REQ-7-2/REQ-7-3/REQ-7-4: members common to every operation type, checked once. REQ-7-3 (first op is create, no later create) needs the log's own position; checked by verifyLog.ts. */
export function checkCommonShape(op: unknown): ShapeResult {
  if (!isPlainObject(op)) return invalid("REQ-5-1: an operation must be an I-JSON object");
  const valuesShape = checkValuesShape(op);
  if (!valuesShape.valid) return valuesShape;
  if (typeof op.type !== "string" || !["create", "update", "addGuardian", "updateGuardian", "removeGuardian", "setPolicy", "acceptWard", "releaseWard", "deactivate"].includes(op.type)) {
    return invalid("REQ-7-2: type must be one of create, update, addGuardian, updateGuardian, removeGuardian, setPolicy, acceptWard, releaseWard or deactivate");
  }
  if (op.type === "create") {
    if (op.prev !== null) return invalid("REQ-7-4: a create operation's prev must be null");
  } else if (typeof op.prev !== "string") {
    return invalid("REQ-7-4: prev must be the operation hash of the preceding operation");
  }
  return VALID;
}

/** REQ-5-1 through REQ-7-35: an operation's full shape, independent of signatures and approvals. */
export function checkOperationShape(op: unknown): ShapeResult {
  const common = checkCommonShape(op);
  if (!common.valid) return common;
  const o = op as Record<string, unknown>;
  switch (o.type) {
    case "create":
      return checkCreateShape(o);
    case "update":
      return checkUpdateShape(o);
    case "addGuardian":
      return checkAddGuardianShape(o);
    case "updateGuardian":
      return checkUpdateGuardianShape(o);
    case "removeGuardian":
      return checkRemoveGuardianShape(o);
    case "setPolicy":
      return checkSetPolicyShape(o);
    case "acceptWard":
      return checkAcceptWardShape(o);
    case "releaseWard":
      return checkReleaseWardShape(o);
    case "deactivate":
      return checkDeactivateShape(o);
    default:
      return invalid("REQ-7-2: unrecognized operation type");
  }
}

/** REQ-7-5: the keys a proof on this operation is permitted to come from -- a key in `keys`, in an entry in `guardians`, or in `successor`, in the state before the operation; or a key in a list of keys the operation itself introduces. */
export function permittedKeys(op: Operation, stateBefore: { keys: Key[]; guardians: Entry[]; successor: Entry | null }): Set<Key> {
  const keys = new Set<Key>();
  for (const k of stateBefore.keys) keys.add(k);
  for (const g of stateBefore.guardians) for (const k of g.keys) keys.add(k);
  if (stateBefore.successor) for (const k of stateBefore.successor.keys) keys.add(k);
  switch (op.type) {
    case "create":
      for (const k of op.keys) keys.add(k);
      for (const g of op.guardians) for (const k of g.keys) keys.add(k);
      if (op.successor) for (const k of op.successor.keys) keys.add(k);
      break;
    case "update":
      for (const k of op.keys) keys.add(k);
      break;
    case "addGuardian":
      for (const k of op.entry.keys) keys.add(k);
      break;
    case "updateGuardian":
      for (const k of op.keys) keys.add(k);
      break;
    case "setPolicy":
      if (op.successor) for (const k of op.successor.keys) keys.add(k);
      break;
    default:
      break;
  }
  return keys;
}

