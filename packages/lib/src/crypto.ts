// Web Crypto (crypto.subtle) based -- portable across Node.js, browsers, and
// Cloudflare Workers with no runtime-specific dependency and no compat flags.
// Previously used node:crypto directly, which Workers don't have without
// nodejs_compat (and even then, EC sign/verify support isn't guaranteed to
// match real Node). See did-method-guardian#<issue>.

/**
 * RFC 8785 (JSON Canonicalization Scheme): sorted object keys (by UTF-16
 * code unit -- exactly what JS's `<`/`>` string comparison already does,
 * so no special-cased comparator is needed), `JSON.stringify` otherwise.
 * `assertJCSSafe` (below) rules out the input shapes where JCS's own
 * number-serialization rules would otherwise matter (this method never
 * needs a float in signed content, so the simplest fix is to forbid one
 * outright rather than implement ECMA-262 `Number::toString` faithfully).
 */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => [k, sortKeysDeep(v)]),
    );
  }
  return value;
}

const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Rejects the input shapes that would otherwise make RFC 8785's own
 * number-serialization rules (ECMA-262 `Number::toString`) and lone
 * surrogates in strings matter for interop: no non-integer number, no
 * `-0` (serializes as "-0" in JS but "0" under some other JCS
 * implementations), no number outside JS's own safe-integer range (a
 * round-trip through a non-JS implementation could lose precision), and
 * no unpaired UTF-16 surrogate (undefined behavior once re-encoded as
 * UTF-8). None of this method's own operation content ever legitimately
 * needs any of these, so forbidding them outright is simpler than
 * matching every other implementation's number formatting exactly.
 */
export function assertJCSSafe(value: unknown): void {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("JCS: number must be finite");
    if (!Number.isInteger(value)) throw new Error("JCS: floating-point numbers are not allowed");
    if (Object.is(value, -0)) throw new Error("JCS: -0 is not allowed");
    if (!Number.isSafeInteger(value)) throw new Error("JCS: integer exceeds the safe range");
    return;
  }
  if (typeof value === "string") {
    if (LONE_SURROGATE_RE.test(value)) throw new Error("JCS: lone surrogate in string");
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) assertJCSSafe(v);
    return;
  }
  if (value && typeof value === "object") {
    for (const v of Object.values(value as Record<string, unknown>)) assertJCSSafe(v);
  }
}

function bytesToBase64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function sha256(input: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
}

/**
 * REQ-6-4: a sha2-256 multihash (multiformats, code 0x12, length 0x20),
 * base58btc-encoded with the multibase 'z' prefix -- the same encoding
 * `did:webvh` uses for `entryHash`. `value` must already have every
 * proof stripped (operations.ts's `unsecuredDocument`) -- a signature
 * is never deterministic (ECDSA's random nonce, plus the s/(n-s)
 * malleability every signature carries before low-S normalization), so
 * hashing one in would make the result depend on which valid signature
 * happened to be produced, not just on content.
 */
export async function contentRef(value: unknown): Promise<string> {
  assertJCSSafe(value);
  const digest = new Uint8Array(await sha256(canonicalize(value)));
  return multihashEncode(digest);
}

export interface Keypair {
  publicKey: string; // Multikey ('z'-prefixed base58btc) -- Fix 4: the wire format everywhere a public key appears, inside an operation included. SPKI is now purely an internal WebCrypto-import detail, converted to/from at the crypto.ts boundary only.
  privateKey: string; // base64url-encoded PKCS8 -- private keys never appear in any operation's own content, so there's no wire-format pressure on this half; unchanged.
}

const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Multibase ('z'-prefixed base58btc) encoding of a raw byte string -- used for both Multikey values and Data Integrity `proofValue`s, the two places this method's wire format uses multibase. */
export function toMultibaseBase58btc(bytes: Uint8Array): string {
  return "z" + base58btcEncode(bytes);
}

export function fromMultibaseBase58btc(s: string): Uint8Array {
  if (!s.startsWith("z")) throw new Error("expected a 'z'-prefixed (base58btc) multibase string");
  return base58btcDecode(s.slice(1));
}

const SHA2_256_MULTIHASH_CODE = 0x12; // single-byte varint
const SHA256_DIGEST_LENGTH = 0x20; // single-byte varint

/** sha2-256 multihash (multiformats): code || length || digest, multibase-encoded. See contentRef's own comment for why this, not a bare hash, is this method's anchor/entryHash format. */
function multihashEncode(digest: Uint8Array): string {
  const payload = new Uint8Array(2 + digest.length);
  payload[0] = SHA2_256_MULTIHASH_CODE;
  payload[1] = SHA256_DIGEST_LENGTH;
  payload.set(digest, 2);
  return toMultibaseBase58btc(payload);
}

function base58btcEncode(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) {
    const r = Number(n % 58n);
    n /= 58n;
    s = BASE58BTC_ALPHABET[r] + s;
  }
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }
  return BASE58BTC_ALPHABET[0].repeat(leadingZeros) + s;
}

function encodeVarint(value: number): Uint8Array {
  const out: number[] = [];
  let n = value;
  for (;;) {
    const b = n & 0x7f;
    n >>>= 7;
    if (n) {
      out.push(b | 0x80);
    } else {
      out.push(b);
      break;
    }
  }
  return new Uint8Array(out);
}

function base58btcDecode(s: string): Uint8Array {
  let n = 0n;
  for (const char of s) {
    const idx = BASE58BTC_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`invalid base58btc character: ${char}`);
    n = n * 58n + BigInt(idx);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let leadingZeros = 0;
  for (const char of s) {
    if (char !== BASE58BTC_ALPHABET[0]) break;
    leadingZeros++;
  }
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes]);
}

function decodeVarint(bytes: Uint8Array): [value: number, rest: Uint8Array] {
  let result = 0;
  let shift = 0;
  let i = 0;
  for (;;) {
    const b = bytes[i++];
    result |= (b & 0x7f) << shift;
    if (!(b & 0x80)) break;
    shift += 7;
  }
  return [result, bytes.slice(i)];
}

// multicodec code for p256-pub (https://github.com/multiformats/multicodec).
const P256_PUB_MULTICODEC = 0x1200;

/**
 * Converts the raw SPKI bytes Web Crypto exports into a W3C Multikey
 * multibase string: the EC point, compressed (33 bytes), prefixed with
 * the p256-pub multicodec varint, base58btc-encoded, 'z'-prefixed. Fix
 * 4: Multikey is this library's own public key format now, everywhere
 * one appears -- inside operations, in a resolved DID document, and in
 * this library's own `Keypair.publicKey` -- so this (and its inverse,
 * `multikeyToSpki`) is the one place SPKI/Multikey conversion happens,
 * used by `generateKeypair`/`importPublicKey` at the WebCrypto boundary
 * rather than by any caller.
 *
 * The fixed 26-byte SPKI header for P-256's AlgorithmIdentifier
 * (ecPublicKey + prime256v1 OIDs) is constant length, confirmed directly
 * against Web Crypto's own exportKey("spki", ...) output (91 bytes total),
 * not assumed -- so the trailing 65 bytes are always the raw uncompressed
 * point (0x04 || X(32) || Y(32)).
 */
export function spkiToMultikey(publicKeyB64url: string): string {
  const der = base64urlToBytes(publicKeyB64url);
  const point = der.slice(der.length - 65);
  if (point[0] !== 0x04) throw new Error("expected an uncompressed EC point in SPKI key material");
  const x = point.slice(1, 33);
  const y = point.slice(33, 65);
  const compressed = new Uint8Array(33);
  compressed[0] = y[31] % 2 === 0 ? 0x02 : 0x03;
  compressed.set(x, 1);
  const prefix = encodeVarint(P256_PUB_MULTICODEC);
  const payload = new Uint8Array(prefix.length + compressed.length);
  payload.set(prefix, 0);
  payload.set(compressed, prefix.length);
  return toMultibaseBase58btc(payload);
}

// NIST P-256 (secp256r1) curve parameters -- fixed constants of the curve,
// needed to decompress a point (multikeyToSpki below) since Web Crypto's
// importKey("spki", ...) only accepts an already-uncompressed point and
// has no decompression entry point at all.
const P256_P = BigInt("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
const P256_B = BigInt("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return result;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

function bigIntToBytes(n: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = n;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Recovers the full (x, y) point from a 33-byte compressed EC point
 * (0x02/0x03 prefix + x). P-256's prime is 3 mod 4, so a square root mod p
 * is just n^((p+1)/4) mod p -- no need for the general Tonelli-Shanks
 * algorithm. Throws if the recovered point doesn't actually satisfy the
 * curve equation, rather than silently returning a wrong point for
 * malformed input.
 */
function decompressPoint(compressed: Uint8Array): { x: Uint8Array; y: Uint8Array } {
  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) throw new Error("expected a compressed EC point (0x02 or 0x03 prefix)");
  const xBytes = compressed.slice(1, 33);
  const x = bytesToBigInt(xBytes);
  let rhs = (modpow(x, 3n, P256_P) - (3n * x) % P256_P + P256_B) % P256_P; // y^2 = x^3 - 3x + b mod p
  if (rhs < 0n) rhs += P256_P;
  let y = modpow(rhs, (P256_P + 1n) / 4n, P256_P);
  const wantEven = prefix === 0x02;
  if (y % 2n === 0n !== wantEven) y = P256_P - y;
  if ((y * y) % P256_P !== rhs) throw new Error("not a valid point on the P-256 curve");
  return { x: xBytes, y: bigIntToBytes(y, 32) };
}

// The fixed 26-byte SPKI header for P-256's AlgorithmIdentifier
// (ecPublicKey + prime256v1 OIDs) -- see spkiToMultikey's comment for how
// this was confirmed against Web Crypto's real exportKey output.
const SPKI_P256_HEADER = new Uint8Array(
  "3059301306072a8648ce3d020106082a8648ce3d030107034200".match(/.{2}/g)!.map((h) => parseInt(h, 16)),
);

/**
 * The inverse of spkiToMultikey -- recovers the raw SPKI bytes Web
 * Crypto's `importKey("spki", ...)` needs from a Multikey string, the
 * format every public key now arrives in (an operation's own
 * `operationalKeys`, a resolved DID document's `verificationMethod`, a
 * Data Integrity proof's `verificationMethod`). Internal to the
 * WebCrypto import boundary (`importPublicKey`, below) -- no caller
 * outside this file needs to reach for it directly anymore, though it
 * stays exported for a caller that already has raw SPKI from elsewhere.
 */
export function multikeyToSpki(multikey: string): string {
  const decoded = fromMultibaseBase58btc(multikey);
  const [codec, rest] = decodeVarint(decoded);
  if (codec !== P256_PUB_MULTICODEC) throw new Error(`expected the p256-pub multicodec (0x1200), got 0x${codec.toString(16)}`);
  if (rest.length !== 33) throw new Error(`expected a 33-byte compressed P-256 point, got ${rest.length} bytes`);
  const { x, y } = decompressPoint(rest);
  const point = new Uint8Array(65);
  point[0] = 0x04;
  point.set(x, 1);
  point.set(y, 33);
  const spki = new Uint8Array(SPKI_P256_HEADER.length + point.length);
  spki.set(SPKI_P256_HEADER, 0);
  spki.set(point, SPKI_P256_HEADER.length);
  return bytesToBase64url(spki);
}

const ECDSA_PARAMS = { name: "ECDSA", namedCurve: "P-256" } as const;
const SIGN_PARAMS = { name: "ECDSA", hash: "SHA-256" } as const;

// P-256's own order (n) -- needed only for low-S normalization below, since
// WebCrypto's ECDSA sign() already returns raw IEEE P1363 r||s (not DER),
// matching the Web Crypto spec exactly, with no decompression or encoding
// step needed to use it directly as a Data Integrity proofValue's payload.
const P256_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

/**
 * ECDSA's s and (n - s) are both valid signatures for the same message
 * under the same key -- anyone, not just the signer, can derive the
 * second from the first. Signing always normalizes to the smaller of
 * the two (s <= n/2, "low-S"), and verification rejects a high-S
 * signature outright rather than accepting both forms, so a given
 * (message, key) pair has exactly one valid signature bit-for-bit, not
 * two. did:plc does the same; WebCrypto itself has no low-S mode.
 */
function normalizeLowS(sig: Uint8Array): Uint8Array {
  const s = bytesToBigInt(sig.slice(32, 64));
  const halfN = P256_N / 2n;
  if (s <= halfN) return sig;
  const out = new Uint8Array(64);
  out.set(sig.slice(0, 32), 0);
  out.set(bigIntToBytes(P256_N - s, 32), 32);
  return out;
}

function isLowS(sig: Uint8Array): boolean {
  return bytesToBigInt(sig.slice(32, 64)) <= P256_N / 2n;
}

/** P-256 keypair -- stands in for the spec's did:key rotation keys. */
export async function generateKeypair(): Promise<Keypair> {
  const pair = await crypto.subtle.generateKey(ECDSA_PARAMS, true, ["sign", "verify"]);
  const [publicKeySpki, privateKey] = await Promise.all([
    crypto.subtle.exportKey("spki", pair.publicKey),
    crypto.subtle.exportKey("pkcs8", pair.privateKey),
  ]);
  return { publicKey: spkiToMultikey(bytesToBase64url(publicKeySpki)), privateKey: bytesToBase64url(privateKey) };
}

async function importPrivateKey(b64url: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", base64urlToBytes(b64url) as BufferSource, ECDSA_PARAMS, false, ["sign"]);
}

async function importPublicKey(multikey: string): Promise<CryptoKey> {
  const spki = multikeyToSpki(multikey);
  return crypto.subtle.importKey("spki", base64urlToBytes(spki) as BufferSource, ECDSA_PARAMS, false, ["verify"]);
}

export async function signPayload(payload: unknown, privateKeyB64url: string): Promise<string> {
  assertJCSSafe(payload);
  const key = await importPrivateKey(privateKeyB64url);
  const sig = new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS, key, new TextEncoder().encode(canonicalize(payload))));
  return bytesToBase64url(normalizeLowS(sig));
}

export async function verifyPayload(payload: unknown, sigB64url: string, publicKeyMultikey: string): Promise<boolean> {
  try {
    assertJCSSafe(payload);
    const sigBytes = base64urlToBytes(sigB64url);
    if (sigBytes.length !== 64 || !isLowS(sigBytes)) return false; // malformed or non-canonical (malleable) -- reject outright, never accept both forms
    const key = await importPublicKey(publicKeyMultikey);
    return await crypto.subtle.verify(SIGN_PARAMS, key, sigBytes as BufferSource, new TextEncoder().encode(canonicalize(payload)));
  } catch {
    return false;
  }
}

export async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input as BufferSource));
}

/**
 * Lower-level than `signPayload`/`verifyPayload`: signs/verifies raw
 * bytes directly (ECDSA always hashes its own input internally, so
 * passing already-hashed bytes here still produces an ordinary
 * signature over them, one further hash deep) rather than a JSON value
 * -- what operations.ts's Data Integrity proof construction needs,
 * since ecdsa-jcs-2019's own signing input is a fixed concatenation of
 * two hashes, not a JSON document to canonicalize. `proofValue`'s own
 * encoding is base58btc multibase (REQ-6-4/W3C vc-di-ecdsa), not this
 * library's ordinary base64url -- distinct from `signPayload`'s own
 * encoding, used for the Data Integrity proof set specifically.
 */
export async function signRawBytes(bytes: Uint8Array, privateKeyB64url: string): Promise<string> {
  const key = await importPrivateKey(privateKeyB64url);
  const sig = new Uint8Array(await crypto.subtle.sign(SIGN_PARAMS, key, bytes as BufferSource));
  return toMultibaseBase58btc(normalizeLowS(sig));
}

export async function verifyRawBytes(bytes: Uint8Array, sigMultibase: string, publicKeyMultikey: string): Promise<boolean> {
  try {
    const sigBytes = fromMultibaseBase58btc(sigMultibase);
    if (sigBytes.length !== 64 || !isLowS(sigBytes)) return false;
    const key = await importPublicKey(publicKeyMultikey);
    return await crypto.subtle.verify(SIGN_PARAMS, key, sigBytes as BufferSource, bytes as BufferSource);
  } catch {
    return false;
  }
}
