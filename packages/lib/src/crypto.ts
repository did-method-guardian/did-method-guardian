// Web Crypto (crypto.subtle) based -- portable across Node.js, browsers, and
// Cloudflare Workers with no runtime-specific dependency and no compat flags.
// Previously used node:crypto directly, which Workers don't have without
// nodejs_compat (and even then, EC sign/verify support isn't guaranteed to
// match real Node). See did-method-guardian#<issue>.

// A lightweight stand-in for the spec's DAG-CBOR + CIDv1 scheme (see the open
// question in spec §8 on interop detail). Canonical JSON (sorted keys) is
// hashed with sha-256 to produce a content reference; real interop would need
// true DAG-CBOR + multicodec/multihash, tracked as follow-up work, not
// something this reference implementation's logic depends on.

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

export async function contentRef(value: unknown): Promise<string> {
  const digest = await sha256(canonicalize(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface Keypair {
  publicKey: string; // base64url-encoded SPKI
  privateKey: string; // base64url-encoded PKCS8
}

const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
 * Converts this library's internal base64url-SPKI public key format into a
 * proper W3C Multikey multibase string: the raw EC point, compressed (33
 * bytes), prefixed with the p256-pub multicodec varint, base58btc-encoded,
 * and 'z'-prefixed. Used only when rendering a DID document
 * (document.ts's toDidDocument) -- internal signing/verification keeps
 * using the SPKI/PKCS8 base64url format unchanged, so this has no bearing
 * on any already-signed operation log content and needs no migration.
 *
 * The fixed 26-byte SPKI header for P-256's own AlgorithmIdentifier
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
  return "z" + base58btcEncode(payload);
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
 * The inverse of spkiToMultikey -- recovers this library's internal
 * base64url-SPKI format from a W3C Multikey string, the only form a
 * resolved DID document actually exposes (REQ-3-1: every verificationMethod
 * is type Multikey). Needed by any caller that wants to verify a signature
 * (a registrar attestation, a log-head statement) against a key it only
 * has by resolving a DID document, rather than one it already holds in
 * this library's internal format from signing/generating a key directly.
 */
export function multikeyToSpki(multikey: string): string {
  if (!multikey.startsWith("z")) throw new Error("expected a 'z'-prefixed Multikey string");
  const decoded = base58btcDecode(multikey.slice(1));
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

/** P-256 keypair -- stands in for the spec's did:key rotation keys. */
export async function generateKeypair(): Promise<Keypair> {
  const pair = await crypto.subtle.generateKey(ECDSA_PARAMS, true, ["sign", "verify"]);
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.exportKey("spki", pair.publicKey),
    crypto.subtle.exportKey("pkcs8", pair.privateKey),
  ]);
  return { publicKey: bytesToBase64url(publicKey), privateKey: bytesToBase64url(privateKey) };
}

async function importPrivateKey(b64url: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", base64urlToBytes(b64url) as BufferSource, ECDSA_PARAMS, false, ["sign"]);
}

async function importPublicKey(b64url: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", base64urlToBytes(b64url) as BufferSource, ECDSA_PARAMS, false, ["verify"]);
}

export async function signPayload(payload: unknown, privateKeyB64url: string): Promise<string> {
  const key = await importPrivateKey(privateKeyB64url);
  const sig = await crypto.subtle.sign(SIGN_PARAMS, key, new TextEncoder().encode(canonicalize(payload)));
  return bytesToBase64url(sig);
}

export async function verifyPayload(payload: unknown, sigB64url: string, publicKeyB64url: string): Promise<boolean> {
  try {
    const key = await importPublicKey(publicKeyB64url);
    return await crypto.subtle.verify(
      SIGN_PARAMS,
      key,
      base64urlToBytes(sigB64url) as BufferSource,
      new TextEncoder().encode(canonicalize(payload)),
    );
  } catch {
    return false;
  }
}
