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
