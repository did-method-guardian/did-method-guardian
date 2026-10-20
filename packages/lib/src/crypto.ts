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
