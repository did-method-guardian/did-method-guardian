import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from "node:crypto";

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

export function contentRef(value: unknown): string {
  return createHash("sha256").update(canonicalize(value)).digest("hex");
}

export interface Keypair {
  publicKeyPem: string;
  privateKeyPem: string;
}

/** P-256 keypair -- stands in for the spec's did:key rotation keys. */
export function generateKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

export function signPayload(payload: unknown, privateKeyPem: string): string {
  const key = createPrivateKey(privateKeyPem);
  const sig = nodeSign(null, Buffer.from(canonicalize(payload)), key);
  return sig.toString("base64url");
}

export function verifyPayload(payload: unknown, sigB64: string, publicKeyPem: string): boolean {
  try {
    const key = createPublicKey(publicKeyPem);
    return nodeVerify(null, Buffer.from(canonicalize(payload)), key, Buffer.from(sigB64, "base64url"));
  } catch {
    return false;
  }
}
