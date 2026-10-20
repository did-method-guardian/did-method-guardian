// Minimal ES256 JWT sign/verify for the OIDC layer -- Web Crypto, same
// primitives as packages/lib's own crypto.ts, JOSE-compliant wire format
// (base64url(header).base64url(payload).base64url(signature)) so standard
// OIDC client libraries can verify tokens from this issuer unmodified.

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function b64urlJson(obj: unknown): string {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}

export interface SigningKeypair {
  publicKeyJwk: JsonWebKey;
  privateKey: CryptoKey;
  kid: string;
}

/** Imports a signing keypair from the same base64url SPKI/PKCS8 format packages/lib's crypto.ts produces. */
export async function importSigningKeypair(publicKeyB64url: string, privateKeyB64url: string, kid: string): Promise<SigningKeypair> {
  const params = { name: "ECDSA", namedCurve: "P-256" } as const;
  const publicKey = await crypto.subtle.importKey("spki", b64urlDecode(publicKeyB64url) as BufferSource, params, true, ["verify"]);
  const privateKey = await crypto.subtle.importKey("pkcs8", b64urlDecode(privateKeyB64url) as BufferSource, params, false, ["sign"]);
  const publicKeyJwk = await crypto.subtle.exportKey("jwk", publicKey);
  return { publicKeyJwk, privateKey, kid };
}

export async function signJwt(payload: Record<string, unknown>, keypair: SigningKeypair): Promise<string> {
  const header = { alg: "ES256", typ: "JWT", kid: keypair.kid };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keypair.privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${b64url(sig)}`;
}

export async function verifyJwt(token: string, publicKey: CryptoKey): Promise<Record<string, unknown> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    b64urlDecode(sigB64) as BufferSource,
    new TextEncoder().encode(`${headerB64}.${payloadB64}`),
  );
  if (!valid) return null;
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
  if (typeof payload.exp === "number" && Date.now() / 1000 > payload.exp) return null;
  return payload;
}

/** PKCE S256 challenge verification: base64url(sha256(code_verifier)) === code_challenge. */
export async function verifyPkce(codeVerifier: string, codeChallenge: string): Promise<boolean> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  return b64url(digest) === codeChallenge;
}

export { b64url };
