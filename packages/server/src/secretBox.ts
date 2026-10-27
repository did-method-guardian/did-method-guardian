// AES-GCM encryption at rest for operational private keys, using the
// deployment's own KEY_ENCRYPTION_KEY secret. Same approach zz's own worker
// already uses for OAuth tokens -- not invented fresh here, just self-
// contained since this is a separate repo with no code to share from zz.

function toBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function toBase64(bytes: Uint8Array | ArrayBuffer): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function importAesKey(keyB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toBytes(keyB64) as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Returns `<base64 iv>.<base64 ciphertext>`. */
export async function encryptSecret(plaintext: string, keyB64: string): Promise<string> {
  const key = await importAesKey(keyB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return `${toBase64(iv)}.${toBase64(ciphertext)}`;
}

/** One-way hash for login secrets -- checked, never decrypted back. */
export async function hashSecret(plaintext: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(plaintext));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomSecret(): string {
  return toBase64(crypto.getRandomValues(new Uint8Array(32))).replace(/[+/=]/g, "");
}

// A human-chosen password needs real key stretching -- unlike randomSecret
// above, it doesn't start with 256 bits of entropy, so a single unsalted
// SHA-256 (hashSecret) would be brute-forceable/rainbow-tableable against a
// database leak. PBKDF2-HMAC-SHA256, salted per-password. Confirmed against
// Cloudflare's own Workers runtime docs that PBKDF2 is supported by
// crypto.subtle.deriveBits -- no new dependency needed.
//
// Stored as `pbkdf2$<iterations>$<salt b64>$<hash b64>` -- a different
// shape than hashSecret's own bare 64-hex-char digest, so verifyCredential
// below can tell the two apart from the stored string alone with no schema
// change: an existing row's randomSecret-issued hash (today's only format)
// keeps verifying exactly as it always has, forever, without a migration.
// Confirmed live (not just reasoned about): 300,000 iterations (~29ms in a
// local Node benchmark) reliably exceeded the actual deployed Worker's CPU
// budget and crashed the request -- Cloudflare's Free plan caps CPU time
// at 10ms per request, and there's other real work (DID signing, JSON) in
// the same request alongside this. 100,000 scales down to roughly a third
// of that measured time, leaving headroom; re-benchmark before raising it.
const PBKDF2_ITERATIONS = 100_000;

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS }, key, 256);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toBase64(salt)}$${toBase64(bits)}`;
}

function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Verifies a login secret against a stored hash in either format -- see hashPassword's own comment for why both exist indefinitely. */
export async function verifyCredential(plaintext: string, stored: string): Promise<boolean> {
  if (stored.startsWith("pbkdf2$")) {
    const parts = stored.split("$");
    if (parts.length !== 4) return false;
    const [, iterStr, saltB64, hashB64] = parts;
    const iterations = Number(iterStr);
    if (!Number.isInteger(iterations) || iterations <= 0) return false;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(plaintext), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: toBytes(saltB64) as BufferSource, iterations }, key, 256);
    return constantTimeEqual(toBase64(bits), hashB64);
  }
  return constantTimeEqual(await hashSecret(plaintext), stored);
}

export async function decryptSecret(encoded: string, keyB64: string): Promise<string> {
  const [ivB64, ctB64] = encoded.split(".");
  const key = await importAesKey(keyB64);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toBytes(ivB64) as BufferSource },
    key,
    toBytes(ctB64) as BufferSource,
  );
  return new TextDecoder().decode(plaintext);
}
