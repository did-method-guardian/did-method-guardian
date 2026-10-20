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
