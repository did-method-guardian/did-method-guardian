export interface Env {
  DB: D1Database;
  KEY_ENCRYPTION_KEY: string; // base64, 32 bytes, AES-GCM -- set via `wrangler secret put`
  REGISTRAR_DOMAIN: string; // e.g. "guardianspec.org"
  // OIDC signing key, set once per deployment -- see oidc.ts
  OIDC_SIGNING_KEY?: string;
}

/** Splits a domain like "guardianspec.org" into its DID label sequence. */
export function domainLabels(domain: string): string[] {
  return domain.split(".");
}

export function didFor(name: string, domain: string): string {
  return `did:guardian:${name}:${domainLabels(domain).join(":")}`;
}
