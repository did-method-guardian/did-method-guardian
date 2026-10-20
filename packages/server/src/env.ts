export interface Env {
  DB: D1Database;
  KEY_ENCRYPTION_KEY: string; // base64, 32 bytes, AES-GCM -- set via `wrangler secret put`
  REGISTRAR_DOMAIN: string; // e.g. "guardianspec.org"
  // OIDC signing key, set once per deployment -- see oidc.ts
  OIDC_SIGNING_KEY?: string;
  // Optional pre-seeded keypair for this instance's own bare-domain root
  // identity (spec §2.1) -- an operator who wants to bring their own root
  // key material (e.g. migrating from somewhere, or managing it outside
  // this registrar's own custodial encryption) sets both; otherwise
  // getOrCreateRootWard (registrar.ts) generates one automatically on
  // first access. Both or neither -- set only one and the other is ignored.
  ROOT_WARD_PUBLIC_KEY?: string;
  ROOT_WARD_PRIVATE_KEY?: string;
}

/** `name: null` builds the bare-domain identity (spec §2.1); domain is embedded as a single dot-joined string, never re-split into colon-joined labels (spec §2). */
export function didFor(name: string | null, domain: string): string {
  return name ? `did:guardian:${name}:${domain}` : `did:guardian:${domain}`;
}
