import type { SendEmail } from "@cloudflare/workers-types";

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
  // Outbound email (emailProviders.ts) -- which provider this deployment
  // uses, and that provider's own API key. Never hardcoded to one vendor:
  // "mailchannels" | "resend" | "cloudflare-native" | "log" (dev-only,
  // prints instead of sending) today, and one more small function away
  // from any other fetch-reachable transactional provider. Unset means
  // email forwarding verification and pending-operation notifications
  // simply don't send, reported as a clear configuration error, not a
  // vendor-specific 401.
  EMAIL_PROVIDER?: string;
  MAILCHANNELS_API_KEY?: string;
  RESEND_API_KEY?: string;
  // Cloudflare's own native Email Sending binding (EMAIL_PROVIDER =
  // "cloudflare-native") -- a send_email binding, not a secret; the one
  // deliberately Workers-specific provider option, needing no external
  // account or API key, just `wrangler email sending enable <domain>`.
  EMAIL?: SendEmail;
}

/** `name: null` builds the bare-domain identity (spec §2.1); domain is embedded as a single dot-joined string, never re-split into colon-joined labels (spec §2). Domain-first, matching did:web's own convention. */
export function didFor(name: string | null, domain: string): string {
  return name ? `did:guardian:${domain}:${name}` : `did:guardian:${domain}`;
}
