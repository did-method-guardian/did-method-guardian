import type { SendEmail } from "@cloudflare/workers-types";

export interface Env {
  DB: D1Database;
  KEY_ENCRYPTION_KEY: string; // base64, 32 bytes, AES-GCM -- set via `wrangler secret put`
  REGISTRAR_DOMAIN: string; // e.g. "guardianspec.org"
  // Comma-separated registrar domains whose own access tokens this
  // instance accepts at bearer-token-gated endpoints (verifyAccessToken),
  // not just its own -- the Managed Identity API's own real need: a
  // guardian's identity doesn't have to live on this same registrar. An
  // operator opts a federated peer in explicitly; empty/unset means this
  // registrar only ever trusts its own tokens, same as before this existed.
  FEDERATED_TRUSTED_ISSUERS?: string;
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
  // The root identity's own login credential -- the only way it ever gets
  // one, since (same reasoning as the key pair above) there's no
  // registration flow to set one through: this identity is claimed by
  // construction, by whoever legitimately operates the domain, not by
  // request. Set by the operator (the only party who can plausibly prove
  // that, same trust model as the key-pair secrets above) via `wrangler
  // secret put`; getOrCreateRootWard (registrar.ts) hashes and stores it
  // the first time it's seen, whether that's at this identity's own
  // creation or lazily on an already-provisioned deployment that didn't
  // have this secret set yet. Unset means the root identity still
  // resolves and attests other wards' genesis correctly, it just can't
  // log in anywhere.
  ROOT_WARD_LOGIN_SECRET?: string;
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
