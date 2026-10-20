import type { Did } from "./types.js";

/**
 * Splits an identifier into its (optional) name and registrar domain.
 * Deterministic, single parse -- no retry/fallback needed (spec §2/§5): the
 * domain is always dot-joined and a name can never contain a dot, so
 * "one colon after the method name" vs. "none" fully disambiguates bare
 * (`did:guardian:acme.com`) from named (`did:guardian:alice:acme.com`).
 */
export function parseDid(did: Did): { name: string | null; domain: string } {
  const parts = did.split(":");
  if (parts[0] !== "did" || parts[1] !== "guardian" || parts.length < 3) {
    throw new Error(`not a valid did:guardian identifier: ${did}`);
  }
  const rest = parts.slice(2);
  const domain = rest[rest.length - 1];
  if (rest.length < 1 || rest.length > 2 || !domain) {
    throw new Error(`not a valid did:guardian identifier: ${did}`);
  }
  return rest.length === 1 ? { name: null, domain } : { name: rest[0], domain };
}

/**
 * Live HTTP resolution (spec §5: `GET https://<domain>/.well-known/guardian/<name>`)
 * is intentionally not implemented in this reference library -- v1 scope is
 * operating on a log already in hand (see website spec, "What this plan builds").
 * This stub documents the intended transport shape for a future directory-server
 * package to implement against.
 */
export interface Resolver {
  resolveLog(did: Did): Promise<never>;
}

/** `name: null` resolves to the reserved `_` segment -- the bare-domain identity's own well-known path (spec §2.1/§5), never a real registration (the name ABNF forbids `_`). */
export function wellKnownPath(name: string | null): string {
  return `/.well-known/guardian/${name ?? "_"}`;
}
