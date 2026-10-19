import type { Did } from "./types.js";

/** Splits a name-first identifier into its name and registrar domain. */
export function parseDid(did: Did): { name: string; domain: string } {
  const parts = did.split(":");
  if (parts[0] !== "did" || parts[1] !== "guardian" || parts.length < 4) {
    throw new Error(`not a valid did:guardian identifier: ${did}`);
  }
  const [, , name, ...labels] = parts;
  return { name, domain: labels.join(".") };
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

export function wellKnownPath(name: string): string {
  return `/.well-known/guardian/${name}`;
}
