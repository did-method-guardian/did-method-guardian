// A LogResolver (the lib's own type, REQ-10-7's "fetch the current log of
// each other identity the operation involves") for this registrar: local
// identities are read straight from `logs`; an identity on another domain
// is fetched over its own REQ-10-1 resource.
import { parseGuardianDid, type Did, type Log } from "@did-guardian/lib";
import { getLog } from "./db.js";
import type { Env } from "./env.js";

export function makeResolveLog(env: Env) {
  return async (did: Did): Promise<Log | null | undefined> => {
    const parsed = parseGuardianDid(did);
    if (!parsed) return undefined;

    if (parsed.domain === env.REGISTRAR_DOMAIN) {
      // D3 (spec r7/r7b, surfaced by registerManagedIdentity's own
      // test): "a DID has no log only if its registrar reports that
      // it has none" (REQ-10-7's acceptWard row) needs `null` to mean
      // that, distinct from `undefined` ("could not be fetched") --
      // for an identity on THIS domain, this registrar is
      // authoritative, so it can say so with confidence, not just
      // "absent." Collapsing both into `undefined` (the pre-D3
      // behavior) made every acceptWard naming a brand-new, not-yet-
      // created ward on this same domain reject outright, which is
      // exactly D3's own single-request create-with-guardian case.
      const log = await getLog(env, did);
      return log.length > 0 ? log : null;
    }

    const segment = parsed.name ?? "_";
    try {
      const resp = await fetch(`https://${parsed.domain}/.well-known/guardian/${encodeURIComponent(segment)}/log`);
      if (resp.status === 404) return null;
      if (!resp.ok) return undefined;
      return (await resp.json()) as Log;
    } catch {
      return undefined;
    }
  };
}
