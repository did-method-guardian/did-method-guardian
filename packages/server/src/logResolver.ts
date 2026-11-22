// A LogResolver (the lib's own type, REQ-10-7's "fetch the current log of
// each other identity the operation involves") for this registrar: local
// identities are read straight from `logs`; an identity on another domain
// is fetched over its own REQ-10-1 resource.
import { parseGuardianDid, type Did, type Log } from "@did-guardian/lib";
import { getLog } from "./db.js";
import type { Env } from "./env.js";

export function makeResolveLog(env: Env) {
  return async (did: Did): Promise<Log | undefined> => {
    const parsed = parseGuardianDid(did);
    if (!parsed) return undefined;

    if (parsed.domain === env.REGISTRAR_DOMAIN) {
      const log = await getLog(env, did);
      return log.length > 0 ? log : undefined;
    }

    const segment = parsed.name ?? "_";
    try {
      const resp = await fetch(`https://${parsed.domain}/.well-known/guardian/${encodeURIComponent(segment)}/log`);
      if (!resp.ok) return undefined;
      return (await resp.json()) as Log;
    } catch {
      return undefined;
    }
  };
}
