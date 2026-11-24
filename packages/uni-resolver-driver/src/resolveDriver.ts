// Universal Resolver driver core for did:guardian -- a thin HTTP service
// answers GET /1.0/identifiers/<did> (server.ts), but the actual resolution
// logic lives here, independent of HTTP, so it's directly testable.
//
// It never trusts a target domain's bare DID document on its own say-so: it
// fetches that domain's full log and independently re-verifies it with
// @did-guardian/lib's own resolve() -- the same check a real did:guardian
// client makes -- so a compromised or lying registrar can't hand the
// Universal Resolver a forged document just because it answered the
// request.
import { parseGuardianDid, resolve, type Did, type Log, type LogResolver } from "@did-guardian/lib";

export interface ResolutionResult {
  didResolutionMetadata: { contentType?: string; error?: string; errorMessage?: string };
  didDocument: unknown | null;
  didDocumentMetadata: object;
}

/** Every did:guardian DID is "remote" from this driver's own point of view -- it holds no log of its own. */
export async function fetchLogOverHttp(did: Did): Promise<Log | null | undefined> {
  const parsed = parseGuardianDid(did);
  if (!parsed) return undefined;
  const segment = parsed.name ?? "_";
  try {
    const resp = await fetch(`https://${parsed.domain}/.well-known/guardian/${encodeURIComponent(segment)}/log`);
    if (resp.status === 404) return null;
    if (!resp.ok) return undefined;
    return (await resp.json()) as Log;
  } catch {
    return undefined;
  }
}

export async function resolveDid(did: string, fetchLog: LogResolver = fetchLogOverHttp): Promise<{ status: number; body: ResolutionResult }> {
  const parsed = parseGuardianDid(did);
  if (!parsed) {
    return { status: 400, body: { didResolutionMetadata: { error: "invalidDid" }, didDocument: null, didDocumentMetadata: {} } };
  }

  const log = await fetchLog(did as Did);
  if (log === undefined) {
    return { status: 502, body: { didResolutionMetadata: { error: "internalError", errorMessage: `could not fetch ${did}'s log from ${parsed.domain}` }, didDocument: null, didDocumentMetadata: {} } };
  }
  if (log === null) {
    return { status: 404, body: { didResolutionMetadata: { error: "notFound" }, didDocument: null, didDocumentMetadata: {} } };
  }

  const result = await resolve(did as Did, log, fetchLog);
  if (result.result !== "valid") {
    return {
      status: result.result === "unsupported" ? 501 : 404,
      body: { didResolutionMetadata: { error: result.result === "unsupported" ? "representationNotSupported" : "notFound", errorMessage: result.reason }, didDocument: null, didDocumentMetadata: {} },
    };
  }
  return {
    status: 200,
    body: { didResolutionMetadata: { contentType: "application/did+ld+json" }, didDocument: result.document, didDocumentMetadata: (result.metadata as object | undefined) ?? {} },
  };
}
