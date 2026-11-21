// A pre-registered, OPERATOR-TRUSTED OIDC client can authenticate itself
// to a few registrar endpoints beyond the OIDC flow proper -- reusing the
// exact same client_id/client_secret credential (the oidc_clients table)
// rather than inventing a second kind of API key. This is what makes it
// safe for a relying party to act on behalf of one of its own already-
// authenticated users without a fresh interactive signature every time:
// the registrar is trusting the relying party's own prior authentication,
// not skipping authentication altogether. See registrar.ts's registerWard
// (an atomic ward-plus-guardian creation) and index.ts's /email handler
// (setting up forwarding right after creating a ward, before any
// interactive session with this registrar exists) for the two places
// this is actually used.
//
// Hotfix (migration 0012): this MUST stay gated on `client.trusted`, never
// loosened to "any client that authenticates." POST /oauth/register-client
// is open, unauthenticated self-registration (RFC 7591) -- without this
// gate, anyone could register a client and immediately use it here to act
// as any ward, including the bare-domain root, via the login-secret/
// rotate/tombstone/relinquish/remove/adopt/take-custody endpoints that
// trust this function's return value.
import type { Env } from "./env.js";
import { getOidcClient, type OidcClientRow } from "./db.js";
import { hashSecret } from "./secretBox.js";

export async function authenticateOidcClient(request: Request, env: Env): Promise<OidcClientRow | null> {
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Basic ")) return null;
  let decoded: string;
  try {
    decoded = atob(auth.slice(6));
  } catch {
    return null;
  }
  const i = decoded.indexOf(":");
  if (i === -1) return null;
  const clientId = decoded.slice(0, i);
  const clientSecret = decoded.slice(i + 1);
  const client = await getOidcClient(env, clientId);
  if (!client) return null;
  if (!client.trusted) return null;
  if ((await hashSecret(clientSecret)) !== client.client_secret_hash) return null;
  return client;
}
