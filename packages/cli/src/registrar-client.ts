// Plain HTTP calls against a registrar's well-known surface (spec §5,
// registrar API spec §1/§2) -- not part of @did-guardian/lib (that package
// deliberately stops at "operate on a log already in hand," see resolve.ts's
// note), so this CLI owns the live-HTTP half.
import { wellKnownPath, parseDid, multikeyToSpki } from "@did-guardian/lib";
import type { Did, LogEntry, LogHeadStatement, Operation } from "@did-guardian/lib";

export interface RegisterResult {
  did: Did;
  document: unknown;
  login_secret?: string;
}

export async function registerWard(registrarDomain: string, name: string): Promise<RegisterResult> {
  const res = await fetch(`https://${registrarDomain}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  const body = (await res.json()) as RegisterResult & { error?: string };
  if (!res.ok) throw new Error(body.error ?? `registration failed with HTTP ${res.status}`);
  return body;
}

export async function resolveDid(did: Did): Promise<unknown> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}`);
  const body = await res.json();
  if (!res.ok) throw new Error((body as { error?: string }).error ?? `resolution failed with HTTP ${res.status}`);
  return body;
}

/** The registrar's public key, in this library's internal SPKI format -- resolved by fetching the bare-domain identity's DID document and converting its Multikey. Needed to check a log-head statement's signature (L2), and to pin the registrar's key alongside a DID's anchor. */
export async function resolveRegistrarKey(domain: string): Promise<{ did: Did; publicKey: string }> {
  const res = await fetch(`https://${domain}/.well-known/guardian/_`);
  const body = (await res.json()) as { id?: Did; verificationMethod?: { publicKeyMultibase: string }[]; error?: string };
  if (!res.ok || !body.id || !body.verificationMethod?.[0]) throw new Error(body.error ?? `could not resolve ${domain}'s registrar identity`);
  return { did: body.id, publicKey: multikeyToSpki(body.verificationMethod[0].publicKeyMultibase) };
}

export async function fetchLogHead(did: Did): Promise<LogHeadStatement> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/log-head`);
  const body = (await res.json()) as LogHeadStatement & { error?: string };
  if (!res.ok) throw new Error((body as { error?: string }).error ?? `log-head fetch failed with HTTP ${res.status}`);
  return body;
}

export async function fetchLog(did: Did): Promise<LogEntry[]> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/log`);
  const body = await res.json();
  if (!res.ok) throw new Error((body as { error?: string }).error ?? `log fetch failed with HTTP ${res.status}`);
  return body as LogEntry[];
}

/**
 * `cid`, when the registrar returns one (currently only for a genesis
 * submission, v0.3 REQ-8-2): the accepted operation's REAL cid, computed
 * server-side over the content the registrar actually stored, including
 * its just-added `registrar` attestation. Never the same value a
 * caller could have computed locally before submitting -- the
 * attestation is part of the signed content, so adding it necessarily
 * changes the cid. Anything that needs to report or pin an anchor for a
 * newly-created identity must use this value, not one computed from the
 * unattested op it sent.
 */
export async function submitOperation(did: Did, op: Operation): Promise<{ accepted: boolean; reason?: string; cid?: string }> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/operations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(op),
  });
  const body = (await res.json()) as { accepted?: boolean; error?: string; cid?: string };
  if (!res.ok) return { accepted: false, reason: body.error ?? `HTTP ${res.status}` };
  return { accepted: true, cid: body.cid };
}

/**
 * Logs in against a registrar's first-party session endpoint (registrar
 * API spec, the browser voting page's login form) -- the one part of
 * this registrar's HTTP surface that isn't a clean JSON API: a successful
 * attempt is an ordinary 302 with a Set-Cookie, so `redirect: "manual"`
 * is required to read the cookie instead of silently following it.
 */
export async function login(registrarDomain: string, name: string, loginSecret: string): Promise<string> {
  const body = new URLSearchParams({ name, login_secret: loginSecret, return_to: "/" });
  const res = await fetch(`https://${registrarDomain}/guardian-login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
    redirect: "manual",
  });
  const setCookie = res.headers.get("set-cookie");
  const match = setCookie?.match(/gw_session=([^;]+)/);
  if (!match) throw new Error("login failed -- check the name and login secret");
  return match[1];
}

/**
 * `keySig`, v0.3 (REQ-7.2-12): proof that the caller holds `publicKey`'s
 * private half, signed locally before this call (see key.ts's take-custody
 * command) -- this registrar never holds that key, so it can't produce
 * that signature the way it does for a server-generated rotation.
 */
export async function takeCustody(
  did: Did,
  sessionCookie: string,
  publicKey: string,
  keySig: string,
  force?: boolean,
): Promise<{ accepted: boolean; warnings: string[]; reason?: string }> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/take-custody`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: `gw_session=${sessionCookie}` },
    body: JSON.stringify({ public_key: publicKey, key_sig: keySig, force }),
  });
  const body = (await res.json()) as { warnings?: string[]; error?: string };
  if (!res.ok) return { accepted: false, warnings: body.warnings ?? [], reason: body.error ?? `HTTP ${res.status}` };
  return { accepted: true, warnings: body.warnings ?? [] };
}

/**
 * Session-based zero-to-one `guardian_add` convenience (registrar API
 * spec §2's `.../adopt`): the caller IS the incoming guardian -- log in
 * as the guardian, not the ward, before calling this against the ward's
 * name.
 */
export async function adopt(wardDid: Did, sessionCookie: string): Promise<{ accepted: boolean; reason?: string }> {
  const { domain, name } = parseDid(wardDid);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/adopt`, {
    method: "POST",
    headers: { cookie: `gw_session=${sessionCookie}` },
  });
  const body = (await res.json()) as { error?: string };
  if (!res.ok) return { accepted: false, reason: body.error ?? `HTTP ${res.status}` };
  return { accepted: true };
}
