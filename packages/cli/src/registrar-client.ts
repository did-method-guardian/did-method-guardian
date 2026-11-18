// Plain HTTP calls against a registrar's well-known surface (spec §5,
// registrar API spec §1/§2) -- not part of @did-guardian/lib (that package
// deliberately stops at "operate on a log already in hand," see resolve.ts's
// note), so this CLI owns the live-HTTP half.
import { wellKnownPath, parseDid } from "@did-guardian/lib";
import type { Did, LogEntry, Operation } from "@did-guardian/lib";

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

export async function fetchLog(did: Did): Promise<LogEntry[]> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/log`);
  const body = await res.json();
  if (!res.ok) throw new Error((body as { error?: string }).error ?? `log fetch failed with HTTP ${res.status}`);
  return body as LogEntry[];
}

export async function submitOperation(did: Did, op: Operation): Promise<{ accepted: boolean; reason?: string }> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/operations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(op),
  });
  const body = (await res.json()) as { accepted?: boolean; error?: string };
  if (!res.ok) return { accepted: false, reason: body.error ?? `HTTP ${res.status}` };
  return { accepted: true };
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

export async function takeCustody(
  did: Did,
  sessionCookie: string,
  publicKey: string,
  force?: boolean,
): Promise<{ accepted: boolean; warnings: string[]; reason?: string }> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/take-custody`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: `gw_session=${sessionCookie}` },
    body: JSON.stringify({ public_key: publicKey, force }),
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
