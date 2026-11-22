// Plain HTTP calls against a registrar's well-known surface (spec §10) --
// not part of @did-guardian/lib (that package deliberately stops at
// "operate on a log already in hand"), so this CLI owns the live-HTTP
// half.
import { parseDid, verifyLog, wellKnownPath } from "@did-guardian/lib";
import type { DataIntegrityProof, Did, Log, LogResolver, Operation } from "@did-guardian/lib";

export interface RegisterResult {
  did: Did;
  login_secret?: string;
  /** REQ-10-14: a consenting guardian named via a Managed Identity API access token is never auto-added in the same request that creates this identity -- echoed back here as a DID to complete the ordinary two-step adopt flow with, never as a proof already produced for it. */
  guardian_pending?: Did;
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

export async function resolveDocument(did: Did): Promise<unknown> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}`);
  const body = await res.json();
  if (!res.ok) throw new Error((body as { error?: string }).error ?? `resolution failed with HTTP ${res.status}`);
  return body;
}

export async function fetchLog(did: Did): Promise<Log> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/log`);
  const body = await res.json();
  if (!res.ok) throw new Error((body as { error?: string }).error ?? `log fetch failed with HTTP ${res.status}`);
  return body as Log;
}

/** A LogResolver (the lib's own type) backed by live HTTP fetches -- for both resolving `did` itself and REQ-10-7/REQ-11-2's own cross-log checks. */
export function makeLiveResolver(): LogResolver {
  return async (did: Did) => {
    try {
      return await fetchLog(did);
    } catch {
      return undefined;
    }
  };
}

export interface SubmitResult {
  accepted: boolean;
  operation?: Operation;
  reason?: string;
}

export async function submitOperation(did: Did, op: Operation): Promise<SubmitResult> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/operations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(op),
  });
  const body = (await res.json()) as { accepted?: boolean; operation?: Operation; error?: string };
  if (!res.ok) return { accepted: false, reason: body.error ?? `HTTP ${res.status}` };
  return { accepted: true, operation: body.operation };
}

/**
 * Logs in against a registrar's first-party session endpoint -- the one
 * part of this registrar's HTTP surface that isn't a clean JSON API: a
 * successful attempt is an ordinary 302 with a Set-Cookie, so `redirect:
 * "manual"` is required to read the cookie instead of silently
 * following it.
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

/** REQ-10-13/10-14: this registrar signs `operation` with its own held key for `did`, combined with `proof` (the caller's own, over the same operation) -- used by take-custody, where the new key's own proof of possession comes from here. */
export async function takeCustody(
  did: Did,
  sessionCookie: string,
  operation: object,
  proof: DataIntegrityProof,
): Promise<{ accepted: boolean; reason?: string }> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/take-custody`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: `gw_session=${sessionCookie}` },
    body: JSON.stringify({ operation, proof }),
  });
  const body = (await res.json()) as { error?: string };
  if (!res.ok) return { accepted: false, reason: body.error ?? `HTTP ${res.status}` };
  return { accepted: true };
}

/** Step 1 of adopt: authenticated as the guardian, naming `wardDid` as the ward it's accepting. */
export async function proposeAdopt(wardDid: Did, guardianSessionCookie: string): Promise<{ pendingId: string }> {
  const { domain, name } = parseDid(wardDid);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/adopt`, {
    method: "POST",
    headers: { cookie: `gw_session=${guardianSessionCookie}` },
  });
  const body = (await res.json()) as { pendingId?: string; error?: string };
  if (!res.ok || !body.pendingId) throw new Error(body.error ?? `HTTP ${res.status}`);
  return { pendingId: body.pendingId };
}

/** Step 2 of adopt: authenticated as the ward itself, completing the pending addGuardian `proposeAdopt` started. */
export async function confirmAdopt(wardDid: Did, wardSessionCookie: string, pendingId: string): Promise<{ accepted: boolean; reason?: string }> {
  const { domain, name } = parseDid(wardDid);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/adopt/confirm`, {
    method: "POST",
    headers: { cookie: `gw_session=${wardSessionCookie}`, "content-type": "application/json" },
    body: JSON.stringify({ pending_id: pendingId }),
  });
  const body = (await res.json()) as { ok?: boolean; error?: string };
  if (!res.ok) return { accepted: false, reason: body.error ?? `HTTP ${res.status}` };
  return { accepted: body.ok === true };
}

export interface ProposeOutcome {
  status: "finalized" | "collecting";
  id?: string;
  operation?: Operation;
  reason?: string;
}

/** The generic multi-signer proposal flow (REQ-10-7's own cross-log checks apply the same as a direct submission) -- for an operation this one signature alone can't satisfy. */
export async function proposeOperation(did: Did, operation: Omit<Operation, "proof">, proof: DataIntegrityProof): Promise<ProposeOutcome> {
  const { domain, name } = parseDid(did);
  const res = await fetch(`https://${domain}${wellKnownPath(name)}/propose`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation, proof }),
  });
  const body = (await res.json()) as ProposeOutcome & { error?: string };
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}

export interface PendingStatus {
  did: Did;
  operation: Operation;
  proofs: DataIntegrityProof[];
  expiresAt: string;
}

export async function fetchPendingStatus(registrarDomain: string, pendingId: string): Promise<PendingStatus> {
  const res = await fetch(`https://${registrarDomain}/.well-known/guardian/pending/${pendingId}`, { headers: { accept: "application/json" } });
  const body = (await res.json()) as PendingStatus & { error?: string };
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}

export async function contributeProof(registrarDomain: string, pendingId: string, proof: DataIntegrityProof): Promise<ProposeOutcome> {
  const res = await fetch(`https://${registrarDomain}/.well-known/guardian/pending/${pendingId}/sign`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ proof }),
  });
  const body = (await res.json()) as ProposeOutcome & { error?: string };
  if (!res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
  return body;
}

/**
 * Before signing AS `did` with a locally-saved key, check that key is
 * actually still `did`'s own current key -- without this, a stale local
 * key (rotated away from elsewhere) signs anyway, since nothing stops a
 * client from producing a signature with any key it holds; the only way
 * to catch this before a confusing rejection from the registrar is to
 * resolve and compare first. Throws with a clear, specific reason on an
 * actual mismatch; resolves silently (never throws) when `did` can't be
 * resolved at all -- that's the ordinary case for an identity that's a
 * still-unpublished draft, which this check has no business blocking.
 */
export async function confirmKeyIsCurrent(did: Did, publicKey: string): Promise<void> {
  let log: Log;
  try {
    log = await fetchLog(did);
  } catch {
    return;
  }
  if (log.length === 0) return;
  const result = await verifyLog(did, log);
  if (result.result !== "valid") return; // not this command's job to report a verification failure
  if (!result.state!.keys.includes(publicKey)) {
    throw new Error(
      `the local key you're about to sign as ${did} with is not that identity's current key -- it was probably rotated away from elsewhere. Resolve ${did} again to see its actual current key before retrying.`,
    );
  }
}
