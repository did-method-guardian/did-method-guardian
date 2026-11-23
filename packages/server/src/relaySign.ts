// Cross-registrar signature relay: lets a guardian whose key THIS
// registrar holds review and sign a pending operation that lives on a
// DIFFERENT registrar (the ward's own) -- a guardian's private key lives
// server-side on their own registrar and is never exposed to them, so
// they can't produce a raw signature themselves the way a self-custodied
// external guardian can.
//
// Nothing here is trusted blindly: the operation's own content is fetched
// live from the ward's own registrar on every request, never cached or
// taken from a query string or an email. The resulting proof is, as
// always, independently re-checked by the ward's own registrar via its
// existing /operations acceptance path -- this page only ever produces a
// proof using a key this registrar already holds for its own logged-in
// identity, the same signAs votingPage.ts's own signAsSelf uses for
// same-registrar operations.

import type { Env } from "./env.js";
import { safeFormData } from "./http.js";
import { html, escapeHtml, pageShell } from "./htmlPage.js";
import { readCookie, resolveSession } from "./login.js";
import { signAs, authenticateRequest } from "./signing.js";
import { RegistrarError } from "./registrarError.js";
import { getLog } from "./db.js";
import { parseGuardianDid, verifyLog, type DataIntegrityProof, type Did } from "@did-guardian/lib";

/**
 * F6 (SSRF + sign-arbitrary-operation): `domain` used to be a free-text
 * field, so this page would fetch and sign whatever an attacker named --
 * an SSRF to any host, and a proof over an operation the signer has no
 * actual relationship to. Relay-signing exists for a guardian to sign
 * for a ward hosted elsewhere, so the only domains ever fetched are
 * domains of this signer's OWN current wards (never a caller-supplied
 * string), and the target DID the remote operation claims must actually
 * be one of them too.
 */
async function allowedWardDids(env: Env, signerDid: Did): Promise<Set<Did>> {
  const log = await getLog(env, signerDid);
  if (log.length === 0) return new Set();
  const verified = await verifyLog(signerDid, log);
  if (verified.result !== "valid") return new Set();
  return new Set(verified.state!.wards.map((w) => w.did));
}

interface RemotePendingStatus {
  did: Did;
  operation: { type: string };
  proofsCollected: number;
  expiresAt: string;
}

function wellKnownPath(name: string | null): string {
  return `/.well-known/guardian/${name ?? "_"}`;
}

async function fetchRemoteStatus(domain: string, opId: string): Promise<RemotePendingStatus> {
  let resp: Response;
  try {
    resp = await fetch(`https://${domain}/.well-known/guardian/pending/${opId}`, { headers: { accept: "application/json" } });
  } catch {
    throw new RegistrarError(`couldn't reach ${domain} to look up this operation`, 502);
  }
  if (!resp.ok) throw new RegistrarError(`${domain} has no such pending operation (status ${resp.status})`, resp.status === 404 ? 404 : 502);
  return (await resp.json()) as RemotePendingStatus;
}

function reviewBody(opId: string, status: RemotePendingStatus, signerDid: string, opts: { error?: string } = {}): string {
  return `
    <h1>Sign for ${escapeHtml(signerDid)}</h1>
    <p class="hint">A <strong>${escapeHtml(status.operation.type)}</strong> operation on ${escapeHtml(status.did)} (hosted on a different registrar) needs your signature.</p>
    ${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
    <dl>
      <dt>Proofs collected so far</dt><dd>${status.proofsCollected}</dd>
      <dt>Expires</dt><dd>${escapeHtml(status.expiresAt)}</dd>
    </dl>
    <h2>Operation</h2>
    <pre style="background:var(--muted-200,#f0f0f0); padding:12px; border-radius:6px; overflow-x:auto; font-size:13px;"><code>${escapeHtml(JSON.stringify(status.operation, null, 2))}</code></pre>
    <form method="post" action="/relay-sign">
      <input type="hidden" name="domain" value="${escapeHtml(parseGuardianDid(status.did)!.domain)}">
      <input type="hidden" name="op" value="${escapeHtml(opId)}">
      <button type="submit">Sign</button>
    </form>
  `;
}

/** GET /relay-sign?domain=<registrar-domain>&op=<id> -- review page, session-gated. */
export async function handleRelaySignPage(request: Request, env: Env, url: URL): Promise<Response> {
  const domain = url.searchParams.get("domain") ?? "";
  const opId = url.searchParams.get("op") ?? "";
  if (!domain || !opId) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">Missing domain or op.</p>`), 400);

  const returnTo = `/relay-sign?domain=${encodeURIComponent(domain)}&op=${encodeURIComponent(opId)}`;
  const sessionId = readCookie(request, "gw_session");
  const signerDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (!signerDid) {
    return new Response(null, { status: 302, headers: { location: `/guardian-login?return_to=${encodeURIComponent(returnTo)}` } });
  }

  const wardDids = await allowedWardDids(env, signerDid as Did);
  if (![...wardDids].some((w) => parseGuardianDid(w)?.domain === domain)) {
    return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">You aren't a guardian of any ward on ${escapeHtml(domain)}.</p>`), 403);
  }

  let status: RemotePendingStatus;
  try {
    status = await fetchRemoteStatus(domain, opId);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }
  if (!wardDids.has(status.did)) {
    return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">This operation isn't for a ward you're a guardian of.</p>`), 403);
  }
  return html(pageShell("Sign elsewhere", reviewBody(opId, status, signerDid)));
}

/** POST /relay-sign -- session-gated. Re-fetches the operation fresh; nothing from the GET above is trusted here. */
export async function handleRelaySignSubmit(request: Request, env: Env): Promise<Response> {
  const form = await safeFormData(request);
  const domain = String(form.get("domain") ?? "");
  const opId = String(form.get("op") ?? "");
  if (!domain || !opId) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">Missing domain or op.</p>`), 400);

  const sessionId = readCookie(request, "gw_session");
  const signerDid = (sessionId ? await resolveSession(env, sessionId) : null) as Did | null;
  if (!signerDid) return html(pageShell("Sign in required", `<h1>Sign in required</h1><p class="error">You need to be signed in to sign this.</p>`), 401);
  const auth = await authenticateRequest(request, env, signerDid);
  if (!auth) return html(pageShell("Sign in required", `<h1>Sign in required</h1><p class="error">You need to be signed in to sign this.</p>`), 401);

  // F6: domain and opId are caller-supplied, but this registrar only
  // ever fetches/signs for a domain and DID that this signer's own
  // current log actually lists as a ward -- never a free-text target.
  const wardDids = await allowedWardDids(env, signerDid);
  if (![...wardDids].some((w) => parseGuardianDid(w)?.domain === domain)) {
    return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">You aren't a guardian of any ward on ${escapeHtml(domain)}.</p>`), 403);
  }

  let status: RemotePendingStatus;
  try {
    status = await fetchRemoteStatus(domain, opId);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }
  if (!wardDids.has(status.did)) {
    return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">This operation isn't for a ward you're a guardian of.</p>`), 403);
  }

  let proof: DataIntegrityProof;
  try {
    proof = await signAs(env, auth, signerDid, status.operation);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Sign elsewhere", reviewBody(opId, status, signerDid, { error: e.message })), e.status);
    throw e;
  }

  let signResp: Response;
  try {
    signResp = await fetch(`https://${domain}/.well-known/guardian/pending/${opId}/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ proof }),
    });
  } catch {
    return html(pageShell("Sign elsewhere", reviewBody(opId, status, signerDid, { error: `Produced a signature, but couldn't reach ${domain} to submit it. Try again.` })), 502);
  }
  if (!signResp.ok) {
    const body = (await signResp.json().catch(() => ({ error: "unknown error" }))) as { error?: string };
    return html(
      pageShell("Sign elsewhere", reviewBody(opId, status, signerDid, { error: body.error ?? `${domain} rejected the signature (status ${signResp.status})` })),
      signResp.status,
    );
  }
  return html(pageShell("Signed", `<h1>Signed</h1><p class="hint">Your signature as ${escapeHtml(signerDid)} was submitted to ${escapeHtml(domain)}.</p>`));
}
