// Cross-registrar signature relay: lets a guardian who is custodial on
// *this* registrar review and sign a pending operation that actually lives
// on a DIFFERENT registrar (the ward's own) -- the gap that meant
// cross-domain guardianship had only ever been verified via a self-held-key
// simulation, never a real custodial-to-custodial flow (a guardian's
// private key lives server-side on their own registrar and is never
// exposed to them, so they can't produce a raw signature themselves the way
// a self-held-key external guardian can).
//
// Nothing here is trusted blindly: every fact about the operation (its
// type, required signers, whether this guardian already signed, the exact
// payload to sign) is fetched live from the ward's own registrar on every
// request, never cached or taken from a query string or an email. The
// resulting signature is, as always, independently verified by the ward's
// own registrar via its existing, already-unauthenticated /sign endpoint --
// this page only ever produces a signature using a key this registrar
// already custodies for its own logged-in ward, the exact same pair
// (decryptWardPrivateKey + signPayload) votingPage.ts's signAsSelf already
// uses for same-registrar operations.

import type { Env } from "./env.js";
import { html, escapeHtml, pageShell } from "./htmlPage.js";
import { readCookie, resolveSession } from "./login.js";
import { getWardByDid } from "./db.js";
import { decryptWardPrivateKey, RegistrarError } from "./registrar.js";
import { signPayload, parseDid, wellKnownPath, type Did } from "@did-guardian/lib";

interface RemotePendingStatus {
  id: string;
  op_type: string;
  state: string;
  required_signers: string[];
  signed: string[];
  expires_at: string;
  unsigned_payload: unknown;
}

async function fetchRemoteStatus(wardDid: string, opId: string): Promise<RemotePendingStatus> {
  let name: string | null, domain: string;
  try {
    ({ name, domain } = parseDid(wardDid as Did));
  } catch {
    throw new RegistrarError("not a valid did:guardian identifier", 400);
  }
  let resp: Response;
  try {
    resp = await fetch(`https://${domain}${wellKnownPath(name)}/pending/${opId}`, { headers: { accept: "application/json" } });
  } catch {
    throw new RegistrarError(`couldn't reach ${domain} to look up this operation`, 502);
  }
  if (!resp.ok) throw new RegistrarError(`${domain} has no such pending operation (status ${resp.status})`, resp.status === 404 ? 404 : 502);
  return (await resp.json()) as RemotePendingStatus;
}

function reviewBody(wardDid: string, opId: string, status: RemotePendingStatus, signerDid: string, opts: { error?: string } = {}): string {
  const alreadySigned = status.signed.includes(signerDid);
  return `
    <h1>Sign for ${escapeHtml(signerDid)}</h1>
    <p class="hint">A <strong>${escapeHtml(status.op_type)}</strong> operation on ${escapeHtml(wardDid)} (hosted on a different registrar) needs your signature.</p>
    ${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
    <dl>
      <dt>Status</dt><dd>${escapeHtml(status.state)}</dd>
      <dt>Required signers</dt><dd>${status.required_signers.map(escapeHtml).join(", ")}</dd>
      <dt>Already signed</dt><dd>${status.signed.length ? status.signed.map(escapeHtml).join(", ") : "none yet"}</dd>
      <dt>Expires</dt><dd>${escapeHtml(status.expires_at)}</dd>
    </dl>
    <h2>Payload to be signed</h2>
    <pre style="background:var(--muted-200,#f0f0f0); padding:12px; border-radius:6px; overflow-x:auto; font-size:13px;"><code>${escapeHtml(JSON.stringify(status.unsigned_payload, null, 2))}</code></pre>
    ${
      alreadySigned
        ? `<p class="hint">You've already signed this.</p>`
        : `<form method="post" action="/relay-sign">
             <input type="hidden" name="ward" value="${escapeHtml(wardDid)}">
             <input type="hidden" name="op" value="${escapeHtml(opId)}">
             <button type="submit">Approve &amp; sign</button>
           </form>`
    }
  `;
}

/** GET /relay-sign?ward=<did>&op=<id> -- review page, session-gated. */
export async function handleRelaySignPage(request: Request, env: Env, url: URL): Promise<Response> {
  const wardDid = url.searchParams.get("ward") ?? "";
  const opId = url.searchParams.get("op") ?? "";
  if (!wardDid || !opId) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">Missing ward or op.</p>`), 400);

  const returnTo = `/relay-sign?ward=${encodeURIComponent(wardDid)}&op=${encodeURIComponent(opId)}`;
  const sessionId = readCookie(request, "gw_session");
  const signerDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (!signerDid) {
    return new Response(null, { status: 302, headers: { location: `/guardian-login?return_to=${encodeURIComponent(returnTo)}` } });
  }
  const ward = await getWardByDid(env, signerDid);
  if (!ward) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">Your own identity isn't custodied by this registrar.</p>`), 500);

  let status: RemotePendingStatus;
  try {
    status = await fetchRemoteStatus(wardDid, opId);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }
  if (!status.required_signers.includes(signerDid)) {
    return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">${escapeHtml(signerDid)} isn't a required signer for this operation.</p>`), 403);
  }
  return html(pageShell("Sign elsewhere", reviewBody(wardDid, opId, status, signerDid)));
}

/** POST /relay-sign -- approve and sign, session-gated. Re-verifies everything server-side; nothing from the GET above is trusted here. */
export async function handleRelaySignApprove(request: Request, env: Env): Promise<Response> {
  const form = await request.formData();
  const wardDid = String(form.get("ward") ?? "");
  const opId = String(form.get("op") ?? "");
  if (!wardDid || !opId) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">Missing ward or op.</p>`), 400);

  const sessionId = readCookie(request, "gw_session");
  const signerDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (!signerDid) return html(pageShell("Sign in required", `<h1>Sign in required</h1><p class="error">You need to be signed in to sign this.</p>`), 401);
  const ward = await getWardByDid(env, signerDid);
  if (!ward) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">Your own identity isn't custodied by this registrar.</p>`), 500);

  let status: RemotePendingStatus;
  try {
    status = await fetchRemoteStatus(wardDid, opId);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }
  if (!status.required_signers.includes(signerDid)) {
    return html(pageShell("Sign elsewhere", `<h1>Sign elsewhere</h1><p class="error">${escapeHtml(signerDid)} isn't a required signer for this operation.</p>`), 403);
  }
  if (status.signed.includes(signerDid)) {
    return html(pageShell("Sign elsewhere", reviewBody(wardDid, opId, status, signerDid)));
  }

  const privateKey = await decryptWardPrivateKey(env, ward);
  const mySig = await signPayload(status.unsigned_payload, privateKey);

  const { name, domain } = parseDid(wardDid as Did);
  let signResp: Response;
  try {
    signResp = await fetch(`https://${domain}${wellKnownPath(name)}/pending/${opId}/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signer_did: signerDid, sig: mySig }),
    });
  } catch {
    return html(pageShell("Sign elsewhere", reviewBody(wardDid, opId, status, signerDid, { error: `Produced a signature, but couldn't reach ${domain} to submit it. Try again.` })), 502);
  }
  if (!signResp.ok) {
    const body = (await signResp.json().catch(() => ({ error: "unknown error" }))) as { error?: string };
    return html(
      pageShell("Sign elsewhere", reviewBody(wardDid, opId, status, signerDid, { error: body.error ?? `${domain} rejected the signature (status ${signResp.status})` })),
      signResp.status,
    );
  }
  return html(pageShell("Signed", `<h1>Signed</h1><p class="hint">Your signature as ${escapeHtml(signerDid)} was submitted to ${escapeHtml(domain)}.</p>`));
}
