// The browser voting UI -- a real status page, linked from pending-op
// notification emails, with real POST buttons for Sign/Decline/Withdraw.
//
// Deliberately NOT a bare clickable GET action link: an email client's own
// link-prefetching security scanner (Microsoft Safe Links, a corporate
// proxy, antivirus) will visit a link the moment the message arrives, long
// before a person ever reads it -- if that GET itself performed the
// action, the proposal could be declined or withdrawn by a scanner, never
// by the person it was addressed to. Landing on a real page that still
// requires an explicit button click (a real POST) is the fix, the same
// reasoning as "never delete via GET" generally.
//
// Decline/withdraw on this page use the token already in the URL (email
// possession is the proof, same as the registrar API's own token-based
// routes). Signing is a different, higher-stakes action -- it grants real
// authority (e.g. a new guardian) rather than only ever blocking or
// abstaining -- so it requires a real authenticated session, not just the
// token, via this registrar's own existing login_secret/gw_session flow.

import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { html, escapeHtml, pageShell, authPageShell } from "./htmlPage.js";
import { readCookie, resolveSession, verifyLogin, createLoginSession } from "./login.js";
import { getPendingOperationStatus, contributeToOperation, type PendingOperationStatus } from "./pendingOps.js";
import { getPendingOperation, getWardByDid } from "./db.js";
import { checkRateLimit, clientIp } from "./rateLimit.js";
import { decryptWardPrivateKey, RegistrarError } from "./registrar.js";
import { signPayload } from "@did-guardian/lib";

const SESSION_COOKIE = "gw_session";

/** Only ever a same-origin relative path -- never follow an open redirect to an arbitrary external target. Exported for registerPage.ts's own return_to handling, the same convention. */
export function isSafeReturnTo(path: string): boolean {
  return path.startsWith("/") && !path.startsWith("//") && !path.startsWith("/\\");
}

function statusLabel(state: string): string {
  const labels: Record<string, string> = {
    collecting: "Collecting signatures",
    satisfied: "Satisfied -- finalizing",
    finalized: "Finalized",
    declined: "Declined (vetoed)",
    expired: "Expired",
  };
  return labels[state] ?? state;
}

function signersList(status: PendingOperationStatus): string {
  const signed = new Set(status.signed);
  return `<ul class="signers">${status.required_signers
    .map((did) => `<li>${escapeHtml(did)} <span class="badge ${signed.has(did) ? "yes" : "no"}">${signed.has(did) ? "signed" : "waiting"}</span></li>`)
    .join("")}</ul>`;
}

/**
 * Renders the status page. `token` (if the viewer arrived via an email
 * link) and `sessionWardDid` (if logged in) are both optional and
 * independent -- either, both, or neither may be present, and the page
 * adapts: decline/withdraw need the token, sign needs the session.
 */
export async function renderPendingOpPage(env: Env, wardName: string, id: string, token: string | null, sessionWardDid: string | null): Promise<Response> {
  const wardDid = didFor(wardName === "_" ? null : wardName, env.REGISTRAR_DOMAIN);
  let status: PendingOperationStatus;
  try {
    status = await getPendingOperationStatus(env, wardDid, id);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Not found", `<h1>Not found</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }

  const selfUrl = `/.well-known/guardian/${wardName}/pending/${id}${token ? `?token=${encodeURIComponent(token)}` : ""}`;
  const isCollecting = status.state === "collecting";
  const alreadySigned = sessionWardDid ? status.signed.includes(sessionWardDid) : false;
  const sessionIsRequired = sessionWardDid ? status.required_signers.includes(sessionWardDid) : false;

  let actions = "";
  if (isCollecting) {
    if (sessionWardDid && sessionIsRequired && !alreadySigned) {
      actions += `<form method="post" action="/.well-known/guardian/${wardName}/pending/${id}/sign-as-self"><button type="submit">Sign as ${escapeHtml(sessionWardDid)}</button></form>`;
    } else if (!sessionWardDid) {
      actions += `<p><a href="/guardian-login?return_to=${encodeURIComponent(selfUrl)}">Log in to sign</a></p>`;
    } else if (!sessionIsRequired) {
      actions += `<p class="hint">Signed in as ${escapeHtml(sessionWardDid)}, which isn't a required signer for this proposal.</p>`;
    } else {
      actions += `<p class="hint">Your signature as ${escapeHtml(sessionWardDid)} has already been recorded.</p>`;
    }
    if (token) {
      actions += `
        <form method="post" action="/.well-known/guardian/${wardName}/pending/${id}/decline"><input type="hidden" name="token" value="${escapeHtml(token)}"><button type="submit" class="danger">Veto (decline)</button></form>
        <form method="post" action="/.well-known/guardian/${wardName}/pending/${id}/withdraw"><input type="hidden" name="token" value="${escapeHtml(token)}"><button type="submit" class="neutral">Withdraw (opt out, doesn't block)</button></form>
      `;
    }
  }

  const body = `
    <h1>${escapeHtml(status.op_type)}</h1>
    <p class="hint">for ${escapeHtml(wardDid)}</p>
    <dl>
      <dt>Status</dt><dd><span class="state">${escapeHtml(statusLabel(status.state))}</span></dd>
      <dt>Required signers</dt><dd>${signersList(status)}</dd>
      <dt>Expires</dt><dd>${escapeHtml(status.expires_at)}</dd>
    </dl>
    ${actions}
  `;
  return html(pageShell(`${status.op_type} -- did:guardian`, body));
}

/** POST .../pending/<id>/sign-as-self -- gw_session-gated. Signs server-side with the key this registrar already custodies for the logged-in identity, same model as /adopt and /rotate; never for an identity hosted elsewhere, which this registrar has no key for. */
export async function signAsSelf(request: Request, env: Env, id: string): Promise<Response> {
  const sessionId = readCookie(request, SESSION_COOKIE);
  const wardDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (!wardDid) return html(pageShell("Sign in required", `<h1>Sign in required</h1><p class="error">You need to be signed in to sign this.</p>`), 401);

  const row = await getPendingOperation(env, id);
  if (!row) return html(pageShell("Not found", `<h1>Not found</h1><p class="error">No such pending operation.</p>`), 404);
  const ward = await getWardByDid(env, wardDid);
  if (!ward) return html(pageShell("Error", `<h1>Error</h1><p class="error">Your own identity isn't custodied by this registrar.</p>`), 500);

  const op = JSON.parse(row.partial_op) as { sig?: unknown; sigs?: unknown };
  const { sig: _sig, sigs: _sigs, ...payload } = op;
  const privateKey = await decryptWardPrivateKey(env, ward);
  const mySig = await signPayload(payload, privateKey);

  try {
    await contributeToOperation(env, id, wardDid, mySig);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Couldn't sign", `<h1>Couldn't sign</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }

  const name = await nameForUrl(env, row.ward_did);
  return new Response(null, { status: 302, headers: { location: `/.well-known/guardian/${name}/pending/${id}` } });
}

async function nameForUrl(env: Env, wardDid: string): Promise<string> {
  const ward = await getWardByDid(env, wardDid);
  return ward && ward.name !== "" ? ward.name : "_";
}

/** GET/POST /guardian-login?return_to=<path> -- this registrar's own first-party login, distinct from the OIDC /authorize relying-party flow (oidc.ts): no client_id/redirect_uri registration, just "I am this identity, take me back to the page I came from." Same credential (login_secret) and session cookie either way. */
export async function handleDirectLogin(request: Request, env: Env, url: URL): Promise<Response> {
  const returnTo = url.searchParams.get("return_to") ?? "/";
  const safeReturnTo = isSafeReturnTo(returnTo) ? returnTo : "/";

  if (request.method === "POST") {
    const form = await request.formData();
    const name = String(form.get("name") ?? "");
    const loginSecret = String(form.get("login_secret") ?? "");
    const formReturnTo = String(form.get("return_to") ?? "/");
    const safeFormReturnTo = isSafeReturnTo(formReturnTo) ? formReturnTo : "/";
    // Public and CPU-bound (PBKDF2) -- rate-limited per IP before verifying,
    // same reasoning as /register (index.ts). A real credential check still
    // runs on every allowed attempt; this only caps the attempt rate.
    if (!(await checkRateLimit(env, "login", clientIp(request), 10, 600))) {
      return html(authPageShell("Sign in", loginFormBody(safeFormReturnTo, { nameValue: name, error: "Too many sign-in attempts from this address. Try again in a few minutes." })), 429);
    }
    const wardDid = await verifyLogin(env, name, loginSecret);
    if (!wardDid) {
      return html(authPageShell("Sign in", loginFormBody(safeFormReturnTo, { nameValue: name, error: "Invalid name or login secret." })), 401);
    }
    const sessionId = await createLoginSession(env, wardDid);
    return new Response(null, {
      status: 302,
      headers: {
        location: safeFormReturnTo,
        "set-cookie": `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
      },
    });
  }

  return html(authPageShell("Sign in", loginFormBody(safeReturnTo, {})));
}

function loginFormBody(returnTo: string, opts: { nameValue?: string; error?: string }): string {
  return `
    <section class="signin-hero">
      <div class="signin-grid">
        <div class="signin-copy">
          <h1>Sign in with your <span class="hl">Guardian ID</span></h1>
          <p>Your name alone (e.g. "alice") or your full id (e.g. "alice@acme.com") both work -- the domain part is ignored here if you include it. Plus the login secret you were shown once when it was created.</p>
        </div>
        <div class="signin-card">
          ${opts.error ? `<p class="error"><i class="ph ph-warning-circle"></i> ${escapeHtml(opts.error)}</p>` : ""}
          <form method="post" action="/guardian-login">
            <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
            <label>Name <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autofocus required></label>
            <label>Login secret <small>(shown once, at creation)</small></label>
            <div class="field-eye">
              <input id="login-secret-field" name="login_secret" type="password" required>
              <button type="button" aria-label="Show login secret" onclick="var f=document.getElementById('login-secret-field'); var show=f.type==='password'; f.type=show?'text':'password'; this.querySelector('i').className=show?'ph ph-eye-slash':'ph ph-eye';"><i class="ph ph-eye"></i></button>
            </div>
            <button type="submit">Sign in</button>
          </form>
          <p style="text-align:center; margin-top: 1rem;"><a href="/register?return_to=${encodeURIComponent(returnTo)}">Don't have an account? Create one</a></p>
        </div>
      </div>
    </section>
  `;
}
