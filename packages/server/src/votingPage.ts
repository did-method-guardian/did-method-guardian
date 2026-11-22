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
import { safeFormData } from "./http.js";
import { didFor } from "./env.js";
import { html, escapeHtml, pageShell, authPageShell } from "./htmlPage.js";
import { readCookie, resolveSession, verifyLogin, createLoginSession, endSession } from "./login.js";
import { getPendingOperationStatus, contributeProof, cancelPendingOperation } from "./pendingProofs.js";
import { checkRateLimit, clientIp } from "./rateLimit.js";
import { signAs } from "./signing.js";
import { RegistrarError } from "./registrarError.js";
import type { Did } from "@did-guardian/lib";

const SESSION_COOKIE = "gw_session";

/** Only ever a same-origin relative path -- never follow an open redirect to an arbitrary external target. Exported for registerPage.ts's own return_to handling, the same convention. */
export function isSafeReturnTo(path: string): boolean {
  return path.startsWith("/") && !path.startsWith("//") && !path.startsWith("/\\");
}

/**
 * Renders the status page. `sessionWardDid` (if logged in) is the only
 * thing that changes what's offered: signing needs a session (this
 * registrar signs server-side with whatever held key that session's
 * own identity has); withdrawing needs the session to belong to the
 * proposal's own did (nothing else can withdraw someone else's proposal).
 */
export async function renderPendingOpPage(env: Env, wardName: string, id: string, sessionWardDid: Did | null): Promise<Response> {
  const wardDid = didFor(wardName === "_" ? null : wardName, env.REGISTRAR_DOMAIN) as Did;
  let status: Awaited<ReturnType<typeof getPendingOperationStatus>>;
  try {
    status = await getPendingOperationStatus(env, id);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Not found", `<h1>Not found</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }
  if (status.did !== wardDid) return html(pageShell("Not found", `<h1>Not found</h1><p class="error">No such pending operation for this identity.</p>`), 404);
  const opType = (status.operation as { type: string }).type;

  let actions = "";
  if (sessionWardDid) {
    actions += `<form method="post" action="/.well-known/guardian/${wardName}/pending/${id}/sign-as-self"><button type="submit">Sign as ${escapeHtml(sessionWardDid)}</button></form>`;
    if (sessionWardDid === wardDid) {
      actions += `<form method="post" action="/.well-known/guardian/${wardName}/pending/${id}/withdraw"><button type="submit" class="danger">Withdraw this proposal</button></form>`;
    }
  } else {
    const selfUrl = `/.well-known/guardian/${wardName}/pending/${id}`;
    actions += `<p><a href="/guardian-login?return_to=${encodeURIComponent(selfUrl)}">Log in to sign</a></p>`;
  }

  const body = `
    <h1>${escapeHtml(opType)}</h1>
    <p class="hint">for ${escapeHtml(wardDid)}</p>
    <dl>
      <dt>Proofs collected so far</dt><dd>${status.proofs.length}</dd>
      <dt>Expires</dt><dd>${escapeHtml(status.expiresAt)}</dd>
    </dl>
    ${actions}
  `;
  return html(pageShell(`${opType} -- did:guardian`, body));
}

/** POST .../pending/<id>/sign-as-self -- gw_session-gated. Signs server-side with the key this registrar already custodies for the logged-in identity, same model as /rotate; never for an identity hosted elsewhere, which this registrar has no key for. */
export async function signAsSelf(request: Request, env: Env, wardName: string, id: string): Promise<Response> {
  const sessionId = readCookie(request, SESSION_COOKIE);
  const signerDid = sessionId ? ((await resolveSession(env, sessionId)) as Did | null) : null;
  if (!signerDid) return html(pageShell("Sign in required", `<h1>Sign in required</h1><p class="error">You need to be signed in to sign this.</p>`), 401);

  let status: { operation: object };
  try {
    status = await getPendingOperationStatus(env, id);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Not found", `<h1>Not found</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }

  let proof;
  try {
    proof = await signAs(env, signerDid, signerDid, status.operation);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Couldn't sign", `<h1>Couldn't sign</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }

  try {
    await contributeProof(env, id, proof);
  } catch (e) {
    if (e instanceof RegistrarError) return html(pageShell("Couldn't sign", `<h1>Couldn't sign</h1><p class="error">${escapeHtml(e.message)}</p>`), e.status);
    throw e;
  }

  return new Response(null, { status: 302, headers: { location: `/.well-known/guardian/${wardName}/pending/${id}` } });
}

/** POST .../pending/<id>/withdraw -- gw_session-gated, and only the proposal's own did may withdraw it (checked by the caller before this is reached). */
export async function withdrawAsSelf(env: Env, id: string): Promise<void> {
  await cancelPendingOperation(env, id);
}

/** GET/POST /guardian-login?return_to=<path> -- this registrar's own first-party login, distinct from the OIDC /authorize relying-party flow (oidc.ts): no client_id/redirect_uri registration, just "I am this identity, take me back to the page I came from." Same credential (login_secret) and session cookie either way. */
export async function handleDirectLogin(request: Request, env: Env, url: URL): Promise<Response> {
  const returnTo = url.searchParams.get("return_to") ?? "/";
  const safeReturnTo = isSafeReturnTo(returnTo) ? returnTo : "/";

  if (request.method === "POST") {
    const form = await safeFormData(request);
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
            <label>Name <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autocomplete="username" autofocus required></label>
            <label>Login secret <small>(shown once, at creation)</small></label>
            <div class="field-eye">
              <input id="login-secret-field" name="login_secret" type="password" autocomplete="current-password" required>
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

/**
 * POST /guardian-logout?return_to=<path> -- named "-logout" (not "/logout")
 * for the same reason "/guardian-login" isn't "/login": zz-maintainer's own
 * catch-all already serves a bare "/logout" of its own on zzmq.dev,
 * confirmed by reading its route table directly, not assumed.
 *
 * There was no way to end a session at all before this -- confirmed a real
 * gap, not theoretical: a stale session from an earlier login silently
 * authenticated a relying-party flow as the wrong identity, with no way to
 * clear it short of the browser's own cookie TTL or manually deleting
 * cookies. POST, not GET, same reasoning as every other state-changing
 * action here (an email client's own link-prefetch scanner must never be
 * able to trigger this just by visiting a link).
 */
export async function handleLogout(request: Request, env: Env, url: URL): Promise<Response> {
  const returnTo = url.searchParams.get("return_to") ?? "/";
  const safeReturnTo = isSafeReturnTo(returnTo) ? returnTo : "/";
  const sessionId = readCookie(request, SESSION_COOKIE);
  if (sessionId) await endSession(env, sessionId);
  return new Response(null, {
    status: 302,
    headers: {
      location: safeReturnTo,
      "set-cookie": `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`,
    },
  });
}
