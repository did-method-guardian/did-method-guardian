// The admin console -- lets a registrar's own root identity (the only
// identity that can plausibly claim "I operate this domain," same test
// ROOT_WARD_NAME already establishes) list and create accounts for other
// people or agents on this registrar, without exposing public self-service
// registration (REGISTRATION_MODE=closed, env.ts). Available on every
// deployment regardless of that setting -- a generically useful capability
// for any operator, not just closed ones. Same first-party-HTML-page
// pattern as accountPage.ts/registerPage.ts, wrapping the exact same
// registerWard function those already use, never a separate code path.

import type { Env } from "./env.js";
import { html, escapeHtml, pageShell, secretBox } from "./htmlPage.js";
import { readCookie, resolveSession } from "./login.js";
import { registerWard, RegistrarError } from "./registrar.js";
import { registerOidcClient } from "./oidc.js";
import { getWardByDid, listWards, listOidcClients, deleteOidcClient, type WardRow } from "./db.js";

const SESSION_COOKIE = "gw_session";
const MIN_PASSWORD_LENGTH = 12;

async function requireRootSession(request: Request, env: Env): Promise<WardRow | Response> {
  const sessionId = readCookie(request, SESSION_COOKIE);
  const wardDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (!wardDid) {
    return new Response(null, { status: 302, headers: { location: `/guardian-login?return_to=${encodeURIComponent("/admin")}` } });
  }
  const ward = await getWardByDid(env, wardDid);
  if (!ward || ward.name !== "") {
    return html(pageShell("Not available", `<h1>Not available</h1><p class="error">This page is only available to this registrar's own root identity.</p>`), 403);
  }
  return ward;
}

export async function handleAdminPage(request: Request, env: Env): Promise<Response> {
  const session = await requireRootSession(request, env);
  if (session instanceof Response) return session;

  const wards = await listWards(env);
  const rows = wards.length
    ? `<ul class="signers">${wards
        .map((w) => `<li>${escapeHtml(w.name || "_ (root)")} -- ${escapeHtml(w.did)} <span class="hint">(created ${escapeHtml(w.created_at)})</span></li>`)
        .join("")}</ul>`
    : `<p class="hint">No accounts yet.</p>`;

  const body = `
    <h1>Admin console</h1>
    <p class="hint">Accounts on this registrar -- ${wards.length} total.</p>
    ${rows}
    <p><a href="/admin/create-account">Create a new account</a></p>
    <p><a href="/admin/apps">Manage OAuth apps</a> <span class="hint">(for third-party sign-in integrations like Tailscale, Vercel, etc.)</span></p>
    <p><a href="/account">Back to your own account</a></p>
  `;
  return html(pageShell("Admin console", body));
}

function createAccountFormBody(opts: { nameValue?: string; error?: string; credentialMode?: "generate" | "password" } = {}): string {
  const mode = opts.credentialMode ?? "generate";
  return `
    <h1>Create an account</h1>
    <p class="hint">For a team member, family member, or an agent you manage. They can sign in with the name below, or change their own password any time afterward from their own account dashboard.</p>
    ${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
    <form method="post" action="/admin/create-account" id="admin-create-form">
      <label>Name <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autocomplete="username" autofocus required pattern="[a-z0-9][a-z0-9-]{1,30}[a-z0-9]"></label>
      <label>Guardian DID <small>(optional -- e.g. your own, to oversee this account)</small> <input name="guardian_did" placeholder="did:guardian:..."></label>
      <fieldset style="border:0; padding:0; margin:1rem 0 0;">
        <label style="display:flex; align-items:center; gap:.4rem; font-weight:400;"><input type="radio" name="credential_mode" value="generate" ${mode === "generate" ? "checked" : ""} style="display:inline; width:auto; min-height:0;"> Generate a secure login secret</label>
        <label style="display:flex; align-items:center; gap:.4rem; font-weight:400; margin-top:.4rem;"><input type="radio" name="credential_mode" value="password" ${mode === "password" ? "checked" : ""} style="display:inline; width:auto; min-height:0;"> Set an initial password myself</label>
      </fieldset>
      <div id="password-fields" ${mode === "password" ? "" : "hidden"}>
        <label>Password <small>(at least ${MIN_PASSWORD_LENGTH} characters)</small> <input id="password-field" type="password" name="password" autocomplete="new-password" minlength="${MIN_PASSWORD_LENGTH}" ${mode === "password" ? "required" : ""}></label>
        <label>Confirm password <input id="password-confirm-field" type="password" name="password_confirm" autocomplete="new-password" minlength="${MIN_PASSWORD_LENGTH}" ${mode === "password" ? "required" : ""}></label>
      </div>
      <button type="submit">Create account</button>
    </form>
    <p><a href="/admin">Back to admin console</a></p>
    <script>
      (function () {
        var form = document.getElementById('admin-create-form');
        var fields = document.getElementById('password-fields');
        var pw = document.getElementById('password-field');
        var confirm = document.getElementById('password-confirm-field');
        function sync() {
          var isPassword = form.credential_mode.value === 'password';
          fields.hidden = !isPassword;
          pw.required = isPassword;
          confirm.required = isPassword;
        }
        Array.prototype.forEach.call(form.credential_mode, function (r) { r.addEventListener('change', sync); });
        sync();
      })();
    </script>
  `;
}

export async function handleAdminCreateAccountPage(request: Request, env: Env): Promise<Response> {
  const session = await requireRootSession(request, env);
  if (session instanceof Response) return session;
  return html(pageShell("Create account", createAccountFormBody()));
}

export async function handleAdminCreateAccountForm(request: Request, env: Env): Promise<Response> {
  const session = await requireRootSession(request, env);
  if (session instanceof Response) return session;

  const form = await request.formData();
  const name = String(form.get("name") ?? "");
  const guardianDidRaw = String(form.get("guardian_did") ?? "").trim();
  const guardianDid = guardianDidRaw || null;
  const credentialMode = form.get("credential_mode") === "password" ? "password" : "generate";

  let password: string | undefined;
  if (credentialMode === "password") {
    const pw = String(form.get("password") ?? "");
    const confirm = String(form.get("password_confirm") ?? "");
    if (pw.length < MIN_PASSWORD_LENGTH) {
      return html(pageShell("Create account", createAccountFormBody({ nameValue: name, credentialMode, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` })), 400);
    }
    if (pw !== confirm) {
      return html(pageShell("Create account", createAccountFormBody({ nameValue: name, credentialMode, error: "Passwords don't match." })), 400);
    }
    password = pw;
  }

  let result: { did: string; document: unknown; login_secret?: string; pending_guardian_add?: { id: string } };
  try {
    result = await registerWard(env, name, guardianDid, password);
  } catch (e) {
    if (e instanceof RegistrarError) {
      return html(pageShell("Create account", createAccountFormBody({ nameValue: name, credentialMode, error: e.message })), e.status);
    }
    throw e;
  }

  const body = `
    <h1>Account created</h1>
    <p class="hint">${escapeHtml(result.did)}</p>
    ${
      result.login_secret
        ? `<p class="hint">Login secret -- shown once, right now. Relay it to whoever this account is for; there's no other way to see it again (though they can always issue a new one, or set their own password, from their own account dashboard).</p>
           <dl><dt>Login secret</dt><dd>${secretBox(result.login_secret)}</dd></dl>`
        : `<p class="hint">The password you set is ready to use -- share it with whoever this account is for; they can change it any time from their own account dashboard.</p>`
    }
    ${result.pending_guardian_add ? `<p class="hint">The named guardian is hosted on a different registrar -- waiting on their own signature before it takes effect (pending operation <code>${escapeHtml(result.pending_guardian_add.id)}</code>).</p>` : ""}
    <p><a href="/admin/create-account">Create another</a> -- <a href="/admin">Back to admin console</a></p>
  `;
  return html(pageShell("Account created", body), 201);
}

// OAuth Apps -- the admin-console UI for RFC 7591 dynamic client
// registration (oidc.ts), for a third-party product's own "custom OIDC"
// integration (Tailscale, Vercel, etc.): the registrar-wide equivalent of
// "create an account," but for an application instead of a person. One
// app registration here serves every account on this registrar, the same
// way a company's own Okta/Azure AD admin sets up a third-party
// integration once for the whole directory, not once per employee --
// registering a client was never tied to any one ward (no owner column on
// oidc_clients), this just gives that existing fact a UI instead of
// requiring curl and raw JSON to use it.
//
// Deliberately minimal: name + one or more redirect URIs is everything a
// real third-party integration's own setup docs ever ask the admin to
// provide on this side. Always a confidential client (client_secret_basic)
// -- a public client (token_endpoint_auth_method: "none") is for a
// different situation (a native/mobile app with no secret to protect)
// that doesn't fit "set up Tailscale SSO," and isn't exposed here to keep
// the form from asking a non-technical admin to make a decision that
// doesn't apply to what they're actually doing.

function appsListBody(apps: Array<{ client_id: string; name: string; redirect_uris: string; created_at: string }>): string {
  const rows = apps.length
    ? `<ul class="signers">${apps
        .map((a) => {
          const uris = (JSON.parse(a.redirect_uris) as string[]).map(escapeHtml).join(", ");
          return `<li>${escapeHtml(a.name)} <span class="hint">(${uris}, created ${escapeHtml(a.created_at)})</span>
            <form method="post" action="/admin/apps/${encodeURIComponent(a.client_id)}/delete" class="inline" onsubmit="return confirm('Remove ${escapeHtml(a.name).replace(/'/g, "\\'")}? Anyone currently signed in through it will be signed out.');">
              <button type="submit" class="danger">Remove</button>
            </form></li>`;
        })
        .join("")}</ul>`
    : `<p class="hint">No apps registered yet.</p>`;
  return `
    <h1>OAuth apps</h1>
    <p class="hint">Third-party applications that let someone sign in with a Guardian ID on this registrar -- ${apps.length} total.</p>
    ${rows}
    <p><a href="/admin/apps/new">Add an app</a></p>
    <p><a href="/admin">Back to admin console</a></p>
  `;
}

export async function handleAdminAppsPage(request: Request, env: Env): Promise<Response> {
  const session = await requireRootSession(request, env);
  if (session instanceof Response) return session;
  const apps = await listOidcClients(env);
  return html(pageShell("OAuth apps", appsListBody(apps)));
}

function newAppFormBody(opts: { nameValue?: string; redirectUrisValue?: string; error?: string } = {}): string {
  return `
    <h1>Add an app</h1>
    <p class="hint">For a third-party product's own "sign in with OIDC" or "custom OIDC" setup. It'll ask you to paste the Client ID and Client Secret shown after you submit this -- check its own setup docs for the exact redirect URI it needs first.</p>
    ${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
    <form method="post" action="/admin/apps/new">
      <label>App name <small>(for your own reference)</small> <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autofocus required placeholder="e.g. Tailscale"></label>
      <label>Redirect URI(s) <small>(one per line, exactly as the app's own docs specify)</small>
        <textarea name="redirect_uris" rows="3" required placeholder="https://example.com/oauth/callback">${escapeHtml(opts.redirectUrisValue ?? "")}</textarea>
      </label>
      <button type="submit">Create app</button>
    </form>
    <p><a href="/admin/apps">Back to OAuth apps</a></p>
  `;
}

export async function handleAdminAppsNewPage(request: Request, env: Env): Promise<Response> {
  const session = await requireRootSession(request, env);
  if (session instanceof Response) return session;
  return html(pageShell("Add an app", newAppFormBody()));
}

export async function handleAdminAppsNewForm(request: Request, env: Env): Promise<Response> {
  const session = await requireRootSession(request, env);
  if (session instanceof Response) return session;

  const form = await request.formData();
  const name = String(form.get("name") ?? "").trim();
  const redirectUrisRaw = String(form.get("redirect_uris") ?? "");
  const redirectUris = redirectUrisRaw
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);

  if (!name) {
    return html(pageShell("Add an app", newAppFormBody({ redirectUrisValue: redirectUrisRaw, error: "App name is required." })), 400);
  }
  if (redirectUris.length === 0) {
    return html(pageShell("Add an app", newAppFormBody({ nameValue: name, error: "At least one redirect URI is required." })), 400);
  }
  for (const uri of redirectUris) {
    try {
      new URL(uri);
    } catch {
      return html(pageShell("Add an app", newAppFormBody({ nameValue: name, redirectUrisValue: redirectUrisRaw, error: `"${uri}" isn't a valid URL.` })), 400);
    }
  }

  const result = await registerOidcClient(env, redirectUris, name, "client_secret_basic");

  const body = `
    <h1>App created</h1>
    <p class="hint">${escapeHtml(name)} can now be used for sign-in by any account on this registrar.</p>
    <p class="hint">Client Secret -- shown once, right now. Paste both of these into ${escapeHtml(name)}'s own OIDC setup now; there's no other way to see the secret again (removing this app and creating a new one is the only way to get a new one).</p>
    <dl>
      <dt>Client ID</dt><dd>${secretBox(result.client_id)}</dd>
      <dt>Client Secret</dt><dd>${secretBox(result.client_secret ?? "")}</dd>
    </dl>
    <p><a href="/admin/apps">Back to OAuth apps</a></p>
  `;
  return html(pageShell("App created", body), 201);
}

export async function handleAdminAppsDelete(request: Request, env: Env, clientId: string): Promise<Response> {
  const session = await requireRootSession(request, env);
  if (session instanceof Response) return session;
  await deleteOidcClient(env, clientId);
  return new Response(null, { status: 302, headers: { location: "/admin/apps" } });
}
