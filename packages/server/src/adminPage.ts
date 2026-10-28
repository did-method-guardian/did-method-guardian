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
import { getWardByDid, listWards, type WardRow } from "./db.js";

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
      <label>Name <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autofocus required pattern="[a-z0-9][a-z0-9-]{1,30}[a-z0-9]"></label>
      <label>Guardian DID <small>(optional -- e.g. your own, to oversee this account)</small> <input name="guardian_did" placeholder="did:guardian:..."></label>
      <fieldset style="border:0; padding:0; margin:1rem 0 0;">
        <label style="display:flex; align-items:center; gap:.4rem; font-weight:400;"><input type="radio" name="credential_mode" value="generate" ${mode === "generate" ? "checked" : ""} style="display:inline; width:auto; min-height:0;"> Generate a secure login secret</label>
        <label style="display:flex; align-items:center; gap:.4rem; font-weight:400; margin-top:.4rem;"><input type="radio" name="credential_mode" value="password" ${mode === "password" ? "checked" : ""} style="display:inline; width:auto; min-height:0;"> Set an initial password myself</label>
      </fieldset>
      <div id="password-fields" ${mode === "password" ? "" : "hidden"}>
        <label>Password <small>(at least ${MIN_PASSWORD_LENGTH} characters)</small> <input id="password-field" type="password" name="password" minlength="${MIN_PASSWORD_LENGTH}" ${mode === "password" ? "required" : ""}></label>
        <label>Confirm password <input id="password-confirm-field" type="password" name="password_confirm" minlength="${MIN_PASSWORD_LENGTH}" ${mode === "password" ? "required" : ""}></label>
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
