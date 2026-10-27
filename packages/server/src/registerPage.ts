// A real "create an account" page -- the login flow (votingPage.ts's
// /guardian-login, oidc.ts's own /authorize login form) previously had no
// way to get here at all: /register already existed as a JSON API, but
// nothing rendered it as something a person arriving at a login page
// could actually use. Same first-party-HTML-page pattern as every other
// page in this registrar: this wraps the exact same registerWard function
// the JSON API already uses, never a separate code path.

import type { Env } from "./env.js";
import { html, escapeHtml, pageShell, authPageShell, secretBox } from "./htmlPage.js";
import { isSafeReturnTo } from "./votingPage.js";
import { registerWard, RegistrarError } from "./registrar.js";
import { createLoginSession } from "./login.js";

const SESSION_COOKIE = "gw_session";

const MIN_PASSWORD_LENGTH = 12;

function registerFormBody(returnTo: string, opts: { nameValue?: string; error?: string; credentialMode?: "generate" | "password" } = {}): string {
  const mode = opts.credentialMode ?? "generate";
  return `
    <section class="signin-hero">
      <div class="signin-grid">
        <div class="signin-copy">
          <h1>Create a <span class="hl">Guardian ID</span></h1>
          <p>Choose a name -- 3 to 32 lowercase letters, numbers, or hyphens. Then either let this registrar generate a secure login secret for you, or set your own password.</p>
        </div>
        <div class="signin-card">
          ${opts.error ? `<p class="error"><i class="ph ph-warning-circle"></i> ${escapeHtml(opts.error)}</p>` : ""}
          <form method="post" action="/register" id="register-form">
            <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
            <label>Name <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autofocus required pattern="[a-z0-9][a-z0-9-]{1,30}[a-z0-9]"></label>
            <fieldset style="border:0; padding:0; margin:1rem 0 0;">
              <label style="display:flex; align-items:center; gap:.4rem; font-weight:400;"><input type="radio" name="credential_mode" value="generate" ${mode === "generate" ? "checked" : ""} style="display:inline; width:auto; min-height:0;"> Generate a secure login secret for me (recommended)</label>
              <label style="display:flex; align-items:center; gap:.4rem; font-weight:400; margin-top:.4rem;"><input type="radio" name="credential_mode" value="password" ${mode === "password" ? "checked" : ""} style="display:inline; width:auto; min-height:0;"> Set my own password</label>
            </fieldset>
            <div id="password-fields" ${mode === "password" ? "" : "hidden"}>
              <label>Password <small>(at least ${MIN_PASSWORD_LENGTH} characters)</small> <input id="password-field" type="password" name="password" minlength="${MIN_PASSWORD_LENGTH}" ${mode === "password" ? "required" : ""}></label>
              <label>Confirm password <input id="password-confirm-field" type="password" name="password_confirm" minlength="${MIN_PASSWORD_LENGTH}" ${mode === "password" ? "required" : ""}></label>
            </div>
            <button type="submit">Create account</button>
          </form>
          <p style="text-align:center; margin-top: 1rem;"><a href="/guardian-login?return_to=${encodeURIComponent(returnTo)}">Already have an account? Sign in</a></p>
        </div>
      </div>
    </section>
    <script>
      (function () {
        var form = document.getElementById('register-form');
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

export async function handleRegisterPage(url: URL): Promise<Response> {
  const returnTo = url.searchParams.get("return_to") ?? "/account";
  const safeReturnTo = isSafeReturnTo(returnTo) ? returnTo : "/account";
  return html(authPageShell("Create account", registerFormBody(safeReturnTo)));
}

/** POST /register, form-encoded -- the browser path. The existing JSON path (index.ts, programmatic callers) is untouched. */
export async function handleRegisterForm(request: Request, env: Env): Promise<Response> {
  const form = await request.formData();
  const name = String(form.get("name") ?? "");
  const returnToRaw = String(form.get("return_to") ?? "/account");
  const returnTo = isSafeReturnTo(returnToRaw) ? returnToRaw : "/account";
  const credentialMode = form.get("credential_mode") === "password" ? "password" : "generate";

  let password: string | undefined;
  if (credentialMode === "password") {
    const pw = String(form.get("password") ?? "");
    const confirm = String(form.get("password_confirm") ?? "");
    if (pw.length < MIN_PASSWORD_LENGTH) {
      return html(
        authPageShell("Create account", registerFormBody(returnTo, { nameValue: name, credentialMode, error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` })),
        400,
      );
    }
    if (pw !== confirm) {
      return html(authPageShell("Create account", registerFormBody(returnTo, { nameValue: name, credentialMode, error: "Passwords don't match." })), 400);
    }
    password = pw;
  }

  let result: { did: string; document: unknown; login_secret?: string };
  try {
    result = await registerWard(env, name, null, password);
  } catch (e) {
    if (e instanceof RegistrarError) {
      return html(authPageShell("Create account", registerFormBody(returnTo, { nameValue: name, credentialMode, error: e.message })), e.status);
    }
    throw e;
  }

  const sessionId = await createLoginSession(env, result.did);
  const body = `
    <h1>Account created</h1>
    <p class="hint">${escapeHtml(result.did)}</p>
    ${
      result.login_secret
        ? `<p class="hint">Your login secret -- shown once, right now. Write it down; there's no other way to see it again (though you can always issue a new one later from your account).</p>
           <dl><dt>Login secret</dt><dd>${secretBox(result.login_secret)}</dd></dl>`
        : `<p class="hint">Your account is ready -- sign in any time with the name above and the password you set.</p>`
    }
    <p><a href="${escapeHtml(returnTo)}">Continue</a></p>
  `;
  return html(pageShell("Account created", body), 201, {
    "set-cookie": `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
  });
}
