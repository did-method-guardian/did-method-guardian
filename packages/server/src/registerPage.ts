// A real "create an account" page -- the login flow (votingPage.ts's
// /guardian-login, oidc.ts's own /authorize login form) previously had no
// way to get here at all: /register already existed as a JSON API, but
// nothing rendered it as something a person arriving at a login page
// could actually use. Same first-party-HTML-page pattern as every other
// page in this registrar: this wraps the exact same registerWard function
// the JSON API already uses, never a separate code path.

import type { Env } from "./env.js";
import { html, escapeHtml, pageShell } from "./htmlPage.js";
import { isSafeReturnTo } from "./votingPage.js";
import { registerWard, RegistrarError } from "./registrar.js";
import { createLoginSession } from "./login.js";

const SESSION_COOKIE = "gw_session";

function registerFormBody(returnTo: string, opts: { nameValue?: string; error?: string } = {}): string {
  return `
    <h1>Create a Guardian ID</h1>
    <p class="hint">Choose a name -- 3 to 32 lowercase letters, numbers, or hyphens. You'll get a login secret, shown once: write it down, since it's the only way back in.</p>
    ${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
    <form method="post" action="/register">
      <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
      <label>Name <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autofocus required pattern="[a-z0-9][a-z0-9-]{1,30}[a-z0-9]"></label>
      <button type="submit">Create account</button>
    </form>
    <p><a href="/guardian-login?return_to=${encodeURIComponent(returnTo)}">Already have an account? Sign in</a></p>
  `;
}

export async function handleRegisterPage(url: URL): Promise<Response> {
  const returnTo = url.searchParams.get("return_to") ?? "/account";
  const safeReturnTo = isSafeReturnTo(returnTo) ? returnTo : "/account";
  return html(pageShell("Create account", registerFormBody(safeReturnTo)));
}

/** POST /register, form-encoded -- the browser path. The existing JSON path (index.ts, programmatic callers) is untouched. */
export async function handleRegisterForm(request: Request, env: Env): Promise<Response> {
  const form = await request.formData();
  const name = String(form.get("name") ?? "");
  const returnToRaw = String(form.get("return_to") ?? "/account");
  const returnTo = isSafeReturnTo(returnToRaw) ? returnToRaw : "/account";

  let result: { did: string; document: unknown; login_secret: string };
  try {
    result = await registerWard(env, name, null);
  } catch (e) {
    if (e instanceof RegistrarError) {
      return html(pageShell("Create account", registerFormBody(returnTo, { nameValue: name, error: e.message })), e.status);
    }
    throw e;
  }

  const sessionId = await createLoginSession(env, result.did);
  const body = `
    <h1>Account created</h1>
    <p class="hint">${escapeHtml(result.did)}</p>
    <p class="hint">Your login secret -- shown once, right now. Write it down; there's no other way to see it again (though you can always issue a new one later from your account).</p>
    <dl><dt>Login secret</dt><dd><code>${escapeHtml(result.login_secret)}</code></dd></dl>
    <p><a href="${escapeHtml(returnTo)}">Continue</a></p>
  `;
  return html(pageShell("Account created", body), 201, {
    "set-cookie": `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
  });
}
