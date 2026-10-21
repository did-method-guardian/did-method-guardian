import { generateKeypair } from "@did-guardian/lib";
import type { Env } from "./env.js";
import { getOidcClient, getSigningKey, insertSigningKey, insertAuthCode, consumeAuthCode, getWardByDid } from "./db.js";
import { encryptSecret, decryptSecret, randomSecret } from "./secretBox.js";
import { importSigningKeypair, signJwt, verifyJwt, verifyPkce, type SigningKeypair } from "./jwt.js";
import { verifyLogin, createLoginSession, resolveSession, readCookie } from "./login.js";

const SESSION_COOKIE = "gw_session";
const AUTH_CODE_TTL_MS = 1000 * 60 * 5; // 5 minutes
const ID_TOKEN_TTL_S = 60 * 60; // 1 hour

async function getOrCreateSigningKeypair(env: Env): Promise<SigningKeypair> {
  const existing = await getSigningKey(env);
  if (existing) {
    const privateKey = await decryptSecret(existing.private_key_enc, env.KEY_ENCRYPTION_KEY);
    return importSigningKeypair(existing.public_key, privateKey, existing.kid);
  }
  const keypair = await generateKeypair();
  const kid = randomSecret().slice(0, 16);
  const privateKeyEnc = await encryptSecret(keypair.privateKey, env.KEY_ENCRYPTION_KEY);
  await insertSigningKey(env, { kid, public_key: keypair.publicKey, private_key_enc: privateKeyEnc, created_at: new Date().toISOString() });
  return importSigningKeypair(keypair.publicKey, keypair.privateKey, kid);
}

function html(body: string, status = 200): Response {
  return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8" } });
}
function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}
function err(message: string, status: number): Response {
  return json({ error: message }, status);
}

/**
 * This is the one page in the whole registrar a real end user actually
 * looks at directly (every other response here is JSON, consumed by a
 * relying party's own code) -- confirmed live it was previously bare,
 * unstyled HTML with no visual continuity from whatever relying-party
 * page sent someone here, which reads as a broken/wrong page rather
 * than a real step in the same flow. Kept deliberately generic/neutral
 * (not any one relying party's own branding) since this is a self-
 * hostable component -- any operator's users land here.
 */
function pageStyles(): string {
  return `<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; max-width: 360px; margin: 10vh auto 0; padding: 0 1.25rem; line-height: 1.5; }
  h1 { font-size: 1.25rem; margin-bottom: .25rem; }
  p.hint { color: #767676; font-size: .9rem; margin-top: 0; }
  label { display: block; font-size: .85rem; font-weight: 600; margin: 1rem 0 .3rem; }
  label small { font-weight: 400; color: #767676; }
  input { display: block; width: 100%; box-sizing: border-box; padding: .6rem .7rem; font-size: 1rem; border: 1px solid #888; border-radius: 6px; background: Canvas; color: CanvasText; }
  button { display: block; width: 100%; margin-top: 1.25rem; padding: .7rem; font-size: 1rem; border: none; border-radius: 6px; background: #2962ff; color: white; cursor: pointer; }
  button:hover { background: #1e4fd6; }
  p.error { color: #c0392b; font-size: .9rem; }
</style>`;
}

function loginForm(action: string, hidden: Record<string, string>, opts: { nameValue?: string; error?: string } = {}): string {
  const hiddenInputs = Object.entries(hidden)
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v)}">`)
    .join("\n");
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${pageStyles()}</head><body>
<h1>Sign in with your Guardian ID</h1>
<p class="hint">Enter just the name part of your id (not the domain), and the login secret you were shown once when it was created.</p>
${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
<form method="post" action="${action}">
  ${hiddenInputs}
  <label>Name <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autofocus required></label>
  <label>Login secret <small>(shown once, at creation)</small><input name="login_secret" type="password" required></label>
  <button type="submit">Sign in</button>
</form>
</body></html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export async function handleOidcRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/.well-known/openid-configuration" && request.method === "GET") {
    const base = `https://${env.REGISTRAR_DOMAIN}`;
    return json({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      userinfo_endpoint: `${base}/userinfo`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid"],
    });
  }

  if (url.pathname === "/.well-known/jwks.json" && request.method === "GET") {
    const keypair = await getOrCreateSigningKeypair(env);
    return json({ keys: [{ ...keypair.publicKeyJwk, use: "sig", alg: "ES256", kid: keypair.kid }] });
  }

  if (url.pathname === "/authorize") {
    return handleAuthorize(request, env, url);
  }

  if (url.pathname === "/token" && request.method === "POST") {
    return handleToken(request, env);
  }

  if (url.pathname === "/userinfo" && request.method === "GET") {
    return handleUserinfo(request, env);
  }

  return err("not found", 404);
}

async function handleAuthorize(request: Request, env: Env, url: URL): Promise<Response> {
  const params = url.searchParams;
  const clientId = params.get("client_id") ?? "";
  const redirectUri = params.get("redirect_uri") ?? "";
  const client = await getOidcClient(env, clientId);
  if (!client) return err("unknown client_id", 400);
  const allowedRedirects: string[] = JSON.parse(client.redirect_uris);
  if (!allowedRedirects.includes(redirectUri)) return err("redirect_uri not registered for this client", 400);
  if (params.get("response_type") !== "code") return err("only response_type=code is supported", 400);

  const codeChallenge = params.get("code_challenge");
  const codeChallengeMethod = params.get("code_challenge_method");
  const state = params.get("state") ?? "";
  const scope = params.get("scope") ?? "openid";
  const nonce = params.get("nonce");

  let wardDid: string | null = null;

  if (request.method === "POST") {
    const form = await request.formData();
    const submittedName = String(form.get("name") ?? "");
    wardDid = await verifyLogin(env, submittedName, String(form.get("login_secret") ?? ""));
    if (!wardDid) {
      return html(loginForm(url.pathname + url.search, {}, { nameValue: submittedName, error: "Invalid name or login secret." }), 401);
    }
  } else {
    const sessionId = readCookie(request, SESSION_COOKIE);
    if (sessionId) wardDid = await resolveSession(env, sessionId);
    if (!wardDid) {
      // login_hint (standard OIDC authentication request parameter) --
      // a relying party that already parsed "name@domain" on its own
      // login page can pass just the name along, so this form's own
      // name field starts pre-filled instead of asking the person to
      // type the same thing again in a different shape (confirmed live
      // this was a real point of confusion: this registrar's own name
      // field never wants the domain part, but a relying party's own
      // login page usually does).
      return html(loginForm(`${url.pathname}${url.search}`, {}, { nameValue: params.get("login_hint") ?? "" }));
    }
  }

  const code = randomSecret();
  const expiresAt = new Date(Date.now() + AUTH_CODE_TTL_MS).toISOString();
  await insertAuthCode(env, {
    code,
    client_id: clientId,
    ward_did: wardDid,
    redirect_uri: redirectUri,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    scope,
    nonce,
    expires_at: expiresAt,
    used: 0,
  });

  const sessionId = await createLoginSession(env, wardDid);
  const redirect = new URL(redirectUri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);

  return new Response(null, {
    status: 302,
    headers: {
      location: redirect.toString(),
      "set-cookie": `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
    },
  });
}

async function handleToken(request: Request, env: Env): Promise<Response> {
  const contentType = request.headers.get("content-type") ?? "";
  const body = contentType.includes("application/json") ? await request.json() : Object.fromEntries((await request.formData()).entries());
  const b = body as Record<string, string>;

  if (b.grant_type !== "authorization_code") return err("only grant_type=authorization_code is supported", 400);
  const authCode = await consumeAuthCode(env, b.code ?? "");
  if (!authCode) return err("invalid or expired code", 400);
  if (authCode.redirect_uri !== b.redirect_uri) return err("redirect_uri mismatch", 400);

  const client = await getOidcClient(env, authCode.client_id);
  if (!client) return err("unknown client", 400);
  if (b.client_secret) {
    const { hashSecret } = await import("./secretBox.js");
    if ((await hashSecret(b.client_secret)) !== client.client_secret_hash) return err("invalid client credentials", 401);
  }

  if (authCode.code_challenge) {
    if (!b.code_verifier || !(await verifyPkce(b.code_verifier, authCode.code_challenge))) {
      return err("PKCE verification failed", 400);
    }
  }

  const keypair = await getOrCreateSigningKeypair(env);
  const now = Math.floor(Date.now() / 1000);
  const idToken = await signJwt(
    {
      iss: `https://${env.REGISTRAR_DOMAIN}`,
      sub: authCode.ward_did,
      aud: authCode.client_id,
      iat: now,
      exp: now + ID_TOKEN_TTL_S,
      nonce: authCode.nonce ?? undefined,
    },
    keypair,
  );
  const accessToken = await signJwt(
    { iss: `https://${env.REGISTRAR_DOMAIN}`, sub: authCode.ward_did, aud: authCode.client_id, iat: now, exp: now + ID_TOKEN_TTL_S, typ: "access" },
    keypair,
  );

  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ID_TOKEN_TTL_S,
    id_token: idToken,
    scope: authCode.scope,
  });
}

async function handleUserinfo(request: Request, env: Env): Promise<Response> {
  const auth = request.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return err("missing bearer token", 401);

  const keypair = await getOrCreateSigningKeypair(env);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    keypair.publicKeyJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  const payload = await verifyJwt(token, publicKey);
  if (!payload || typeof payload.sub !== "string") return err("invalid or expired token", 401);

  const ward = await getWardByDid(env, payload.sub);
  return json({ sub: payload.sub, name: ward?.name });
}
