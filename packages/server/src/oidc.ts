import { generateKeypair, liveGuardians } from "@did-guardian/lib";
import type { Env } from "./env.js";
import { resolveState, makeGuardianLivenessResolver } from "./registrar.js";
import {
  getOidcClient,
  getSigningKey,
  insertSigningKey,
  insertAuthCode,
  consumeAuthCode,
  getWardByDid,
  insertOidcClient,
  getOidcConsent,
  upsertOidcConsent,
  insertRefreshToken,
  getRefreshToken,
  revokeRefreshToken,
  revokeRefreshTokenFamily,
  insertRevokedJti,
  isJtiRevoked,
  getVerifiedForwardingByDid,
} from "./db.js";
import { encryptSecret, decryptSecret, randomSecret, hashSecret } from "./secretBox.js";
import { importSigningKeypair, signJwt, verifyJwt, verifyPkce, decodeJwtUnsafe, type SigningKeypair } from "./jwt.js";
import { verifyLogin, createLoginSession, resolveSession, readCookie } from "./login.js";
import { html, escapeHtml, pageStyles } from "./htmlPage.js";

const SESSION_COOKIE = "gw_session";
const AUTH_CODE_TTL_MS = 1000 * 60 * 5; // 5 minutes
const ID_TOKEN_TTL_S = 60 * 60; // 1 hour
const REFRESH_TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * 30; // 30 days

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

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}
function err(message: string, status: number): Response {
  return json({ error: message }, status);
}

/**
 * This is one of the few pages in the whole registrar a real end user
 * actually looks at directly (everything else here is JSON, consumed by a
 * relying party's own code, or the voting UI in votingPage.ts) --
 * confirmed live it was previously bare, unstyled HTML with no visual
 * continuity from whatever relying-party page sent someone here, which
 * reads as a broken/wrong page rather than a real step in the same flow.
 * pageStyles/html/escapeHtml now live in htmlPage.ts, shared with
 * votingPage.ts's own login form -- same look, one definition.
 */
function loginForm(action: string, hidden: Record<string, string>, opts: { nameValue?: string; error?: string } = {}): string {
  const hiddenInputs = Object.entries(hidden)
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${escapeHtml(v)}">`)
    .join("\n");
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${pageStyles()}</head><body>
<h1>Sign in with your Guardian ID</h1>
<p class="hint">Your name alone (e.g. "alice") or your full id (e.g. "alice@acme.com") both work -- the domain part is ignored here if you include it. Plus the login secret you were shown once when it was created.</p>
${opts.error ? `<p class="error">${escapeHtml(opts.error)}</p>` : ""}
<form method="post" action="${action}">
  ${hiddenInputs}
  <label>Name <input name="name" value="${escapeHtml(opts.nameValue ?? "")}" autofocus required></label>
  <label>Login secret <small>(shown once, at creation)</small><input name="login_secret" type="password" required></label>
  <button type="submit">Sign in</button>
</form>
<p><a href="/register?return_to=${encodeURIComponent(action)}">Don't have an account? Create one</a></p>
</body></html>`;
}

/** Previously-granted scope already covers a newly requested one iff every requested token is already present -- a returning user is only re-asked when the requested scope actually grows, the same posture every major OAuth provider already takes. */
function scopeSatisfied(granted: string, requested: string): boolean {
  const grantedSet = new Set(granted.split(/\s+/).filter(Boolean));
  return requested.split(/\s+/).filter(Boolean).every((s) => grantedSet.has(s));
}

/** The "App X wants access -- Allow/Deny" step handleAuthorize previously skipped entirely. POSTs back to the same /authorize URL (same query string) with just a consent decision -- the session cookie set when this page was rendered is what lets that follow-up POST resolve the ward without asking for credentials again. */
function consentPage(action: string, clientName: string, scope: string): string {
  const scopeLabels: Record<string, string> = {
    openid: "Your Guardian identity",
    email: "Your verified email address",
    "create:managed-identity": "Create new identities with you as their real, signed guardian",
  };
  const items = scope
    .split(/\s+/)
    .filter(Boolean)
    .map((s) => `<li>${escapeHtml(scopeLabels[s] ?? s)}</li>`)
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">${pageStyles()}</head><body>
<h1>${escapeHtml(clientName)} wants access to:</h1>
<ul>${items}</ul>
<form method="post" action="${escapeHtml(action)}">
  <input type="hidden" name="consent" value="allow">
  <button type="submit">Allow</button>
</form>
<form method="post" action="${escapeHtml(action)}">
  <input type="hidden" name="consent" value="deny">
  <button type="submit" class="neutral">Deny</button>
</form>
</body></html>`;
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
      revocation_endpoint: `${base}/revoke`,
      registration_endpoint: `${base}/oauth/register-client`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["ES256"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid", "email", "create:managed-identity"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    });
  }

  // RFC 9728 Protected Resource Metadata (registrar API spec §12): this
  // registrar is both its own authorization server and, for endpoints like
  // /userinfo, a protected resource in its own right -- the shape an
  // MCP-style client expects when it discovers this domain as a resource
  // and needs to find out who issues tokens for it.
  if (url.pathname === "/.well-known/oauth-protected-resource" && request.method === "GET") {
    const base = `https://${env.REGISTRAR_DOMAIN}`;
    return json({
      resource: base,
      authorization_servers: [base],
      bearer_methods_supported: ["header"],
      scopes_supported: ["openid", "email", "create:managed-identity"],
    });
  }

  if (url.pathname === "/.well-known/jwks.json" && request.method === "GET") {
    const keypair = await getOrCreateSigningKeypair(env);
    return json({ keys: [{ ...keypair.publicKeyJwk, use: "sig", alg: "ES256", kid: keypair.kid }] });
  }

  if (url.pathname === "/oauth/register-client" && request.method === "POST") {
    return handleRegisterClient(request, env);
  }

  if (url.pathname.startsWith("/oauth/register-client/") && request.method === "GET") {
    return handleReadClientRegistration(request, env, url.pathname.slice("/oauth/register-client/".length));
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

  if (url.pathname === "/revoke" && request.method === "POST") {
    return handleRevoke(request, env);
  }

  return err("not found", 404);
}

/**
 * POST /oauth/register-client -- RFC 7591 Dynamic Client Registration.
 * Open, unauthenticated self-service, the same posture every other
 * registration endpoint this registrar exposes already has (/register,
 * .../propose, etc.) -- no new gate invented for OAuth clients specifically.
 * A public client (token_endpoint_auth_method: "none") still gets a
 * client_secret_hash row (a random value it's never given, since the
 * column predates dynamic registration and stays NOT NULL) -- handleToken's
 * own client_secret check is already conditional on the client actually
 * supplying one, so a public client simply never triggers it.
 */
async function handleRegisterClient(request: Request, env: Env): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return err("request body must be JSON", 400);
  }
  const b = body as { redirect_uris?: unknown; client_name?: unknown; token_endpoint_auth_method?: unknown };
  if (!Array.isArray(b.redirect_uris) || b.redirect_uris.length === 0 || !b.redirect_uris.every((u) => typeof u === "string")) {
    return err("redirect_uris must be a non-empty array of strings", 400);
  }
  const authMethod = b.token_endpoint_auth_method === "none" ? "none" : "client_secret_basic";
  const clientName = typeof b.client_name === "string" ? b.client_name : "unnamed client";

  const clientId = randomSecret();
  const clientSecret = authMethod === "none" ? randomSecret() : randomSecret(); // public clients still get a never-issued placeholder, see header comment
  const registrationAccessToken = randomSecret();
  const now = new Date().toISOString();

  await insertOidcClient(env, {
    client_id: clientId,
    client_secret_hash: await hashSecret(clientSecret),
    redirect_uris: JSON.stringify(b.redirect_uris),
    name: clientName,
    token_endpoint_auth_method: authMethod,
    registration_access_token_hash: await hashSecret(registrationAccessToken),
    created_at: now,
  });

  const response: Record<string, unknown> = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.parse(now) / 1000),
    redirect_uris: b.redirect_uris,
    client_name: clientName,
    token_endpoint_auth_method: authMethod,
    registration_access_token: registrationAccessToken,
    registration_client_uri: `https://${env.REGISTRAR_DOMAIN}/oauth/register-client/${clientId}`,
  };
  if (authMethod !== "none") response.client_secret = clientSecret;
  return json(response, 201);
}

/**
 * GET /oauth/register-client/<client_id> -- RFC 7592's read operation only
 * (v1 scope; update/delete deferred). Authenticated by the
 * registration_access_token issued at registration time, exactly the same
 * trust model this registrar's other one-time-shown secrets already use
 * (a ward's own login_secret, a pending-op signer's own email token).
 */
async function handleReadClientRegistration(request: Request, env: Env, clientId: string): Promise<Response> {
  const auth = request.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return err("missing registration access token", 401);

  const client = await getOidcClient(env, clientId);
  if (!client || client.registration_access_token_hash !== (await hashSecret(token))) {
    return err("invalid client_id or registration access token", 401);
  }

  return json({
    client_id: client.client_id,
    client_id_issued_at: Math.floor(Date.parse(client.created_at) / 1000),
    redirect_uris: JSON.parse(client.redirect_uris),
    client_name: client.name,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    registration_client_uri: `https://${env.REGISTRAR_DOMAIN}/oauth/register-client/${client.client_id}`,
  });
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
  // PKCE mandatory for every client, confidential or public -- the OAuth
  // 2.1 baseline, tightened from v1's own "PKCE only if the client happened
  // to send one" (meaning a client that omitted it skipped PKCE entirely).
  if (!codeChallenge) return err("code_challenge is required (PKCE is mandatory)", 400);
  if (codeChallengeMethod !== "S256") return err("code_challenge_method must be S256", 400);
  const state = params.get("state") ?? "";
  const scope = params.get("scope") ?? "openid";
  const nonce = params.get("nonce");
  const resourceParam = params.get("resource");
  if (resourceParam && !isValidResourceIndicator(resourceParam)) {
    return err("resource must be an absolute URI with no fragment (RFC 8707)", 400);
  }

  let wardDid: string | null = null;
  let consentDecision: "allow" | "deny" | null = null;

  if (request.method === "POST") {
    const form = await request.formData();
    if (form.has("consent")) {
      // This POST is a consent decision, not a login attempt -- the ward
      // was already established by the login (or existing session) that
      // rendered the consent page in the first place, and its session
      // cookie is what resolves them here with no credentials re-asked.
      const sessionId = readCookie(request, SESSION_COOKIE);
      wardDid = sessionId ? await resolveSession(env, sessionId) : null;
      if (!wardDid) return err("session expired -- please start over", 400);
      consentDecision = form.get("consent") === "allow" ? "allow" : "deny";
    } else {
      const submittedName = String(form.get("name") ?? "");
      wardDid = await verifyLogin(env, submittedName, String(form.get("login_secret") ?? ""));
      if (!wardDid) {
        return html(loginForm(url.pathname + url.search, {}, { nameValue: submittedName, error: "Invalid name or login secret." }), 401);
      }
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

  if (consentDecision === "deny") {
    const redirect = new URL(redirectUri);
    redirect.searchParams.set("error", "access_denied");
    if (state) redirect.searchParams.set("state", state);
    return new Response(null, { status: 302, headers: { location: redirect.toString() } });
  }

  if (consentDecision === "allow") {
    await upsertOidcConsent(env, { ward_did: wardDid, client_id: clientId, scope, granted_at: new Date().toISOString() });
  } else {
    // No explicit decision yet this request -- check whether a prior visit
    // already granted (at least) this scope before asking again.
    const existing = await getOidcConsent(env, wardDid, clientId);
    if (!existing || !scopeSatisfied(existing.scope, scope)) {
      // Ensure the session is set even on a fresh login, so the consent
      // page's own follow-up POST (just `consent=allow|deny`, no
      // credentials) can resolve the ward via cookie alone.
      const sessionId = await createLoginSession(env, wardDid);
      return html(consentPage(url.pathname + url.search, client.name, scope), 200, {
        "set-cookie": `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`,
      });
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
    resource: resourceParam,
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

/**
 * RFC 8707 Resource Indicators: an absolute URI, no fragment component
 * (RFC 8707 §2's own requirement -- a resource identifies a server, not a
 * location within one). Deliberately not also requiring https: a resource
 * server on a private network during development is still a valid target.
 */
function isValidResourceIndicator(value: string): boolean {
  try {
    const u = new URL(value);
    return u.hash === "";
  } catch {
    return false;
  }
}

/**
 * Every access/id token gets its own jti -- the only way to revoke an
 * otherwise-stateless JWT before its own natural expiry (RFC 7009, via
 * POST /revoke -> oidc_revoked_jti, checked in handleUserinfo). `resource`
 * (RFC 8707), when the client named one at /authorize or refresh time,
 * replaces the OAuth client's own id as `aud` -- an MCP-style resource
 * server expects its own URI there, not the identity of whatever app
 * mediated the login.
 */
async function issueTokenPair(
  env: Env,
  wardDid: string,
  clientId: string,
  nonce: string | null | undefined,
  scope: string,
  resource?: string | null,
): Promise<{ idToken: string; accessToken: string }> {
  const keypair = await getOrCreateSigningKeypair(env);
  const now = Math.floor(Date.now() / 1000);
  const aud = resource ?? clientId;
  const idToken = await signJwt(
    { iss: `https://${env.REGISTRAR_DOMAIN}`, sub: wardDid, aud, iat: now, exp: now + ID_TOKEN_TTL_S, nonce: nonce ?? undefined, jti: randomSecret() },
    keypair,
  );
  // scope travels with the access token itself (not just the one-time auth
  // code/refresh-token row) so handleUserinfo can gate which claims it
  // returns without a second DB lookup.
  const accessToken = await signJwt(
    { iss: `https://${env.REGISTRAR_DOMAIN}`, sub: wardDid, aud, iat: now, exp: now + ID_TOKEN_TTL_S, typ: "access", scope, jti: randomSecret() },
    keypair,
  );
  return { idToken, accessToken };
}

/**
 * Delegation-chain token (RFC 8693 token exchange, registrar API spec's
 * own §10) -- `sub` is the identity being acted *as* (the target), `act`
 * names who's *actually* doing the acting (the caller, already proven by
 * their own subject_token) -- the emerging OpenID on-behalf-of shape, not
 * a one-off: anything already building against RFC 8693's own `act` claim
 * recognizes this unmodified. No id_token -- this isn't a fresh
 * authentication event, just a scoped delegation of an already-
 * authenticated caller's own, separately-proven authority.
 */
async function issueDelegatedAccessToken(env: Env, targetDid: string, actorDid: string, clientId: string, scope: string): Promise<string> {
  const keypair = await getOrCreateSigningKeypair(env);
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    {
      iss: `https://${env.REGISTRAR_DOMAIN}`,
      sub: targetDid,
      aud: clientId,
      iat: now,
      exp: now + ID_TOKEN_TTL_S,
      typ: "access",
      scope,
      act: { sub: actorDid },
      jti: randomSecret(),
    },
    keypair,
  );
}

/** Issues a fresh refresh token, same family as `familyId` if given (rotation) or a new family (first issuance) -- stored hashed, same pattern login_secret_hash already uses. `resource` (RFC 8707) is carried forward so a later refresh keeps scoping new tokens to the same resource server unless the client explicitly asks to narrow it. */
async function issueRefreshToken(
  env: Env,
  clientId: string,
  wardDid: string,
  scope: string,
  resource: string | null,
  familyId?: string,
): Promise<string> {
  const token = randomSecret();
  const now = new Date();
  await insertRefreshToken(env, {
    token_hash: await hashSecret(token),
    client_id: clientId,
    ward_did: wardDid,
    scope,
    family_id: familyId ?? randomSecret(),
    created_at: now.toISOString(),
    expires_at: new Date(now.getTime() + REFRESH_TOKEN_TTL_MS).toISOString(),
    revoked: 0,
    resource,
  });
  return token;
}

/** client_secret_basic (RFC 6749 §2.3.1, the Authorization header) or client_secret_post (the same value as a body param) -- either is accepted, matching discovery's own token_endpoint_auth_methods_supported claim. */
function extractClientSecret(request: Request, b: Record<string, string>): string | undefined {
  const auth = request.headers.get("authorization") ?? "";
  if (auth.startsWith("Basic ")) {
    try {
      const [, secret] = atob(auth.slice(6)).split(":");
      if (secret) return secret;
    } catch {
      // malformed Basic header -- fall through to the body param, if any
    }
  }
  return b.client_secret;
}

async function handleToken(request: Request, env: Env): Promise<Response> {
  const contentType = request.headers.get("content-type") ?? "";
  const body = contentType.includes("application/json") ? await request.json() : Object.fromEntries((await request.formData()).entries());
  const b = body as Record<string, string>;
  const clientSecret = extractClientSecret(request, b);

  if (b.grant_type === "refresh_token") return handleRefreshGrant(b, clientSecret, env);
  if (b.grant_type === "urn:ietf:params:oauth:grant-type:token-exchange") return handleTokenExchangeGrant(b, clientSecret, env);
  if (b.grant_type !== "authorization_code") {
    return err("only grant_type=authorization_code, grant_type=refresh_token, and grant_type=urn:ietf:params:oauth:grant-type:token-exchange are supported", 400);
  }

  const authCode = await consumeAuthCode(env, b.code ?? "");
  if (!authCode) return err("invalid or expired code", 400);
  if (authCode.redirect_uri !== b.redirect_uri) return err("redirect_uri mismatch", 400);

  const client = await getOidcClient(env, authCode.client_id);
  if (!client) return err("unknown client", 400);
  if (clientSecret) {
    if ((await hashSecret(clientSecret)) !== client.client_secret_hash) return err("invalid client credentials", 401);
  }

  // PKCE is mandatory (handleAuthorize refuses to issue a code without a
  // code_challenge), so a stored auth code missing one is an invariant
  // violation, not a legitimate "this client skipped it" case -- fail
  // closed rather than silently accept.
  if (!authCode.code_challenge || !b.code_verifier || !(await verifyPkce(b.code_verifier, authCode.code_challenge))) {
    return err("PKCE verification failed", 400);
  }

  const { idToken, accessToken } = await issueTokenPair(env, authCode.ward_did, authCode.client_id, authCode.nonce, authCode.scope, authCode.resource);
  const refreshToken = await issueRefreshToken(env, authCode.client_id, authCode.ward_did, authCode.scope, authCode.resource);

  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ID_TOKEN_TTL_S,
    id_token: idToken,
    refresh_token: refreshToken,
    scope: authCode.scope,
  });
}

/**
 * grant_type=refresh_token -- rotates on every use (old token marked
 * revoked, new one issued in the same family). Presenting an
 * already-revoked token is the standard signal that one has been stolen
 * (a legitimate client never reuses a rotated-away token), so the
 * response is to revoke the WHOLE family, not just deny this one request.
 */
async function handleRefreshGrant(b: Record<string, string>, clientSecret: string | undefined, env: Env): Promise<Response> {
  if (!b.refresh_token) return err("refresh_token is required", 400);
  const tokenHash = await hashSecret(b.refresh_token);
  const stored = await getRefreshToken(env, tokenHash);
  if (!stored) return err("invalid refresh token", 400);

  if (stored.revoked) {
    await revokeRefreshTokenFamily(env, stored.family_id);
    return err("refresh token reuse detected -- this token and every other one issued from the same login have been revoked", 400);
  }
  if (new Date(stored.expires_at).getTime() < Date.now()) return err("refresh token expired", 400);

  const client = await getOidcClient(env, stored.client_id);
  if (!client) return err("unknown client", 400);
  if (clientSecret && (await hashSecret(clientSecret)) !== client.client_secret_hash) return err("invalid client credentials", 401);

  // RFC 8707 §2: a refresh request may narrow (never widen) the resource a
  // new token is scoped to. Only accepted when one was already established
  // at the original /authorize -- a client that never asked for resource
  // scoping can't introduce it later via refresh.
  let resource = stored.resource;
  if (b.resource) {
    if (!isValidResourceIndicator(b.resource)) return err("resource must be an absolute URI with no fragment (RFC 8707)", 400);
    if (!stored.resource) return err("this refresh token was not scoped to a resource at /authorize -- resource cannot be introduced at refresh time", 400);
    resource = b.resource;
  }

  await revokeRefreshToken(env, tokenHash);
  const { idToken, accessToken } = await issueTokenPair(env, stored.ward_did, stored.client_id, null, stored.scope, resource);
  const newRefreshToken = await issueRefreshToken(env, stored.client_id, stored.ward_did, stored.scope, resource, stored.family_id);

  return json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ID_TOKEN_TTL_S,
    id_token: idToken,
    refresh_token: newRefreshToken,
    scope: stored.scope,
  });
}

/**
 * grant_type=urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693,
 * registrar API spec §10) -- mints a token to act *as* `resource` (the
 * target DID), on behalf of whoever `subject_token` proves is actually
 * calling. Authorization is the same live-guardian check this registrar
 * already uses everywhere else a guardian's own standing matters
 * (rules.ts's liveGuardians, via @did-guardian/lib -- never a
 * reimplementation): the caller must be the target itself, or a current,
 * live guardian of it, checked fresh against the target's own operation
 * log every time, never cached. `resource` must be a ward this registrar
 * itself custodies -- there's no key material to produce a token for an
 * identity it doesn't hold.
 */
async function handleTokenExchangeGrant(b: Record<string, string>, clientSecret: string | undefined, env: Env): Promise<Response> {
  if (!b.subject_token) return err("subject_token is required", 400);
  if (!b.resource) return err("resource (the target DID to act as) is required", 400);
  if (!b.client_id) return err("client_id is required", 400);

  const client = await getOidcClient(env, b.client_id);
  if (!client) return err("unknown client", 400);
  if (clientSecret && (await hashSecret(clientSecret)) !== client.client_secret_hash) return err("invalid client credentials", 401);

  const verified = await verifyAccessToken(env, b.subject_token);
  if (!verified) return err("subject_token is invalid, expired, or revoked", 400);
  const actorDid = verified.sub;
  const targetDid = b.resource;

  const targetWard = await getWardByDid(env, targetDid);
  if (!targetWard) return err(`"${targetDid}" is not an identity this registrar custodies -- it has no key material to issue a token for`, 400);

  if (actorDid !== targetDid) {
    const resolved = await resolveState(env, targetWard.name === "" ? null : targetWard.name);
    const live = resolved ? await liveGuardians(resolved.state, makeGuardianLivenessResolver(env)) : [];
    if (!live.includes(actorDid)) {
      return err(`"${actorDid}" is neither "${targetDid}" itself, nor a current guardian of it`, 403);
    }
  }

  const scope = typeof b.scope === "string" && b.scope ? b.scope : "openid";
  const accessToken = await issueDelegatedAccessToken(env, targetDid, actorDid, b.client_id, scope);
  return json({
    access_token: accessToken,
    issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
    token_type: "Bearer",
    expires_in: ID_TOKEN_TTL_S,
    scope,
  });
}

/** POST /revoke (RFC 7009). A refresh token is looked up and marked revoked directly; an access/id token (a stateless JWT) is decoded (not re-verified -- RFC 7009 doesn't require the token still be valid to revoke it) just far enough to read its own jti, added to the revocation blocklist handleUserinfo already checks. Per RFC 7009 §2.2, an unrecognized or already-invalid token still returns 200 -- revocation is idempotent, never a way to probe which tokens exist. */
async function handleRevoke(request: Request, env: Env): Promise<Response> {
  const contentType = request.headers.get("content-type") ?? "";
  const body = contentType.includes("application/json") ? await request.json() : Object.fromEntries((await request.formData()).entries());
  const b = body as Record<string, string>;
  if (!b.token) return err("token is required", 400);

  if (b.token_type_hint !== "access_token") {
    const stored = await getRefreshToken(env, await hashSecret(b.token));
    if (stored) {
      await revokeRefreshToken(env, stored.token_hash);
      return new Response(null, { status: 200 });
    }
  }
  const parts = b.token.split(".");
  if (parts.length === 3) {
    try {
      const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
      if (typeof payload.jti === "string") await insertRevokedJti(env, payload.jti, new Date().toISOString());
    } catch {
      // not a well-formed JWT -- nothing to revoke, still 200 per RFC 7009
    }
  }
  return new Response(null, { status: 200 });
}

export interface VerifiedAccessToken {
  sub: string;
  scope: string[];
}

/** Fetches and caches-for-this-request a foreign registrar's own JWKS, importing the key matching `kid`. No local caching across requests yet -- correctness first; a real cache is a reasonable follow-up once this sees enough traffic to matter. */
async function fetchForeignPublicKey(issuer: string, kid: string): Promise<CryptoKey | null> {
  try {
    const resp = await fetch(`${issuer}/.well-known/jwks.json`);
    if (!resp.ok) return null;
    const jwks = (await resp.json()) as { keys?: Array<JsonWebKey & { kid?: string }> };
    const jwk = jwks.keys?.find((k) => k.kid === kid);
    if (!jwk) return null;
    return await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  } catch {
    return null;
  }
}

/**
 * Shared bearer-token verification -- originally handleUserinfo's own
 * inline logic, now also used by registerPage.ts's own managed-identity
 * creation path (REQ: a managed identity's guardian must be derived from
 * a real, scope-checked access token's own sub, never a client-supplied
 * free-text field -- see that file's own header comment for why) and by
 * handleTokenExchangeGrant's own subject_token check.
 *
 * Accepts tokens issued by this registrar itself, or (new) by any other
 * registrar this operator explicitly trusts (FEDERATED_TRUSTED_ISSUERS) --
 * the real gap a cross-registrar Managed Identity API call surfaced: a
 * guardian's own identity doesn't have to live on this same registrar,
 * so a token proving who they are doesn't either. The issuer is read from
 * the token's own (unverified at this point) `iss` claim, then the token
 * is verified against *that* issuer's own key -- never trusted just
 * because it claims to be from a trusted domain. An issuer this operator
 * hasn't explicitly trusted is rejected outright, same as an issuer that
 * doesn't match this registrar's own domain at all.
 *
 * jti revocation (oidc_revoked_jti) is only ever checked for this
 * registrar's own tokens -- a foreign registrar's own revocation table
 * isn't visible here, the same limitation any JWT-based federation has
 * without a shared introspection endpoint. Short token TTLs bound the
 * exposure; this isn't solved further here.
 */
export async function verifyAccessToken(env: Env, token: string): Promise<VerifiedAccessToken | null> {
  const decoded = decodeJwtUnsafe(token);
  if (!decoded || typeof decoded.header.kid !== "string") return null;
  const issuer = typeof decoded.payload.iss === "string" ? decoded.payload.iss : null;
  const selfIssuer = `https://${env.REGISTRAR_DOMAIN}`;

  let publicKey: CryptoKey | null;
  let checkLocalRevocation: boolean;
  if (issuer === selfIssuer) {
    const keypair = await getOrCreateSigningKeypair(env);
    publicKey = await crypto.subtle.importKey("jwk", keypair.publicKeyJwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    checkLocalRevocation = true;
  } else {
    const trusted = (env.FEDERATED_TRUSTED_ISSUERS ?? "").split(",").map((d) => d.trim()).filter(Boolean);
    if (!issuer || !trusted.includes(new URL(issuer).hostname)) return null;
    publicKey = await fetchForeignPublicKey(issuer, decoded.header.kid);
    checkLocalRevocation = false;
  }
  if (!publicKey) return null;

  const payload = await verifyJwt(token, publicKey);
  if (!payload || typeof payload.sub !== "string") return null;
  if (checkLocalRevocation && typeof payload.jti === "string" && (await isJtiRevoked(env, payload.jti))) return null;
  const scope = typeof payload.scope === "string" ? payload.scope.split(/\s+/).filter(Boolean) : [];
  return { sub: payload.sub, scope };
}

/** RFC 9728 §5.1: a protected resource's 401 names where to find its own metadata, so a generic (e.g. MCP) client can discover this registrar as the authorization server without being told out of band. */
function unauthorizedWithResourceMetadata(env: Env, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 401,
    headers: {
      "content-type": "application/json",
      "www-authenticate": `Bearer resource_metadata="https://${env.REGISTRAR_DOMAIN}/.well-known/oauth-protected-resource"`,
    },
  });
}

async function handleUserinfo(request: Request, env: Env): Promise<Response> {
  const auth = request.headers.get("authorization") ?? "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return unauthorizedWithResourceMetadata(env, "missing bearer token");

  const verified = await verifyAccessToken(env, token);
  if (!verified) return unauthorizedWithResourceMetadata(env, "invalid, expired, or revoked token");

  const ward = await getWardByDid(env, verified.sub);
  const claims: Record<string, unknown> = { sub: verified.sub, name: ward?.name };

  if (verified.scope.includes("email")) {
    const forwarding = await getVerifiedForwardingByDid(env, verified.sub);
    if (forwarding) {
      claims.email = forwarding.forward_to;
      claims.email_verified = true;
    }
  }
  return json(claims);
}
