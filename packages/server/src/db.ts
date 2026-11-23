import type { Operation } from "@did-guardian/lib";
import type { Env } from "./env.js";

export interface LogRow {
  did: string;
  seq: number;
  prev: string;
  operation: string; // JSON
  created_at: string;
}

/** The full operation log for a DID, oldest first, parsed. `[]` means the DID has never been registered. */
export async function getLog(env: Env, did: string): Promise<Operation[]> {
  const result = await env.DB.prepare("SELECT operation FROM logs WHERE did = ? ORDER BY seq ASC").bind(did).all<{ operation: string }>();
  return result.results.map((row) => JSON.parse(row.operation) as Operation);
}

/** The account dashboard's own activity feed: each operation with the time this registrar accepted it. */
export async function getLogWithTimestamps(env: Env, did: string): Promise<Array<{ operation: Operation; acceptedAt: string }>> {
  const result = await env.DB.prepare("SELECT operation, created_at FROM logs WHERE did = ? ORDER BY seq ASC").bind(did).all<{ operation: string; created_at: string }>();
  return result.results.map((row) => ({ operation: JSON.parse(row.operation) as Operation, acceptedAt: row.created_at }));
}

/**
 * Appends one operation. `prev` is the operation hash the op's own
 * `prev` member names, or `""` for the first (a create has no `prev`
 * member). The unique index on (did, prev) makes this REQ-10-8's own
 * enforcement: a concurrent append naming the same (did, prev) fails
 * here with a constraint violation (caught and reported as a conflict),
 * never as two operations both landing.
 */
export async function appendOperation(env: Env, did: string, seq: number, prev: string, operation: Operation, createdAt: string): Promise<boolean> {
  try {
    await env.DB.prepare("INSERT INTO logs (did, seq, prev, operation, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(did, seq, prev, JSON.stringify(operation), createdAt)
      .run();
    return true;
  } catch (e) {
    if (e instanceof Error && /UNIQUE constraint failed/.test(e.message)) return false;
    throw e;
  }
}

export interface NameRow {
  domain: string;
  name: string;
  did: string;
  created_at: string;
}

export async function getNameEntry(env: Env, domain: string, name: string): Promise<NameRow | null> {
  const row = await env.DB.prepare("SELECT * FROM names WHERE domain = ? AND name = ?").bind(domain, name).first<NameRow>();
  return row ?? null;
}

/** The reverse lookup -- a did's own display name, e.g. for OIDC userinfo. */
export async function getNameEntryByDid(env: Env, did: string): Promise<NameRow | null> {
  const row = await env.DB.prepare("SELECT * FROM names WHERE did = ?").bind(did).first<NameRow>();
  return row ?? null;
}

/** REQ-10-12: a name, once used, is never used again. Returns false if the (domain, name) pair is already taken -- the caller's own race-free check, same pattern as appendOperation. */
export async function insertNameEntry(env: Env, domain: string, name: string, did: string, createdAt: string): Promise<boolean> {
  try {
    await env.DB.prepare("INSERT INTO names (domain, name, did, created_at) VALUES (?, ?, ?, ?)").bind(domain, name, did, createdAt).run();
    return true;
  } catch (e) {
    if (e instanceof Error && /UNIQUE constraint failed/.test(e.message)) return false;
    throw e;
  }
}

/** For the admin console -- every name registered on this domain, newest first. */
export async function listNames(env: Env, domain: string): Promise<NameRow[]> {
  const result = await env.DB.prepare("SELECT * FROM names WHERE domain = ? ORDER BY created_at DESC").bind(domain).all<NameRow>();
  return result.results;
}

export interface HeldKeyRow {
  did: string;
  public_key: string;
  private_key_enc: string;
  login_secret_hash: string | null;
  created_at: string;
}

/** Presence of a row is "this registrar holds a key for this identity" (REQ-10-13/REQ-10-14). */
export async function getHeldKey(env: Env, did: string): Promise<HeldKeyRow | null> {
  const row = await env.DB.prepare("SELECT * FROM held_keys WHERE did = ?").bind(did).first<HeldKeyRow>();
  return row ?? null;
}

export async function insertHeldKey(env: Env, row: HeldKeyRow): Promise<void> {
  await env.DB.prepare("INSERT INTO held_keys (did, public_key, private_key_enc, login_secret_hash, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(row.did, row.public_key, row.private_key_enc, row.login_secret_hash, row.created_at)
    .run();
}

export async function setHeldKeyLoginSecretHash(env: Env, did: string, hash: string): Promise<void> {
  await env.DB.prepare("UPDATE held_keys SET login_secret_hash = ? WHERE did = ?").bind(hash, did).run();
}

/** Take-custody: once the caller's own `update` op naming their supplied key is durable in the log, this registrar's held key for them is gone for good -- not merely marked unused. */
export async function deleteHeldKey(env: Env, did: string): Promise<void> {
  await env.DB.prepare("DELETE FROM held_keys WHERE did = ?").bind(did).run();
}

/** Rotation: replaces the key this registrar holds for a did that already has one, keeping its existing login_secret_hash. */
export async function replaceHeldKey(env: Env, did: string, publicKey: string, privateKeyEnc: string): Promise<void> {
  await env.DB.prepare("UPDATE held_keys SET public_key = ?, private_key_enc = ? WHERE did = ?").bind(publicKey, privateKeyEnc, did).run();
}

export interface PendingProofRow {
  id: string;
  did: string;
  operation: string; // JSON, without `proof`
  proofs: string; // JSON array of DataIntegrityProof
  created_at: string;
  expires_at: string;
}

export async function insertPendingProof(env: Env, row: PendingProofRow): Promise<void> {
  await env.DB.prepare("INSERT INTO pending_proofs (id, did, operation, proofs, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(row.id, row.did, row.operation, row.proofs, row.created_at, row.expires_at)
    .run();
}

export async function getPendingProof(env: Env, id: string): Promise<PendingProofRow | null> {
  const row = await env.DB.prepare("SELECT * FROM pending_proofs WHERE id = ?").bind(id).first<PendingProofRow>();
  return row ?? null;
}

/** Every signer adds only its own proof (handoff #9): an atomic JSON array append via SQLite's own json_insert, never a read-modify-write -- two signers submitting at nearly the same instant both land. */
export async function appendPendingProof(env: Env, id: string, proof: unknown): Promise<void> {
  await env.DB.prepare("UPDATE pending_proofs SET proofs = json_insert(proofs, '$[#]', json(?)) WHERE id = ?")
    .bind(JSON.stringify(proof), id)
    .run();
}

/** Every still-live proposal naming `did` -- the account dashboard's own "needs your signature" list, filtered further by the caller against the operation's own permitted signers. */
export async function listPendingProofsForDid(env: Env, did: string): Promise<PendingProofRow[]> {
  const result = await env.DB.prepare("SELECT * FROM pending_proofs WHERE did = ? ORDER BY created_at ASC").bind(did).all<PendingProofRow>();
  return result.results;
}

/** Every pending proposal on this registrar, regardless of did -- the daily expiry sweep's own candidate set. */
export async function listAllPendingProofs(env: Env): Promise<PendingProofRow[]> {
  const result = await env.DB.prepare("SELECT * FROM pending_proofs ORDER BY created_at ASC").all<PendingProofRow>();
  return result.results;
}

export async function deletePendingProof(env: Env, id: string): Promise<void> {
  await env.DB.prepare("DELETE FROM pending_proofs WHERE id = ?").bind(id).run();
}

export interface OidcClientRow {
  client_id: string;
  client_secret_hash: string; // a throwaway, never-issued random value for a public client (token_endpoint_auth_method = "none") -- the column predates dynamic registration and stays NOT NULL rather than forcing a disruptive table rebuild
  redirect_uris: string; // JSON array
  name: string;
  token_endpoint_auth_method: string; // "client_secret_basic" | "none"
  registration_access_token_hash: string | null; // RFC 7592 -- lets the registering party read back its own client later; null for a client inserted by hand (pre-dynamic-registration) rather than via /oauth/register-client
  created_at: string;
  /** 0/1 (SQLite has no real boolean). Hotfix, migration 0012: whether this client may authenticate as a "trusted client acting on a ward's behalf" (clientAuth.ts) -- login-secret reissue, rotate, tombstone, relinquish, remove, adopt, take-custody. Always 0 for a dynamically self-registered client (insertOidcClient never mentions this column, so SQLite's own column default applies); settable only by a direct operator DB write, never through any endpoint. */
  trusted: number;
}

export async function getOidcClient(env: Env, clientId: string): Promise<OidcClientRow | null> {
  const row = await env.DB.prepare("SELECT * FROM oidc_clients WHERE client_id = ?").bind(clientId).first<OidcClientRow>();
  return row ?? null;
}

/** The admin console's own "OAuth Apps" list (adminPage.ts) -- every client ever registered on this registrar, newest first. Never projects out client_secret_hash/registration_access_token_hash; nothing calling this needs them. */
export async function listOidcClients(env: Env): Promise<Array<Omit<OidcClientRow, "client_secret_hash" | "registration_access_token_hash">>> {
  const result = await env.DB.prepare("SELECT client_id, redirect_uris, name, token_endpoint_auth_method, created_at FROM oidc_clients ORDER BY created_at DESC").all();
  return result.results as Array<Omit<OidcClientRow, "client_secret_hash" | "registration_access_token_hash">>;
}

/** Deletes a client and everything that references it (FK-ordered) -- the admin console's own "remove this app" action. oidc_revoked_jti is untouched: it keys on jti, not client_id, and a revoked token should stay revoked regardless of whether its issuing client still exists. */
export async function deleteOidcClient(env: Env, clientId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM oidc_refresh_tokens WHERE client_id = ?").bind(clientId).run();
  await env.DB.prepare("DELETE FROM oidc_auth_codes WHERE client_id = ?").bind(clientId).run();
  await env.DB.prepare("DELETE FROM oidc_consents WHERE client_id = ?").bind(clientId).run();
  await env.DB.prepare("DELETE FROM oidc_clients WHERE client_id = ?").bind(clientId).run();
}

/** `trusted` is deliberately not a parameter here -- every insert through this function (only ever dynamic self-registration, oidc.ts) gets SQLite's own column default (0, untrusted). Marking a client trusted is only ever a direct operator DB write. */
export async function insertOidcClient(env: Env, row: Omit<OidcClientRow, "trusted">): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO oidc_clients (client_id, client_secret_hash, redirect_uris, name, token_endpoint_auth_method, registration_access_token_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      row.client_id,
      row.client_secret_hash,
      row.redirect_uris,
      row.name,
      row.token_endpoint_auth_method,
      row.registration_access_token_hash,
      row.created_at,
    )
    .run();
}

export async function getOidcClientByRegistrationToken(env: Env, registrationAccessTokenHash: string): Promise<OidcClientRow | null> {
  const row = await env.DB.prepare("SELECT * FROM oidc_clients WHERE registration_access_token_hash = ?")
    .bind(registrationAccessTokenHash)
    .first<OidcClientRow>();
  return row ?? null;
}

export interface OidcConsentRow {
  ward_did: string;
  client_id: string;
  scope: string;
  granted_at: string;
}

export async function getOidcConsent(env: Env, wardDid: string, clientId: string): Promise<OidcConsentRow | null> {
  const row = await env.DB.prepare("SELECT * FROM oidc_consents WHERE ward_did = ? AND client_id = ?").bind(wardDid, clientId).first<OidcConsentRow>();
  return row ?? null;
}

export async function upsertOidcConsent(env: Env, row: OidcConsentRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO oidc_consents (ward_did, client_id, scope, granted_at) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(ward_did, client_id) DO UPDATE SET scope = excluded.scope, granted_at = excluded.granted_at",
  )
    .bind(row.ward_did, row.client_id, row.scope, row.granted_at)
    .run();
}

export interface OidcConsentWithClientName extends OidcConsentRow {
  client_name: string;
}

/** For the account dashboard's own "connected apps" section -- every app this identity has ever granted access to, newest first. */
export async function listOidcConsentsForWard(env: Env, wardDid: string): Promise<OidcConsentWithClientName[]> {
  const result = await env.DB.prepare(
    "SELECT c.ward_did, c.client_id, c.scope, c.granted_at, o.name AS client_name FROM oidc_consents c JOIN oidc_clients o ON o.client_id = c.client_id WHERE c.ward_did = ? ORDER BY c.granted_at DESC",
  )
    .bind(wardDid)
    .all<OidcConsentWithClientName>();
  return result.results;
}

export async function deleteOidcConsent(env: Env, wardDid: string, clientId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM oidc_consents WHERE ward_did = ? AND client_id = ?").bind(wardDid, clientId).run();
}

/** Revoking access to an app has to actually revoke access, not just "stop remembering consent" -- kills every still-live refresh token this (ward, client) pair has outstanding, so a prior grant can't keep minting fresh access tokens after the consent record is gone. */
export async function revokeRefreshTokensForWardAndClient(env: Env, wardDid: string, clientId: string): Promise<void> {
  await env.DB.prepare("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE ward_did = ? AND client_id = ?").bind(wardDid, clientId).run();
}

export interface AuthCodeRow {
  code: string;
  client_id: string;
  ward_did: string;
  redirect_uri: string;
  code_challenge: string | null;
  code_challenge_method: string | null;
  scope: string;
  nonce: string | null;
  expires_at: string;
  used: number;
  resource: string | null;
}

export async function insertAuthCode(env: Env, row: AuthCodeRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO oidc_auth_codes (code, client_id, ward_did, redirect_uri, code_challenge, code_challenge_method, scope, nonce, expires_at, used, resource) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
  )
    .bind(
      row.code,
      row.client_id,
      row.ward_did,
      row.redirect_uri,
      row.code_challenge,
      row.code_challenge_method,
      row.scope,
      row.nonce,
      row.expires_at,
      row.resource,
    )
    .run();
}

export async function consumeAuthCode(env: Env, code: string): Promise<AuthCodeRow | null> {
  const row = await env.DB.prepare("SELECT * FROM oidc_auth_codes WHERE code = ? AND used = 0").bind(code).first<AuthCodeRow>();
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  await env.DB.prepare("UPDATE oidc_auth_codes SET used = 1 WHERE code = ?").bind(code).run();
  return row;
}

export interface RefreshTokenRow {
  token_hash: string;
  client_id: string;
  ward_did: string;
  scope: string;
  family_id: string;
  created_at: string;
  expires_at: string;
  revoked: number;
  resource: string | null;
}

export async function insertRefreshToken(env: Env, row: RefreshTokenRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO oidc_refresh_tokens (token_hash, client_id, ward_did, scope, family_id, created_at, expires_at, revoked, resource) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)",
  )
    .bind(row.token_hash, row.client_id, row.ward_did, row.scope, row.family_id, row.created_at, row.expires_at, row.resource)
    .run();
}

export async function getRefreshToken(env: Env, tokenHash: string): Promise<RefreshTokenRow | null> {
  const row = await env.DB.prepare("SELECT * FROM oidc_refresh_tokens WHERE token_hash = ?").bind(tokenHash).first<RefreshTokenRow>();
  return row ?? null;
}

export async function revokeRefreshToken(env: Env, tokenHash: string): Promise<void> {
  await env.DB.prepare("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE token_hash = ?").bind(tokenHash).run();
}

/** Reuse-detection response: an already-revoked refresh token being presented again means it was likely stolen -- revoke every token descended from the same original grant, not just the one reused. */
export async function revokeRefreshTokenFamily(env: Env, familyId: string): Promise<void> {
  await env.DB.prepare("UPDATE oidc_refresh_tokens SET revoked = 1 WHERE family_id = ?").bind(familyId).run();
}

export async function insertRevokedJti(env: Env, jti: string, revokedAt: string): Promise<void> {
  await env.DB.prepare("INSERT INTO oidc_revoked_jti (jti, revoked_at) VALUES (?, ?) ON CONFLICT(jti) DO NOTHING").bind(jti, revokedAt).run();
}

export async function isJtiRevoked(env: Env, jti: string): Promise<boolean> {
  const row = await env.DB.prepare("SELECT 1 FROM oidc_revoked_jti WHERE jti = ?").bind(jti).first();
  return row !== null;
}

export interface SigningKeyRow {
  kid: string;
  public_key: string;
  private_key_enc: string;
}

export async function getSigningKey(env: Env): Promise<SigningKeyRow | null> {
  const row = await env.DB.prepare("SELECT kid, public_key, private_key_enc FROM oidc_signing_key WHERE id = 1").first<SigningKeyRow>();
  return row ?? null;
}

export async function insertSigningKey(env: Env, row: SigningKeyRow & { created_at: string }): Promise<void> {
  await env.DB.prepare("INSERT INTO oidc_signing_key (id, kid, public_key, private_key_enc, created_at) VALUES (1, ?, ?, ?, ?)")
    .bind(row.kid, row.public_key, row.private_key_enc, row.created_at)
    .run();
}

export async function insertLoginSession(env: Env, sessionId: string, wardDid: string, createdAt: string, expiresAt: string): Promise<void> {
  await env.DB.prepare("INSERT INTO login_sessions (session_id, ward_did, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .bind(sessionId, wardDid, createdAt, expiresAt)
    .run();
}

export async function getLoginSession(env: Env, sessionId: string): Promise<{ ward_did: string; expires_at: string } | null> {
  const row = await env.DB.prepare("SELECT ward_did, expires_at FROM login_sessions WHERE session_id = ?").bind(sessionId).first<{ ward_did: string; expires_at: string }>();
  return row ?? null;
}

/** Logout (login.ts's own endSession) -- a no-op if the session was already gone (expired, or already logged out elsewhere). */
export async function deleteLoginSession(env: Env, sessionId: string): Promise<void> {
  await env.DB.prepare("DELETE FROM login_sessions WHERE session_id = ?").bind(sessionId).run();
}

/**
 * R2-0.5 (round-2 audit): every session for one ward, not just one by
 * id -- called from registrar.ts's submitOperation whenever an
 * `update` is accepted, regardless of who signed it or which path
 * produced it (self-service /rotate, take-custody, a guardian's own
 * CLI-signed recovery submitted directly, or the generic multi-signer
 * proposal flow). A key rotation and a login session are unrelated
 * credentials here (login_secret, not the operational key, is what a
 * session actually proves) -- without this, whoever holds a ward's old
 * login_secret keeps a working session through a rotation that was
 * specifically meant to recover from exactly that kind of compromise.
 *
 * Audit r3 (F7/dead-code review): this function itself survived, but
 * nothing called it any more -- the Step 5 server rewrite carried the
 * helper over without its own caller. Re-wired below.
 */
export async function deleteAllLoginSessionsForWard(env: Env, wardDid: string): Promise<void> {
  await env.DB.prepare("DELETE FROM login_sessions WHERE ward_did = ?").bind(wardDid).run();
}

export interface EmailForwardingRow {
  did: string;
  forward_to: string;
  verified: number;
  verification_token: string | null;
  created_at: string;
}

export async function upsertEmailForwarding(env: Env, row: Omit<EmailForwardingRow, "verified"> & { verified?: number }): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO email_forwarding (did, forward_to, verified, verification_token, created_at) VALUES (?, ?, 0, ?, ?) " +
      "ON CONFLICT(did) DO UPDATE SET forward_to = excluded.forward_to, verified = 0, verification_token = excluded.verification_token, created_at = excluded.created_at",
  )
    .bind(row.did, row.forward_to, row.verification_token, row.created_at)
    .run();
}

export async function getEmailForwardingByToken(env: Env, token: string): Promise<EmailForwardingRow | null> {
  const row = await env.DB.prepare("SELECT * FROM email_forwarding WHERE verification_token = ?").bind(token).first<EmailForwardingRow>();
  return row ?? null;
}

export async function markEmailForwardingVerified(env: Env, did: string): Promise<void> {
  await env.DB.prepare("UPDATE email_forwarding SET verified = 1, verification_token = NULL WHERE did = ?").bind(did).run();
}

export async function getVerifiedForwardingByDid(env: Env, did: string): Promise<EmailForwardingRow | null> {
  const row = await env.DB.prepare("SELECT * FROM email_forwarding WHERE did = ? AND verified = 1").bind(did).first<EmailForwardingRow>();
  return row ?? null;
}

