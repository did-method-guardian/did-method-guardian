import type { Env } from "./env.js";

export interface WardRow {
  name: string;
  did: string;
  public_key: string;
  private_key_enc: string; // a non-ciphertext sentinel ("") once custody_mode is "self" -- see getWardCustodyMode/clearWardPrivateKey below
  created_at: string;
  login_secret_hash: string | null;
}

export interface OperationRow {
  cid: string;
  did: string;
  prev_cid: string | null;
  op_type: string;
  payload: string;
  created_at: string;
}

export async function getWardByName(env: Env, name: string): Promise<WardRow | null> {
  const row = await env.DB.prepare("SELECT * FROM wards WHERE name = ?").bind(name).first<WardRow>();
  return row ?? null;
}

export async function getWardByDid(env: Env, did: string): Promise<WardRow | null> {
  const row = await env.DB.prepare("SELECT * FROM wards WHERE did = ?").bind(did).first<WardRow>();
  return row ?? null;
}

export async function insertWard(env: Env, ward: WardRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO wards (name, did, public_key, private_key_enc, created_at, login_secret_hash) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(ward.name, ward.did, ward.public_key, ward.private_key_enc, ward.created_at, ward.login_secret_hash)
    .run();
}

export interface WardSummary {
  name: string;
  did: string;
  created_at: string;
}

/** For the admin console (adminPage.ts) -- every ward on this registrar, newest first. Projects out public_key/private_key_enc/login_secret_hash deliberately; nothing calling this needs them. */
export async function listWards(env: Env): Promise<WardSummary[]> {
  const result = await env.DB.prepare("SELECT name, did, created_at FROM wards ORDER BY created_at DESC").all<WardSummary>();
  return result.results;
}

export async function appendOperation(env: Env, op: OperationRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO operations (cid, did, prev_cid, op_type, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(op.cid, op.did, op.prev_cid, op.op_type, op.payload, op.created_at)
    .run();
}

/**
 * WS-1.12 (audit): appends `op`, but only if the number of existing rows
 * for its exact (did, prev_cid) pair still equals `expectedExistingCount`
 * at the instant of insert -- one atomic statement, not a separate
 * read-then-write, closing the race between submitOperation's own
 * verification (which read the log some time earlier in the request)
 * and this insert actually landing. Two concurrent requests both
 * extending the same then-current head would otherwise both pass
 * verification and both insert, forking the log by accident rather than
 * through a deliberate, policy-checked nullification. Returns whether
 * the insert actually happened; `false` means some other operation won
 * this exact (did, prev_cid) slot in between -- the caller must treat
 * that as a conflict to retry against the now-current log, never as a
 * silent success.
 *
 * `expectedExistingCount` is 0 for an ordinary append (nobody has used
 * this prev_cid yet) and 1 for a nullification (exactly the one original
 * entry being superseded, and only that one -- checkNullification
 * already enforced "one level only" before this is ever called, so a
 * count of 1 here is never itself someone else's nullification race;
 * it's either the ordinary original entry, or this call has already
 * lost the race and sees 1 where it expected 0).
 */
export async function appendOperationIfCountMatches(env: Env, op: OperationRow, expectedExistingCount: number): Promise<boolean> {
  const result = await env.DB.prepare(
    `INSERT INTO operations (cid, did, prev_cid, op_type, payload, created_at)
     SELECT ?, ?, ?, ?, ?, ?
     WHERE (SELECT COUNT(*) FROM operations WHERE did = ? AND prev_cid IS ?) = ?`,
  )
    .bind(op.cid, op.did, op.prev_cid, op.op_type, op.payload, op.created_at, op.did, op.prev_cid, expectedExistingCount)
    .run();
  return (result.meta.rows_written ?? 0) > 0;
}

/**
 * Full operation log for a DID, oldest first -- the real resolution
 * path, never a cache. Ordered by SQLite's own implicit `rowid` (this
 * table has no `WITHOUT ROWID` clause and no INTEGER PRIMARY KEY, so one
 * exists and is assigned in strict insertion order), not `created_at` --
 * WS-1.12 (audit): a TEXT millisecond timestamp has no tiebreaker for
 * two operations accepted in the same millisecond, and reconstructChain
 * (document.ts) requires its input in true causal order or it throws.
 * rowid gives that order unconditionally, with no new column needed.
 */
export async function getOperationLog(env: Env, did: string): Promise<OperationRow[]> {
  const result = await env.DB.prepare("SELECT * FROM operations WHERE did = ? ORDER BY rowid ASC").bind(did).all<OperationRow>();
  return result.results;
}

export async function setLoginSecretHash(env: Env, name: string, hash: string): Promise<void> {
  await env.DB.prepare("UPDATE wards SET login_secret_hash = ? WHERE name = ?").bind(hash, name).run();
}

/** Only ever called after a custodial_rotate op this registrar itself just signed and appended has been accepted (registrar.ts's own rotateWard) -- the stored key material this registrar custodies for a ward moves to the new keypair only once the operation it's meant to back is already durable in the log, never before. */
export async function updateWardKeys(env: Env, did: string, publicKey: string, privateKeyEnc: string): Promise<void> {
  await env.DB.prepare("UPDATE wards SET public_key = ?, private_key_enc = ? WHERE did = ?").bind(publicKey, privateKeyEnc, did).run();
}

/**
 * Which of a ward's keys is live where (0011_take_custody.sql): no row in
 * ward_custody means "registrar", the default and by far the common case
 * -- a row only ever gets written once a ward actually takes custody, and
 * custody_mode only ever moves one direction (registrar -> self; there's
 * no code path that writes it back).
 */
export async function getWardCustodyMode(env: Env, did: string): Promise<"registrar" | "self"> {
  const row = await env.DB.prepare("SELECT custody_mode FROM ward_custody WHERE did = ?").bind(did).first<{ custody_mode: "registrar" | "self" }>();
  return row?.custody_mode ?? "registrar";
}

/**
 * Take-custody (registrar.ts's takeCustody): the caller's supplied public key
 * replaces this registrar's, and private_key_enc is overwritten with ""
 * -- not a real ciphertext, so even a KEY_ENCRYPTION_KEY compromise can't
 * recover a key this registrar no longer holds. Called only after the
 * custodial_rotate op backing this is already durable in the log, same
 * ordering updateWardKeys relies on. Two statements, not a transaction --
 * D1's batch() would be the right tool if this registrar needs
 * atomicity here beyond what it already has (a half-applied write just
 * leaves custody_mode as "registrar" until retried, never the reverse).
 */
export async function takeCustodyOfWardKey(env: Env, did: string, publicKey: string): Promise<void> {
  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE wards SET public_key = ?, private_key_enc = '' WHERE did = ?").bind(publicKey, did).run();
  await env.DB.prepare(
    "INSERT INTO ward_custody (did, custody_mode, taken_custody_at) VALUES (?, 'self', ?) ON CONFLICT(did) DO UPDATE SET custody_mode = 'self', taken_custody_at = ?",
  )
    .bind(did, now, now)
    .run();
}

/**
 * For a ward that's self-held from birth (a client-submitted
 * genesis accepted by registrar.ts's acceptGenesis) -- unlike
 * takeCustodyOfWardKey above, there's no prior "registrar" row to
 * transition from and no wards.public_key to overwrite (insertWard
 * already wrote the ward's key and an empty private_key_enc).
 */
export async function insertWardCustody(env: Env, did: string, custodyMode: "registrar" | "self", at: string): Promise<void> {
  await env.DB.prepare("INSERT INTO ward_custody (did, custody_mode, taken_custody_at) VALUES (?, ?, ?)").bind(did, custodyMode, at).run();
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

/** R2-0.5 (round-2 audit): every session for one ward, not just one by id -- used when an externally-produced rotation (registrar.ts's submitOperation, after accepting a custodial_rotate it didn't itself sign) means whoever's holding this ward's OLD login secret might not be its legitimate owner any more. */
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

export interface PendingOperationRow {
  id: string;
  ward_did: string;
  op_type: string;
  partial_op: string; // JSON
  required_signers: string; // JSON array of DIDs
  collected_sigs: string; // JSON object, signer DID -> DataIntegrityProof
  /** JSON object, signer DID -> ISO timestamp of when THIS registrar collected that signer's own signature -- REQ-4-2's point-in-time key resolution needs this at finalize time, since a signer may have rotated their own key in the meantime (see rules.ts's VerificationContext.sigTimestamps). Mirrors collected_sigs' own keys exactly. */
  sig_timestamps: string;
  state: string;
  created_at: string;
  expires_at: string;
}

export async function insertPendingOperation(env: Env, row: PendingOperationRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO pending_operations (id, ward_did, op_type, partial_op, required_signers, collected_sigs, sig_timestamps, state, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      row.id,
      row.ward_did,
      row.op_type,
      row.partial_op,
      row.required_signers,
      row.collected_sigs,
      row.sig_timestamps,
      row.state,
      row.created_at,
      row.expires_at,
    )
    .run();
}

export async function getPendingOperation(env: Env, id: string): Promise<PendingOperationRow | null> {
  const row = await env.DB.prepare("SELECT * FROM pending_operations WHERE id = ?").bind(id).first<PendingOperationRow>();
  return row ?? null;
}

export async function updatePendingOperationState(env: Env, id: string, state: string, collectedSigs: string, sigTimestamps: string): Promise<void> {
  await env.DB.prepare("UPDATE pending_operations SET state = ?, collected_sigs = ?, sig_timestamps = ? WHERE id = ?")
    .bind(state, collectedSigs, sigTimestamps, id)
    .run();
}

/** Every still-live (not finalized/declined/expired) proposal naming `signerDid` somewhere in its own `required_signers` -- advisory, same spirit as that column itself (rules.ts's own isSatisfied is the real gate, this is just who to show/notify). */
export async function listPendingOperationsForSigner(env: Env, signerDid: string): Promise<PendingOperationRow[]> {
  const result = await env.DB.prepare(
    "SELECT * FROM pending_operations WHERE state NOT IN ('finalized', 'declined', 'expired') ORDER BY created_at ASC",
  ).all<PendingOperationRow>();
  return result.results.filter((row) => (JSON.parse(row.required_signers) as string[]).includes(signerDid));
}

/** Every still-pending (any state, including satisfied/finalized -- a caller deciding whether to send a reminder filters that itself) proposal naming `wardDid`, newest first. Used by the daily reminder cron (task #113) to scan every ward's own pending_operations without needing a signer to filter by. */
export async function listPendingOperationsCollecting(env: Env): Promise<PendingOperationRow[]> {
  const result = await env.DB.prepare("SELECT * FROM pending_operations WHERE state = 'collecting'").all<PendingOperationRow>();
  return result.results;
}

export interface PendingOperationTokenRow {
  pending_op_id: string;
  signer_did: string;
  token: string;
  created_at: string;
  last_notified_at: string;
}

/** The existing token for (pendingOpId, signerDid), if one has already been issued -- reused across every notification about the same proposal so earlier email links keep working. */
export async function getPendingOperationToken(env: Env, pendingOpId: string, signerDid: string): Promise<PendingOperationTokenRow | null> {
  const row = await env.DB.prepare("SELECT * FROM pending_operation_tokens WHERE pending_op_id = ? AND signer_did = ?").bind(pendingOpId, signerDid).first<PendingOperationTokenRow>();
  return row ?? null;
}

export async function insertPendingOperationToken(env: Env, row: PendingOperationTokenRow): Promise<void> {
  await env.DB.prepare("INSERT INTO pending_operation_tokens (pending_op_id, signer_did, token, created_at, last_notified_at) VALUES (?, ?, ?, ?, ?)")
    .bind(row.pending_op_id, row.signer_did, row.token, row.created_at, row.last_notified_at)
    .run();
}

export async function touchPendingOperationToken(env: Env, pendingOpId: string, signerDid: string, now: string): Promise<void> {
  await env.DB.prepare("UPDATE pending_operation_tokens SET last_notified_at = ? WHERE pending_op_id = ? AND signer_did = ?").bind(now, pendingOpId, signerDid).run();
}

/** Resolves a one-click email link's token back to which proposal and which signer it was issued for -- the token itself is the proof (email possession), no signature needed. */
export async function getPendingOperationByToken(env: Env, token: string): Promise<PendingOperationTokenRow | null> {
  const row = await env.DB.prepare("SELECT * FROM pending_operation_tokens WHERE token = ?").bind(token).first<PendingOperationTokenRow>();
  return row ?? null;
}

/** Every token row for a pending op whose last_notified_at is more than `olderThanMs` ago -- the daily reminder cron's own candidate set. */
export async function listStaleTokensForPendingOp(env: Env, pendingOpId: string, olderThanIso: string): Promise<PendingOperationTokenRow[]> {
  const result = await env.DB.prepare("SELECT * FROM pending_operation_tokens WHERE pending_op_id = ? AND last_notified_at < ?").bind(pendingOpId, olderThanIso).all<PendingOperationTokenRow>();
  return result.results;
}

export interface RelayInboxRow {
  signer_did: string;
  pending_operation_id: string;
  ward_did: string;
  op_type: string;
  status: string;
  created_at: string;
}

/** handleRelayNotify's own durable record (pendingOps.ts) -- see migration 0010's header comment for why this exists and what it does/doesn't guarantee. An upsert: the same (signer, op) pair can be notified more than once as an operation progresses, and re-opens a previously resolved entry if relay-notify somehow fires again for it (shouldn't happen once genuinely resolved, but never silently drop a real notification over it). */
export async function upsertRelayInboxEntry(env: Env, row: { signer_did: string; pending_operation_id: string; ward_did: string; op_type: string; created_at: string }): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO relay_inbox (signer_did, pending_operation_id, ward_did, op_type, status, created_at) VALUES (?, ?, ?, ?, 'open', ?) " +
      "ON CONFLICT(signer_did, pending_operation_id) DO UPDATE SET status = 'open', resolved_at = NULL",
  )
    .bind(row.signer_did, row.pending_operation_id, row.ward_did, row.op_type, row.created_at)
    .run();
}

/** The account dashboard's own "needs your signature on another registrar" section -- open entries only; a resolved one has already been signed or declined through this registrar's /relay-sign. */
export async function listOpenRelayInboxForSigner(env: Env, signerDid: string): Promise<RelayInboxRow[]> {
  const result = await env.DB.prepare("SELECT * FROM relay_inbox WHERE signer_did = ? AND status = 'open' ORDER BY created_at DESC").bind(signerDid).all<RelayInboxRow>();
  return result.results;
}

/** Marks an inbox entry resolved once this registrar has actually signed or declined it on the signer's behalf (relaySign.ts) -- a no-op if no matching row exists (e.g. the signer acted before any notification ever arrived). */
export async function resolveRelayInboxEntry(env: Env, signerDid: string, pendingOperationId: string, now: string): Promise<void> {
  await env.DB.prepare("UPDATE relay_inbox SET status = 'resolved', resolved_at = ? WHERE signer_did = ? AND pending_operation_id = ?").bind(now, signerDid, pendingOperationId).run();
}
