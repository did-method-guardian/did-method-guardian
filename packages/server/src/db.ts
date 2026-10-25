import type { Env } from "./env.js";

export interface WardRow {
  name: string;
  did: string;
  public_key: string;
  private_key_enc: string;
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

export async function appendOperation(env: Env, op: OperationRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO operations (cid, did, prev_cid, op_type, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
  )
    .bind(op.cid, op.did, op.prev_cid, op.op_type, op.payload, op.created_at)
    .run();
}

/** Full operation log for a DID, oldest first -- the real resolution path, never a cache. */
export async function getOperationLog(env: Env, did: string): Promise<OperationRow[]> {
  const result = await env.DB.prepare("SELECT * FROM operations WHERE did = ? ORDER BY created_at ASC").bind(did).all<OperationRow>();
  return result.results;
}

export async function setLoginSecretHash(env: Env, name: string, hash: string): Promise<void> {
  await env.DB.prepare("UPDATE wards SET login_secret_hash = ? WHERE name = ?").bind(hash, name).run();
}

/** Only ever called after a custodial_rotate op this registrar itself just signed and appended has been accepted (registrar.ts's own rotateWard) -- the stored key material this registrar custodies for a ward moves to the new keypair only once the operation it's meant to back is already durable in the log, never before. */
export async function updateWardKeys(env: Env, did: string, publicKey: string, privateKeyEnc: string): Promise<void> {
  await env.DB.prepare("UPDATE wards SET public_key = ?, private_key_enc = ? WHERE did = ?").bind(publicKey, privateKeyEnc, did).run();
}

export interface OidcClientRow {
  client_id: string;
  client_secret_hash: string;
  redirect_uris: string; // JSON array
  name: string;
  created_at: string;
}

export async function getOidcClient(env: Env, clientId: string): Promise<OidcClientRow | null> {
  const row = await env.DB.prepare("SELECT * FROM oidc_clients WHERE client_id = ?").bind(clientId).first<OidcClientRow>();
  return row ?? null;
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
}

export async function insertAuthCode(env: Env, row: AuthCodeRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO oidc_auth_codes (code, client_id, ward_did, redirect_uri, code_challenge, code_challenge_method, scope, nonce, expires_at, used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
  )
    .bind(row.code, row.client_id, row.ward_did, row.redirect_uri, row.code_challenge, row.code_challenge_method, row.scope, row.nonce, row.expires_at)
    .run();
}

export async function consumeAuthCode(env: Env, code: string): Promise<AuthCodeRow | null> {
  const row = await env.DB.prepare("SELECT * FROM oidc_auth_codes WHERE code = ? AND used = 0").bind(code).first<AuthCodeRow>();
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;
  await env.DB.prepare("UPDATE oidc_auth_codes SET used = 1 WHERE code = ?").bind(code).run();
  return row;
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
  collected_sigs: string; // JSON object, signer DID -> sig
  state: string;
  created_at: string;
  expires_at: string;
}

export async function insertPendingOperation(env: Env, row: PendingOperationRow): Promise<void> {
  await env.DB.prepare(
    "INSERT INTO pending_operations (id, ward_did, op_type, partial_op, required_signers, collected_sigs, state, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(row.id, row.ward_did, row.op_type, row.partial_op, row.required_signers, row.collected_sigs, row.state, row.created_at, row.expires_at)
    .run();
}

export async function getPendingOperation(env: Env, id: string): Promise<PendingOperationRow | null> {
  const row = await env.DB.prepare("SELECT * FROM pending_operations WHERE id = ?").bind(id).first<PendingOperationRow>();
  return row ?? null;
}

export async function updatePendingOperationState(env: Env, id: string, state: string, collectedSigs: string): Promise<void> {
  await env.DB.prepare("UPDATE pending_operations SET state = ?, collected_sigs = ? WHERE id = ?").bind(state, collectedSigs, id).run();
}

/** Every still-live (not finalized/declined/expired) proposal naming `signerDid` somewhere in its own `required_signers` -- advisory, same spirit as that column itself (rules.ts's own isSatisfied is the real gate, this is just who to show/notify). */
export async function listPendingOperationsForSigner(env: Env, signerDid: string): Promise<PendingOperationRow[]> {
  const result = await env.DB.prepare(
    "SELECT * FROM pending_operations WHERE state NOT IN ('finalized', 'declined', 'expired') ORDER BY created_at ASC",
  ).all<PendingOperationRow>();
  return result.results.filter((row) => (JSON.parse(row.required_signers) as string[]).includes(signerDid));
}
