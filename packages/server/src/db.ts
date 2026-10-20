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
