import type { Env } from "./env.js";

export interface WardRow {
  name: string;
  did: string;
  public_key: string;
  private_key_enc: string;
  created_at: string;
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
    "INSERT INTO wards (name, did, public_key, private_key_enc, created_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(ward.name, ward.did, ward.public_key, ward.private_key_enc, ward.created_at)
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
