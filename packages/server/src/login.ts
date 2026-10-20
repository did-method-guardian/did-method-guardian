import type { Env } from "./env.js";
import { getWardByName, getLoginSession, insertLoginSession } from "./db.js";
import { hashSecret, randomSecret } from "./secretBox.js";

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

export async function verifyLogin(env: Env, name: string, loginSecret: string): Promise<string | null> {
  const ward = await getWardByName(env, name);
  if (!ward || !ward.login_secret_hash) return null;
  const hash = await hashSecret(loginSecret);
  if (hash !== ward.login_secret_hash) return null;
  return ward.did;
}

export async function createLoginSession(env: Env, wardDid: string): Promise<string> {
  const sessionId = randomSecret();
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_TTL_MS);
  await insertLoginSession(env, sessionId, wardDid, now.toISOString(), expires.toISOString());
  return sessionId;
}

export async function resolveSession(env: Env, sessionId: string): Promise<string | null> {
  const session = await getLoginSession(env, sessionId);
  if (!session) return null;
  if (new Date(session.expires_at).getTime() < Date.now()) return null;
  return session.ward_did;
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}
