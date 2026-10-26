import type { Env } from "./env.js";
import { getWardByName, getLoginSession, insertLoginSession } from "./db.js";
import { hashSecret, randomSecret } from "./secretBox.js";

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

/**
 * Liberal in what it accepts: "alice", "alice@acme.com", "alice:acme.com",
 * and "did:guardian:alice:acme.com" all mean the same thing on a login
 * form, since the domain part is implied by whichever registrar is
 * actually being asked -- strict in what it produces, every other page
 * this registrar renders only ever shows the bare name. Whatever domain
 * was typed (if any) is simply discarded, never checked against this
 * registrar's own -- it isn't security-relevant, since the login_secret
 * itself is what actually authenticates; a wrong name (with or without a
 * domain tacked on) just fails to match any account, same as today.
 */
function normalizeLoginName(input: string): string {
  let s = input.trim();
  if (s.startsWith("did:guardian:")) s = s.slice("did:guardian:".length);
  const sepIdx = s.search(/[@:]/);
  return sepIdx === -1 ? s : s.slice(0, sepIdx);
}

export async function verifyLogin(env: Env, name: string, loginSecret: string): Promise<string | null> {
  const ward = await getWardByName(env, normalizeLoginName(name));
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
