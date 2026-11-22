import type { Env } from "./env.js";
import { getHeldKey, getNameEntry, getLoginSession, insertLoginSession, deleteLoginSession } from "./db.js";
import { verifyCredential, randomSecret } from "./secretBox.js";

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

/**
 * Liberal in what it accepts: "alice", "alice@acme.com", "alice:acme.com",
 * and "did:guardian:acme.com:alice" all mean the same thing on a login
 * form, since the domain part is implied by whichever registrar is
 * actually being asked -- strict in what it produces, every other page
 * this registrar renders only ever shows the bare name. Whatever domain
 * was typed (if any) is simply discarded, never checked against this
 * registrar's own -- it isn't security-relevant, since the login_secret
 * itself is what actually authenticates; a wrong name (with or without a
 * domain tacked on) just fails to match any account, same as today.
 *
 * A full "did:guardian:" string is domain-first (the DID's own grammar,
 * matching did:web) and needs its *last* segment as the name; the
 * shorthand forms ("alice@acme.com", "alice:acme.com") stay name-first,
 * matching the email-address convention humans already expect -- two
 * different, deliberately independent conventions for the same entity,
 * same as how an email address and a URL path order "alice at acme"
 * differently without anyone finding that confusing.
 */
function normalizeLoginName(input: string): string {
  const s = input.trim();
  if (s.startsWith("did:guardian:")) {
    const rest = s.slice("did:guardian:".length).split(":");
    return rest.length > 1 ? rest[rest.length - 1] : rest[0];
  }
  const sepIdx = s.search(/[@:]/);
  return sepIdx === -1 ? s : s.slice(0, sepIdx);
}

/**
 * "_" or this registrar's own bare domain, typed with no name at all, means
 * the bare-domain root identity (wards.name's own "" sentinel) -- the same
 * identity "@acme.com" already reaches today, by construction: normalizeLoginName
 * splits on the first "@"/":" it finds, and one sitting at position 0 slices
 * down to "" already. Checked here (needs `env`; normalizeLoginName stays a
 * pure function with no env dependency) rather than inside normalizeLoginName
 * itself. Exported for oidc.ts's own use -- comparing a relying party's
 * login_hint against an already-logged-in session's own name needs the
 * exact same normalization a real login attempt would get, not a second,
 * possibly-drifting implementation of the same rule.
 *
 * `_@acme.com` also means root, not a ward literally named "_" -- confirmed
 * live this was a real gap, not theoretical: a relying party that forces a
 * `name@domain` shape on its own login form (Tailscale's own custom-OIDC
 * login does) leaves `_@domain` as the *only* way to express "the root
 * identity" through that form at all, since neither bare `_` nor bare
 * `@domain` fits what the form demands. Checked on the name normalizeLoginName
 * actually extracts, not the raw trimmed input -- "_" has to survive having
 * an "@domain" sliced off after it, the same way a real ward's own name
 * already does.
 */
export function normalizeLoginIdentifier(env: Env, input: string): string {
  const trimmed = input.trim();
  if (trimmed === env.REGISTRAR_DOMAIN) return "";
  const name = normalizeLoginName(trimmed);
  return name === "_" ? "" : name;
}

export async function verifyLogin(env: Env, name: string, loginSecret: string): Promise<string | null> {
  const normalized = normalizeLoginIdentifier(env, name);
  const nameEntry = await getNameEntry(env, env.REGISTRAR_DOMAIN, normalized);
  if (!nameEntry) return null;
  const held = await getHeldKey(env, nameEntry.did);
  if (!held || !held.login_secret_hash) return null;
  if (!(await verifyCredential(loginSecret, held.login_secret_hash))) return null;
  return held.did;
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

/** Logs out -- deletes the session row server-side (not just the cookie client-side), so the old session id can't be replayed even if it somehow survives the browser clearing it. */
export async function endSession(env: Env, sessionId: string): Promise<void> {
  await deleteLoginSession(env, sessionId);
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
