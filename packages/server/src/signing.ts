// REQ-10-13/REQ-10-14: this registrar signs with a held key only on an
// authenticated request from that identity, and never produces proofs for
// more than one identity in one request apart from the attestation.
import { createAttestation, createProof, operationHash, verifyLog, type CreateOp, type DataIntegrityProof, type Did, type Key } from "@did-guardian/lib";
import { getHeldKey, getLog, type HeldKeyRow } from "./db.js";
import { decryptSecret } from "./secretBox.js";
import { didFor, type Env } from "./env.js";
import { RegistrarError } from "./registrarError.js";
import { readCookie, resolveSession } from "./login.js";
import { authenticateOidcClient } from "./clientAuth.js";

declare const authenticatedRequestBrand: unique symbol;

/**
 * Proof that SOME request was actually checked against `identity` --
 * the only way to produce one is authenticateRequest, below. signAs
 * takes this instead of a bare Did specifically so a call site can't
 * satisfy REQ-10-13's own check by just passing the same value twice
 * (every call site used to read `signAs(env, did, did, op)`, which is
 * trivially always true and proves nothing about whether this request
 * was ever actually authenticated -- the real protection was always
 * that every caller happened to check authenticatedAs/callerIdentity
 * first, a convention the type system couldn't enforce).
 */
export interface AuthenticatedRequest {
  readonly identity: Did;
  readonly [authenticatedRequestBrand]: true;
}

/**
 * REQ-10-13: checks whether `request` is actually authenticated as
 * `did` -- a gw_session for that exact identity, or a trusted OIDC
 * client (which has no identity of its own, so it may act as any).
 * Returns null, never throws, on a mismatch or no authentication at
 * all -- the caller decides how to report that.
 */
export async function authenticateRequest(request: Request, env: Env, did: Did): Promise<AuthenticatedRequest | null> {
  const sessionId = readCookie(request, "gw_session");
  const sessionDid = sessionId ? await resolveSession(env, sessionId) : null;
  if (sessionDid === did) return { identity: did } as AuthenticatedRequest;
  if (sessionDid) return null; // signed in as someone else -- a trusted client never overrides an existing session's own identity
  const trustedClient = await authenticateOidcClient(request, env);
  return trustedClient ? ({ identity: did } as AuthenticatedRequest) : null;
}

/**
 * REQ-10-13: the same brand as authenticateRequest's, for a caller
 * that already verified identity through a DIFFERENT channel this
 * module has no business re-checking -- an OIDC access token's own
 * `sub`, already verified by verifyAccessToken before this is ever
 * called. Exists so that path can call signAs too, instead of
 * bypassing the brand with an inline cast the type system can't tell
 * apart from a genuine mistake.
 */
export function authenticatedViaAccessToken(identity: Did): AuthenticatedRequest {
  return { identity } as AuthenticatedRequest;
}

/**
 * REQ-10-13: creates a proof with a held key only for the identity
 * `auth` was actually checked against -- `auth.identity` can only have
 * come from authenticateRequest, never a caller's own say-so.
 */
export async function signAs(env: Env, auth: AuthenticatedRequest, did: Did, op: object): Promise<DataIntegrityProof> {
  if (auth.identity !== did) throw new RegistrarError("REQ-10-13: a held key signs only on a request authenticated as that identity");
  const held = await getHeldKey(env, did);
  if (!held) throw new RegistrarError("this registrar does not hold a key for this identity");
  return proofFromHeldKey(env, held, op);
}

async function proofFromHeldKey(env: Env, held: HeldKeyRow, op: object): Promise<DataIntegrityProof> {
  const privateKey = await decryptSecret(held.private_key_enc, env.KEY_ENCRYPTION_KEY);
  return createProof(op, held.public_key as Key, privateKey);
}

/**
 * REQ-10-9: the registrar's own attestation over a `create`, using a key
 * of its root identity and the current version of the root identity's
 * log. The root identity's own create never gets one (REQ-7-7) -- never
 * called for it.
 */
export async function signAttestation(env: Env, candidate: CreateOp): Promise<DataIntegrityProof> {
  const rootDid = didFor(null, env.REGISTRAR_DOMAIN) as Did;
  const rootHeld = await getHeldKey(env, rootDid);
  if (!rootHeld) throw new Error("this registrar does not hold its own root key");

  const rootLog = await getLog(env, rootDid);
  if (rootLog.length === 0) throw new RegistrarError("REQ-10-10: this registrar's root identity does not exist yet");
  const verified = await verifyLog(rootDid, rootLog);
  if (verified.result !== "valid") throw new Error("this registrar's own root log does not verify");
  const index = verified.state!.keys.indexOf(rootHeld.public_key as Key);
  if (index === -1) throw new Error("this registrar's held root key is not in its own root state");

  const version = await operationHash(rootLog[rootLog.length - 1]);
  const privateKey = await decryptSecret(rootHeld.private_key_enc, env.KEY_ENCRYPTION_KEY);
  return createAttestation(candidate, rootDid, version, index, privateKey);
}
