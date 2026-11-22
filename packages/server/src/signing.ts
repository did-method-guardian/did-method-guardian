// REQ-10-13/REQ-10-14: this registrar signs with a held key only on an
// authenticated request from that identity, and never produces proofs for
// more than one identity in one request apart from the attestation.
import { createAttestation, createProof, operationHash, verifyLog, type CreateOp, type DataIntegrityProof, type Did, type Key } from "@did-guardian/lib";
import { getHeldKey, getLog, type HeldKeyRow } from "./db.js";
import { decryptSecret } from "./secretBox.js";
import { didFor, type Env } from "./env.js";
import { RegistrarError } from "./registrarError.js";

/**
 * REQ-10-13: creates a proof with a held key only for the identity a
 * request is authenticated as. `authenticatedIdentity` is the caller's
 * own verified identity (from the session or bearer token) -- never the
 * request body's own claims about who it's signing for.
 */
export async function signAs(env: Env, authenticatedIdentity: Did, did: Did, op: object): Promise<DataIntegrityProof> {
  if (authenticatedIdentity !== did) throw new RegistrarError("REQ-10-13: a held key signs only on a request authenticated as that identity");
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
