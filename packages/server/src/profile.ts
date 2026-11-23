// The registrar profile's own identity-lifecycle operations (handoff
// #9): thin wrappers that build one of the method's 9 operations, sign
// it with whatever held keys this registrar has, and submit it through
// registrar.ts's one acceptance path. Nothing here re-implements any
// part of REQ-10-5/10-7 -- that's checkAcceptance's job alone.
import {
  anchorOf,
  checkMutuality,
  createProof,
  generateKeypair,
  isValidName,
  operationHash,
  sortProofs,
  verifyLog,
  type AcceptWardOp,
  type AddGuardianOp,
  type CreateOp,
  type DataIntegrityProof,
  type DeactivateOp,
  type Did,
  type Entry,
  type Key,
  type RemoveGuardianOp,
  type UpdateOp,
} from "@did-guardian/lib";
import { getHeldKey, getLog, insertHeldKey, replaceHeldKey, deleteHeldKey, setHeldKeyLoginSecretHash, type HeldKeyRow } from "./db.js";
import { didForSegment, submitOperation } from "./registrar.js";
import { makeResolveLog } from "./logResolver.js";
import { signAs, type AuthenticatedRequest } from "./signing.js";
import { RegistrarError } from "./registrarError.js";
import { encryptSecret, hashPassword, randomSecret } from "./secretBox.js";
import { proposeOperation, contributeProof, getPendingOperationStatus } from "./pendingProofs.js";
import type { Env } from "./env.js";

/**
 * REQ-7-1: creates a named identity. `heldKey` true (the common case:
 * /register, the admin console) means this registrar generates and
 * holds the key; false means the caller already supplied one (a
 * self-custodied identity from birth) and this function only builds and
 * submits the operation -- it never asks the caller for their private
 * key, which never exists here. No initial guardian: an identity picks
 * up its first guardian afterward, through the addGuardian/acceptWard
 * flow (proposeAdopt/confirmAdopt, below) -- a guardian's own
 * cooperation (REQ-7-6: every key in a `create`'s own `guardians` must
 * co-sign) can't be assumed at registration time.
 */
export async function registerIdentity(env: Env, name: string, options: { publicKey?: Key; password?: string }): Promise<{ did: Did; loginSecret?: string }> {
  if (!isValidName(name)) throw new RegistrarError(`invalid name "${name}" -- must be 3-32 lowercase alphanumeric/hyphen characters, no leading/trailing/double hyphens`, 400);
  const did = didForSegment(env, name);
  const keypair = options.publicKey ? undefined : await generateKeypair();
  const publicKey = options.publicKey ?? (keypair!.publicKey as Key);

  const createOp: Omit<CreateOp, "proof" | "attestation"> = {
    type: "create",
    did,
    keys: [publicKey],
    guardians: [],
    successor: null,
    policy: {},
    services: [],
    alsoKnownAs: [],
    prev: null,
  };

  if (keypair) {
    const proof = await createProof(createOp, publicKey, keypair.privateKey);
    const accepted = (await submitOperation(env, did, { ...createOp, proof: [proof] } as CreateOp)).operation as CreateOp;
    const now = new Date().toISOString();
    let loginSecret: string | undefined;
    let loginSecretHash: string | null = null;
    if (options.password) {
      loginSecretHash = await hashPassword(options.password);
    } else {
      loginSecret = randomSecret();
      loginSecretHash = await hashPassword(loginSecret);
    }
    await insertHeldKey(env, {
      did,
      public_key: publicKey,
      private_key_enc: await encryptSecret(keypair.privateKey, env.KEY_ENCRYPTION_KEY),
      login_secret_hash: loginSecretHash,
      created_at: now,
    });
    void accepted;
    return { did, loginSecret };
  }

  // Self-custodied from birth: the caller must have already produced a
  // proof with their own key before this is ever called -- see the
  // caller's own route for how `op` (with `proof` attached) reaches here
  // instead of this function building one. This branch only exists to
  // document the split; routes needing it call submitOperation directly.
  throw new RegistrarError("a self-supplied key must submit its own signed create operation directly", 400);
}

/** REQ-10-13: generates a fresh login secret for a held identity, or sets an operator-chosen password -- never a new operation, since the login secret is this registrar's own bookkeeping, not part of the DID's own state. */
export async function reissueLoginSecret(env: Env, did: Did, password?: string): Promise<string | undefined> {
  const held = await getHeldKey(env, did);
  if (!held) throw new RegistrarError("this registrar does not hold a key for this identity", 404);
  if (password) {
    await setHeldKeyLoginSecretHash(env, did, await hashPassword(password));
    return undefined;
  }
  const secret = randomSecret();
  await setHeldKeyLoginSecretHash(env, did, await hashPassword(secret));
  return secret;
}

async function currentServicesAndAkas(env: Env, did: Did): Promise<{ services: UpdateOp["services"]; alsoKnownAs: string[]; prev: string }> {
  const log = await getLog(env, did);
  if (log.length === 0) throw new RegistrarError("this identity has no log yet", 404);
  const verified = await verifyLog(did, log);
  if (verified.result !== "valid") throw new RegistrarError("this identity's own log does not verify", 500);
  const { operationHash } = await import("@did-guardian/lib");
  return { services: verified.state!.services, alsoKnownAs: verified.state!.alsoKnownAs, prev: await operationHash(log[log.length - 1]) };
}

async function currentPrev(env: Env, did: Did): Promise<string> {
  const log = await getLog(env, did);
  if (log.length === 0) throw new RegistrarError("this identity has no log yet", 404);
  return operationHash(log[log.length - 1]);
}

/**
 * Rotates a held identity to a freshly generated key -- an `update`
 * whose two required approvals (every key in the new `keys`, and one
 * current key) this registrar can both produce itself, since it holds
 * the old key and is about to hold the new one.
 */
export async function rotateHeldKey(env: Env, auth: AuthenticatedRequest, did: Did): Promise<void> {
  const held = await getHeldKey(env, did);
  if (!held) throw new RegistrarError("this registrar does not hold a key for this identity", 404);
  const { services, alsoKnownAs, prev } = await currentServicesAndAkas(env, did);

  const newKeypair = await generateKeypair();
  const base: Omit<UpdateOp, "proof"> = { type: "update", keys: [newKeypair.publicKey as Key], services, alsoKnownAs, prev };
  const newKeyProof = await createProof(base, newKeypair.publicKey as Key, newKeypair.privateKey);
  const oldKeyProof = await signAs(env, auth, did, base);
  const op: UpdateOp = { ...base, proof: sortProofs([newKeyProof, oldKeyProof]) };

  await submitOperation(env, did, op);
  await replaceHeldKey(env, did, newKeypair.publicKey, await encryptSecret(newKeypair.privateKey, env.KEY_ENCRYPTION_KEY));
}

/**
 * Take-custody: the caller already signed an `update` naming their own
 * supplied key with that same key (proof of possession); this registrar
 * adds the other required approval (one current key, its own held key)
 * and, once accepted, forgets the key it held for this identity for
 * good (REQ-10-13: it can never produce a proof for this identity again).
 */
export async function takeCustody(env: Env, auth: AuthenticatedRequest, did: Did, callerProvidedOp: Omit<UpdateOp, "proof">, callerProof: DataIntegrityProof): Promise<void> {
  const held = await getHeldKey(env, did);
  if (!held) throw new RegistrarError("this registrar does not hold a key for this identity", 404);
  const oldKeyProof = await signAs(env, auth, did, callerProvidedOp);
  const op: UpdateOp = { ...callerProvidedOp, proof: sortProofs([callerProof, oldKeyProof]) };
  await submitOperation(env, did, op);
  await deleteHeldKey(env, did);
}

/**
 * A held identity deactivating itself. REQ-7-6: if it has no guardians
 * (N=0), one current key suffices and this registrar can do the whole
 * thing itself; otherwise `policy.deactivation.by` may require guardian
 * cooperation too, which this single-request path can't produce --
 * submitOperation's own rejection reason surfaces that case as-is, and
 * the caller falls back to the multi-signer proposal flow
 * (pendingProofs.ts) instead.
 */
export async function deactivateSelf(env: Env, auth: AuthenticatedRequest, did: Did): Promise<void> {
  const prev = await currentPrev(env, did);
  const base: Omit<DeactivateOp, "proof"> = { type: "deactivate", prev };
  const proof = await signAs(env, auth, did, base);
  await submitOperation(env, did, { ...base, proof: [proof] });
}

/** A guardian resigning itself from `wardDid`'s own guardians -- REQ-7-6's "the removed guardian itself, if N >= 2" path, a single signature from the guardian's own held key. */
export async function removeGuardianSelf(env: Env, auth: AuthenticatedRequest, wardDid: Did, guardianDid: Did): Promise<void> {
  const prev = await currentPrev(env, wardDid);
  const base: Omit<RemoveGuardianOp, "proof"> = { type: "removeGuardian", guardian: guardianDid, prev };
  const proof = await signAs(env, auth, guardianDid, base);
  await submitOperation(env, wardDid, { ...base, proof: [proof] });
}

/**
 * The ward itself removing a guardian with `evidence` -- REQ-7-6's "one
 * current key, if evidence is present" path: the ward's own held key,
 * alone, naming a deactivate or a releaseWard on the guardian's own log
 * as evidence (REQ-10-7's own cross-log check does the rest).
 */
export async function removeGuardianWithEvidence(env: Env, auth: AuthenticatedRequest, wardDid: Did, guardianDid: Did, evidence: string): Promise<void> {
  const prev = await currentPrev(env, wardDid);
  const base: Omit<RemoveGuardianOp, "proof"> = { type: "removeGuardian", guardian: guardianDid, evidence, prev };
  const proof = await signAs(env, auth, wardDid, base);
  await submitOperation(env, wardDid, { ...base, proof: [proof] });
}

/**
 * Step 1 of adopt (handoff #9): `guardianDid`, authenticated as itself,
 * accepts `wardDid` into its own log (REQ-7-22), then immediately drafts
 * the matching `addGuardian` on the ward's own log and adds its own
 * required proof to it (REQ-7-6: "every key in `entry`") -- the ward
 * still has to add the other required approval (one current key) itself,
 * in a second, separate request (confirmAdopt), authenticated as the
 * ward.
 */
export async function proposeAdopt(env: Env, auth: AuthenticatedRequest, guardianDid: Did, wardDid: Did): Promise<{ pendingId: string }> {
  const wardLog = await getLog(env, wardDid);
  if (wardLog.length === 0) throw new RegistrarError("no such identity", 404);
  const wardAnchor = await anchorOf(wardLog[0] as CreateOp);

  const acceptBase: Omit<AcceptWardOp, "proof"> = { type: "acceptWard", ward: { did: wardDid, anchor: wardAnchor }, prev: await currentPrev(env, guardianDid) };
  const acceptProof = await signAs(env, auth, guardianDid, acceptBase);
  const acceptOp = (await submitOperation(env, guardianDid, { ...acceptBase, proof: [acceptProof] })).operation as AcceptWardOp;
  const consentHash = await operationHash(acceptOp);

  const guardianLog = await getLog(env, guardianDid);
  const guardianVerified = await verifyLog(guardianDid, guardianLog);
  const guardianAnchor = await anchorOf(guardianLog[0] as CreateOp);
  const entry: Entry = { did: guardianDid, anchor: guardianAnchor, keys: guardianVerified.state!.keys, consent: consentHash };

  const addGuardianBase: Omit<AddGuardianOp, "proof"> = { type: "addGuardian", entry, prev: await currentPrev(env, wardDid) };
  const guardianProofOnAddGuardian = await signAs(env, auth, guardianDid, addGuardianBase);

  const outcome = await proposeOperation(env, wardDid, addGuardianBase, guardianProofOnAddGuardian);
  if (outcome.status === "finalized") throw new Error("addGuardian requires the ward's own approval too; it cannot finalize from the guardian's proof alone");
  return { pendingId: outcome.id };
}

/**
 * Step 2 of adopt: the ward, authenticated as itself, adds the other
 * required approval (one current key) to the pending `addGuardian` and
 * finalizes it.
 *
 * F2 (confused deputy), corrected per thoward-59's review of a59e733:
 * `/propose` is unauthenticated, so a pending operation naming this
 * ward as `did` could be anything an attacker built. But REQ-10-7's own
 * standing check (hasStanding, accept.ts, itself built on
 * checkMutuality) ALREADY refuses a fabricated entry at acceptance --
 * `entry.consent` being well-shaped (REQ-6-2) but not a genuine
 * acceptWard is caught there regardless of what's signed here. The
 * checkMutuality call below is therefore redundant with that, kept
 * only for a clearer, earlier rejection reason than contributeProof's
 * generic one.
 *
 * The real remaining risk: `acceptWard` is one-sided (spec's "One-sided
 * records") -- anyone can genuinely accept this ward without its
 * cooperation, then propose themselves as its guardian through the
 * ordinary /adopt flow. That consent is completely genuine, so
 * checkMutuality reports "mutual" correctly. The only thing standing
 * between that and a real, unwanted guardian is the ward actually
 * recognizing which guardian it's about to confirm -- so this requires
 * `expectedDigest` to match the pending op's own content hash (the
 * same binding sign-as-self uses), and the caller (CLI or any other
 * client) is responsible for having shown the ward exactly who --
 * `entry.did`, with its domain -- this would add before asking for
 * that digest back.
 */
export async function confirmAdopt(env: Env, auth: AuthenticatedRequest, wardDid: Did, pendingId: string, expectedDigest: string): Promise<{ accepted: boolean; reason?: string }> {
  const pending = await getPendingOperationStatus(env, pendingId);
  if (pending.did !== wardDid) throw new RegistrarError("no such pending operation for this identity", 404);
  if (expectedDigest !== pending.digest) {
    throw new RegistrarError("this confirmation doesn't match the pending operation's current content -- fetch it again and confirm the guardian it actually names", 400);
  }

  const op = pending.operation as { type?: string; entry?: Entry };
  if (op.type !== "addGuardian" || !op.entry) {
    throw new RegistrarError("this pending operation is not a guardian request -- confirm-adopt only ever signs an addGuardian", 400);
  }
  const wardLog = await getLog(env, wardDid);
  const wardAnchor = await anchorOf(wardLog[0] as CreateOp);
  const mutuality = await checkMutuality(wardDid, wardAnchor, op.entry, makeResolveLog(env));
  if (mutuality !== "mutual") {
    throw new RegistrarError(`this guardian request isn't a genuine, current guardian relationship (${mutuality}) -- refusing to sign it`, 400);
  }

  const proof = await signAs(env, auth, wardDid, pending.operation);
  const outcome = await contributeProof(env, pendingId, proof);
  return outcome.status === "finalized" ? { accepted: true } : { accepted: false, reason: outcome.reason };
}

export type { HeldKeyRow };
