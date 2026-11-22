import {
  generateKeypair,
  unsecuredDocument,
  createProof,
  checkGenesisShape,
  verifyCustodialCreate,
  signCustodialCreate,
  signCustodialRotate,
  signGuardianAdd,
  signGuardianRemove,
  signGuardianRelinquish,
  signCustodialTombstone,
  signRegistrarAttestation,
  signReceipt,
  cidFor,
  replay,
  checkNullification,
  toDidDocument,
  liveGuardians,
  verifyByRules,
  isValidName,
  meetsThreshold,
  parseDid,
  wellKnownPath,
  DEFAULT_GUARDIAN_POLICY,
  signLogHeadStatement,
  logHashFor,
} from "@did-guardian/lib";
import type { CustodialCreateOp, DataIntegrityProof, Did, GuardianLivenessResolver, LogEntry, LogHeadStatement, Operation, ResolvedState, VerificationContext } from "@did-guardian/lib";
import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { appendOperation, appendOperationIfCountMatches, getOperationLog, getWardByDid, getWardByName, getWardCustodyMode, insertWard, insertWardCustody, setLoginSecretHash, takeCustodyOfWardKey, updateWardKeys, type WardRow } from "./db.js";
import { encryptSecret, decryptSecret, hashSecret, hashPassword, randomSecret } from "./secretBox.js";
import { proposeOperation } from "./pendingOps.js";

export class RegistrarError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

/**
 * WS-1.12 (audit): `wards.name`/`wards.did` are each UNIQUE (name is
 * even the PRIMARY KEY), so D1/SQLite itself already makes two
 * concurrent inserts for the same name atomic -- at most one can ever
 * succeed. What wasn't handled is the LOSER: both acceptGenesis and
 * getOrCreateRootWard previously checked "does this name already exist"
 * well before actually inserting, a classic check-then-act gap a
 * concurrent request can land in. Without this, the loser's insert threw
 * an unhandled D1 error (a 500, not the clean 409 the pre-check was
 * supposed to guarantee) instead of being recognized as exactly the race
 * the pre-check exists to catch.
 */
function isUniqueConstraintError(e: unknown): boolean {
  return e instanceof Error && /UNIQUE constraint failed/i.test(e.message);
}

/** REQ-2-1, via the single source of truth in @did-guardian/lib -- registrar.ts previously had its own copy that let a double-hyphen and even a single-character name through. */
export function assertValidName(name: string): void {
  if (!isValidName(name)) {
    throw new RegistrarError(`invalid name "${name}" -- must be 3-32 lowercase alphanumeric/hyphen characters, no leading/trailing/double hyphens`, 400);
  }
}

// Length alone -- no forced uppercase/digit/symbol complexity rules, the
// modern (NIST-aligned) guidance that length is the effective, least
// annoying constraint and composition rules mostly just push people toward
// predictable substitutions.
const MIN_PASSWORD_LENGTH = 12;

export function assertValidPassword(password: string): void {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new RegistrarError(`password must be at least ${MIN_PASSWORD_LENGTH} characters`, 400);
  }
}

/**
 * v0.3, REQ-8-2: genesis submission is part of the method now, not a
 * registerWard-only special case -- a client that built and self-signed
 * a `custodial_create` (keySigs already attached, REQ-7.1-8) gets
 * accepted here exactly like registerWard's server-generated one does,
 * through this one shared path. The op arriving here carries no
 * `registrar` attestation yet (adding it is this function's job, same
 * as it always was); everything else about it -- `name`, keys, keySigs,
 * `creator`, `policy` -- is already fixed and signed by the time it
 * gets here, so nothing below may touch any of that content once
 * computed, only check it.
 *
 * `incoming` MAY be non-empty now (REQ-7.1-1, relaxed v0.3) -- a genesis
 * establishing a guardian directly, as long as every named guardian
 * co-signs (checkGenesisShape checks a slot exists; verifyCustodialCreate
 * below, once this registrar's attestation is attached, checks those
 * signatures are actually valid). REQ-7.1-6 is name validity plus
 * availability, checked here independently of whatever a caller already
 * checked, since this is reachable directly from an external submission
 * with nothing upstream guaranteeing either.
 */
export async function acceptGenesis(
  env: Env,
  name: string,
  op: CustodialCreateOp,
  // registerWard's use only: this registrar generated operationalKeys[0]
  // and will go on custodying it, so the ward row stores its real
  // encrypted private key and no ward_custody row at all (registrar
  // custody is the no-row default) -- never set by an external submission,
  // which is always self-held by construction (nothing else custodies a
  // key it was never given).
  serverPrivateKeyEnc?: string,
): Promise<{ accepted: true; did: string; cid: string; document: unknown } | { accepted: false; reason: string }> {
  if (op.name !== name) return { accepted: false, reason: `operation names "${op.name}", but was submitted to "${name}"` };
  if (!isValidName(name)) return { accepted: false, reason: `invalid name "${name}" -- must be 3-32 lowercase alphanumeric/hyphen characters, no leading/trailing/double hyphens (REQ-7.1-6)` };
  if (await getWardByName(env, name)) return { accepted: false, reason: `name "${name}" is already taken (REQ-7.1-6)` };

  const did = didFor(name, env.REGISTRAR_DOMAIN);
  // Fix 2: without this, a genesis already publicly accepted elsewhere
  // (its name, keys, keySigs-equivalent proofs, and any guardian
  // consents, all still verifying -- none of it binds to a domain) could
  // be replayed verbatim here under the same free name, becoming a
  // second, distinct identity nobody who signed the original ever
  // intended -- worse still if it named a guardian directly (REQ-7.1-1),
  // since that guardian never consented to guarding THIS identity.
  if (op.did !== did) return { accepted: false, reason: `operation's did "${op.did}" does not match "${did}" (Fix 2) -- this looks like a genesis built for a different registrar, replayed here` };
  if (op.incoming.includes(did)) return { accepted: false, reason: `${did} can't be named as a guardian of itself (REQ-7.1-9)` };

  const shape = checkGenesisShape(op);
  if (!shape.valid) return { accepted: false, reason: shape.reason ?? "invalid genesis shape" };

  // WS-1.14 (audit): one timestamp for both the attestation's own `created`
  // and the stored `createdAt` -- previously two separate `new Date()`
  // calls a couple of lines apart, so they drifted by 1-2ms. For genesis,
  // this attestation IS the acceptance receipt (WS-4.1) -- no second proof
  // needed, unlike every other operation type, which gets one appended
  // below in submitOperation.
  const acceptedAt = new Date().toISOString();
  const rootWard = await getOrCreateRootWard(env);
  const rootPrivateKey = await decryptWardPrivateKey(env, rootWard);
  const attestation = await signRegistrarAttestation(op, rootWard.did, rootPrivateKey, acceptedAt);
  const genesis = { ...op, proof: [...op.proof, attestation] };

  // Everything cryptographic -- proof of possession (REQ-7.1-8), every
  // incoming guardian's signature, and (now that it's attached) this
  // registrar's attestation -- checked in one call, through the
  // same function the interop suite and every other verifier use. A
  // local guardian resolves synchronously; a foreign one is fetched
  // live from its registrar (makeExternalResolver, below), same as any
  // other cross-registrar signature this registrar ever checks.
  const verified = await verifyCustodialCreate(genesis, makeExternalResolver(env), rootWard.did as Did);
  if (!verified.valid) return { accepted: false, reason: verified.reason ?? "genesis verification failed" };

  const cid = await cidFor(genesis);
  const createdAt = acceptedAt;

  // WS-1.12 (audit): the "already taken" check above read the table
  // before this verification work ran -- a concurrent request for the
  // SAME name could easily have inserted its own row in between. The
  // wards table's own PRIMARY KEY makes the actual insert atomic either
  // way; this only turns the loser's D1 error into the same clean
  // rejection the earlier check was already supposed to produce.
  try {
    await insertWard(env, { name, did, public_key: op.operationalKeys[0], private_key_enc: serverPrivateKeyEnc ?? "", created_at: createdAt, login_secret_hash: null });
  } catch (e) {
    if (isUniqueConstraintError(e)) return { accepted: false, reason: `name "${name}" is already taken (REQ-7.1-6)` };
    throw e;
  }
  if (!serverPrivateKeyEnc) await insertWardCustody(env, did, "self", createdAt);
  await appendOperation(env, { cid, did, prev_cid: null, op_type: genesis.type, payload: JSON.stringify(genesis), created_at: createdAt });

  const state = replay(did as Did, [{ cid, op: genesis }]);
  return { accepted: true, did, cid, document: toDidDocument(state) };
}

/**
 * Registers a brand-new, server-custodied identity -- this registrar
 * generates the key, signs proof of possession (REQ-7.1-8) with
 * it, and submits the result through `acceptGenesis` above, the exact
 * same acceptance path a client-built, self-held genesis goes through.
 * One creation path, two kinds of callers.
 *
 * `guardianDid`, when given, establishes a real first guardian via a
 * genuine, separately-signed `guardian_add` (REQ-7.2-5, zero-to-one) --
 * two log entries, one API call, not genesis itself carrying a guardian
 * directly. Two different outcomes, gated on `callerDid` (WS-1.11,
 * audit) rather than merely on where the guardian's key happens to
 * live:
 * - **`guardianDid === callerDid`** (the caller is naming itself):
 *   whoever is making this call has already, by making it, consented to
 *   becoming this new ward's guardian -- the Managed Identity API path
 *   (registrar API spec §9) derives `guardianDid` FROM a validated
 *   access token's own `sub`, the real end user who consented on a real
 *   OAuth screen (scope=create:managed-identity), so it's always equal
 *   to `callerDid` there; the admin console path (adminPage.ts) passes
 *   its own root session's DID as `callerDid`, so this only fires when
 *   an operator names THEMSELVES, matching that form's own "e.g. your
 *   own, to oversee this account" hint. When this holds AND that key is
 *   registrar-held, both required signatures are producible server-
 *   side, so this finishes synchronously, with no interactive signing
 *   round trip needed.
 * - **Anything else** -- a different registrar-held ward (what WS-1.11
 *   closed: an admin naming some OTHER account it merely happens to
 *   custody is not that other account's own consent, no matter whose
 *   form field the DID came from) or a genuinely foreign/self-held key
 *   this registrar never had a signature for in the first place --
 *   the `guardian_add` is proposed instead, signed only with the new
 *   ward's own key, left pending the guardian's own signature via the
 *   same async collection (§3) any other guardian relationship goes
 *   through. The response's own `pending_guardian_add.id` names it; the
 *   identity exists and is usable immediately, just guardian-less until
 *   that signature actually lands.
 *
 * Either way, genesis itself has already succeeded by the time
 * guardian_add is attempted -- the ward exists, ownerless, rather than
 * half-created; a same-registrar failure gets a clear error naming just
 * that failure, never rolling genesis back.
 */
/**
 * WS-1.11 (audit): true exactly when the caller is naming itself as the
 * new ward's guardian -- the one case where the auto-sign, same-call
 * convenience is actually that caller's own consent, not someone else's
 * signed on their behalf. Isolated as its own function (rather than an
 * inline comparison inside registerWard) so this specific condition --
 * the entire fix -- can't later be loosened by an edit that doesn't
 * realize what it's guarding.
 */
export function callerMayAutoSignAsGuardian(guardianDid: string, callerDid: string | null | undefined): boolean {
  return guardianDid === callerDid;
}

export async function registerWard(
  env: Env,
  name: string,
  guardianDid?: string | null,
  password?: string,
  callerDid?: string | null,
): Promise<{ did: string; document: unknown; login_secret?: string; pending_guardian_add?: { id: string } }> {
  assertValidName(name);
  if (password) assertValidPassword(password);
  if (await getWardByName(env, name)) {
    throw new RegistrarError(`name "${name}" is already taken`, 409);
  }

  const did = didFor(name, env.REGISTRAR_DOMAIN);
  const keypair = await generateKeypair();
  const rootWard = await getOrCreateRootWard(env);

  const genesisPartial = {
    type: "custodial_create" as const,
    did,
    name,
    operationalKeys: [keypair.publicKey],
    services: {},
    outgoing: [] as [],
    incoming: [] as Did[],
    prev: null,
    creator: rootWard.did,
  };
  const genesis = await signCustodialCreate(genesisPartial, {}, { [keypair.publicKey]: keypair.privateKey });
  const privateKeyEnc = await encryptSecret(keypair.privateKey, env.KEY_ENCRYPTION_KEY);
  const accepted = await acceptGenesis(env, name, genesis, privateKeyEnc);
  // WS-1.13 (audit): acceptGenesis's own rejections (name taken, bad
  // shape, failed verification) are all caller-caused, same convention
  // as every other submitOperation/acceptGenesis result this file maps
  // to a response -- this was the one site still using 500.
  if (!accepted.accepted) throw new RegistrarError(`registration failed: ${accepted.reason}`, 400);
  const { cid } = accepted;

  // The login secret proves control of this ward to THIS registrar's own
  // login/OIDC flow -- a separate credential from the operational key,
  // needed because the custodial model here means the key itself isn't
  // provable client-side (the server holds it, not the caller). A
  // generated one is returned once, in plaintext, here only -- stored
  // hashed. A user-chosen password is never returned here at all (the
  // caller already knows it); see secretBox.ts's hashPassword for why it
  // needs real key stretching that a generated secret doesn't.
  const loginSecret = password ? undefined : randomSecret();
  const loginSecretHash = password ? await hashPassword(password) : await hashSecret(loginSecret!);
  await setLoginSecretHash(env, name, loginSecretHash);

  let pendingGuardianAdd: { id: string } | undefined;
  if (guardianDid) {
    const guardianWard = await getWardByDid(env, guardianDid);
    if (callerMayAutoSignAsGuardian(guardianDid, callerDid) && guardianWard && (await getWardCustodyMode(env, guardianWard.did)) === "registrar") {
      // Same registrar, both keys producible server-side, AND the
      // caller is naming itself (WS-1.11) -- the one-call convenience
      // this was originally built for.
      const guardianPrivateKey = await decryptWardPrivateKey(env, guardianWard);
      const addOp = await signGuardianAdd(
        { type: "guardian_add", incoming: guardianDid, prev: cid, anchor: await genesisAnchor(env, guardianDid) },
        { [guardianDid]: guardianPrivateKey, [did]: keypair.privateKey }, // REQ-7.2-5: zero-to-one needs both the incoming guardian's key and the ward's operational key
        [guardianDid, did],
      );
      const result = await submitOperation(env, name, addOp);
      if (!result.accepted) {
        // WS-1.13 (audit): same convention as every other submitOperation
        // result mapped to a response -- 400, not 500.
        throw new RegistrarError(`"${name}" was created, but establishing "${guardianDid}" as its guardian failed: ${result.reason}`, 400);
      }
    } else {
      // A foreign guardian (this registrar never holds a key it doesn't
      // custody), a same-registrar guardian who's taken custody of their
      // own key, or -- WS-1.11 -- a same-registrar, still-custodied
      // guardian the CALLER isn't itself: in every one of these cases
      // there's either no signature to produce here, or producing one
      // would mean signing on behalf of a party who never actually
      // consented to this specific guardianship through this specific
      // call. Propose the guardian_add with only the ward's own
      // signature attached instead, same async collection every other
      // guardian relationship already uses (§3) -- the named guardian
      // signs it themselves, whenever they do, under their own session.
      const addOp = await signGuardianAdd({ type: "guardian_add", incoming: guardianDid, prev: cid }, { [did]: keypair.privateKey }, [did]);
      const proposeResult = await proposeOperation(env, name, addOp);
      pendingGuardianAdd = { id: proposeResult.id };
    }
  }

  const log = await loadLog(env, did);
  const state = replay(did as Did, log);
  return { did, document: toDidDocument(state), login_secret: loginSecret, pending_guardian_add: pendingGuardianAdd };
}

/**
 * Replaces a ward's login secret -- the one real recovery path for "I
 * never saved it" or "I think it leaked," since there's no way to recover
 * the original (only its hash is ever stored). The old secret stops
 * working the instant this runs: nothing here keeps the previous hash
 * around or allows more than one valid secret at a time, same as a
 * password reset invalidating the old password. Callers (index.ts,
 * accountPage.ts) already gate who may call this at all -- either an
 * active session as this exact ward, or a trusted relying party acting on
 * an already-authenticated session of its own.
 *
 * `password`, when given, replaces the "freshly generated" default with
 * this ward's own chosen one -- the same choice registerWard offers at
 * creation time, available again any time after.
 */
export async function reissueLoginSecret(env: Env, name: string, password?: string): Promise<string | undefined> {
  if (password) {
    assertValidPassword(password);
    await setLoginSecretHash(env, name, await hashPassword(password));
    return undefined;
  }
  const loginSecret = randomSecret();
  await setLoginSecretHash(env, name, await hashSecret(loginSecret));
  return loginSecret;
}

/**
 * A ward's own self-service operational-key rotation (spec §4.2,
 * custodial_rotate). The real reason this needs to be a registrar
 * capability rather than something a caller does by submitting an
 * already-signed op directly (POST .../operations, above): for a
 * custodial ward (every one this registrar hosts, human or managed
 * agent -- the whole point of "custodial"), nobody outside this
 * registrar ever holds the current operational private key to sign a
 * rotation with in the first place. It's decrypted here for the one
 * moment it takes to sign the new operation, never returned to any
 * caller.
 *
 * Builds and self-signs a custodial_rotate op with a freshly generated
 * keypair, then appends it through the exact same verify-then-append
 * path an externally-submitted operation goes through (submitOperation,
 * below) -- no separate, parallel trust path for this one operation
 * type, even though this registrar could technically skip verification
 * since it produced both the old and new key material itself. Only on
 * that succeeding does the ward's own stored key material actually
 * move to the new keypair -- if anything above fails, the ward is left
 * exactly as it was, never half-rotated.
 *
 * Callers (index.ts) gate who may call this at all -- either an active
 * session as this exact ward (self-rotation), or a trusted relying
 * party (zz's own backend, say) that has already decided the caller is
 * authorized to do this on behalf of a ward it manages. This function
 * performs the rotation unconditionally once called, same split as
 * reissueLoginSecret above.
 */
export async function rotateWard(env: Env, name: string): Promise<{ did: string; document: unknown }> {
  // `name === ""` (the bare-domain root identity's own sentinel) works
  // here exactly like any other ward -- getWardByName finds it directly,
  // and rotateWard's own call to updateWardKeys below means every future
  // registrar attestation (signRegistrarAttestation, used by registerWard)
  // correctly picks up the rotated key; a past attestation is never
  // re-verified against it (verifyCustodialCreate only ever runs once, at
  // submission time), so rotating this identity's key can't retroactively
  // invalidate anything already in any ward's own log. index.ts gates who
  // may call this at all, same as for any other ward.
  const ward = await getWardByName(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const log = await loadLog(env, ward.did);
  const latestCid = log[log.length - 1]?.cid;
  if (!latestCid) throw new RegistrarError(`"${name}" has no genesis operation to rotate from`, 500);
  const state = replay(ward.did as Did, log);

  const oldPrivateKey = await decryptWardPrivateKey(env, ward);
  const newKeypair = await generateKeypair();
  const op = await signCustodialRotate(
    {
      type: "custodial_rotate",
      operationalKeys: [newKeypair.publicKey],
      services: state.services,
      prev: latestCid,
    },
    ward.did as Did,
    oldPrivateKey,
    { [newKeypair.publicKey]: newKeypair.privateKey },
  );
  const result = await submitOperation(env, name, op);
  // WS-1.13 (audit): same convention as every other submitOperation
  // result mapped to a response -- 400, not 500.
  if (!result.accepted) throw new RegistrarError(`rotation failed: ${result.reason}`, 400);

  const newPrivateKeyEnc = await encryptSecret(newKeypair.privateKey, env.KEY_ENCRYPTION_KEY);
  await updateWardKeys(env, ward.did, newKeypair.publicKey, newPrivateKeyEnc);

  const document = await resolveDocument(env, name);
  return { did: ward.did, document };
}

/**
 * Self-destruct, not a transfer -- custodial_tombstone's own eligible
 * signers are "the ward's own operational key, or any current
 * guardian" (verifyCustodialTombstone), and DEFAULT_GUARDIAN_POLICY's
 * tombstone_threshold is "any" -- the lowest bar, by design (an
 * identity can always end itself). That means the ward's own
 * registrar-custodied key is *always* sufficient on its own, with no
 * guardian signature needed at all -- the same safe, self-contained
 * shape rotateWard already has (no new authority granted to anyone),
 * so the same trusted-client-or-self-session gate /rotate uses is
 * enough here too; nothing more to check at this layer.
 */
export async function tombstoneWard(env: Env, name: string): Promise<{ did: string; document: unknown }> {
  const ward = await getWardByName(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const log = await loadLog(env, ward.did);
  const latestCid = log[log.length - 1]?.cid;
  if (!latestCid) throw new RegistrarError(`"${name}" has no genesis operation to tombstone from`, 500);

  const ownKey = await decryptWardPrivateKey(env, ward);
  const op = await signCustodialTombstone({ type: "custodial_tombstone", prev: latestCid }, { [ward.did]: ownKey }, [ward.did]);
  const result = await submitOperation(env, name, op);
  // WS-1.13 (audit): same convention as every other submitOperation
  // result mapped to a response -- 400, not 500.
  if (!result.accepted) throw new RegistrarError(`tombstone failed: ${result.reason}`, 400);

  const document = await resolveDocument(env, name);
  return { did: ward.did, document };
}

/**
 * Full self-abdication (every current guardian relinquishes, leaving
 * the ward ownerless) -- deliberately NOT the general guardian_transfer
 * case (adding/swapping SOME guardians while keeping others), which
 * this registrar does not offer as a convenience endpoint: transfer
 * hands new authority to a party who never asked for it, and
 * requiredTransferSigners needs that incoming party's own consent too
 * -- a bare trusted-client credential alone can't legitimately produce
 * that signature even when this registrar custodies the incoming
 * DID's key, since holding a key isn't the same as that identity
 * having agreed to take on this specific new responsibility right
 * now. Relinquish has no such problem: every signer it needs is
 * already a CURRENT guardian voluntarily giving up its own standing,
 * the same self-contained shape as rotate/tombstone.
 *
 * Only signs with whichever of the ward's current guardians this
 * registrar itself custodies (a guardian hosted on a different
 * registrar entirely can't be signed for here, same limit
 * registerWard's own atomic-creation path already accepts for
 * `incoming`) -- refuses clearly if that subset doesn't meet the
 * ward's own removal_threshold, rather than silently doing nothing.
 */
export async function relinquishWard(env: Env, name: string): Promise<{ did: string; document: unknown }> {
  const ward = await getWardByName(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const log = await loadLog(env, ward.did);
  const latestCid = log[log.length - 1]?.cid;
  if (!latestCid) throw new RegistrarError(`"${name}" has no genesis operation to relinquish from`, 500);
  const state = replay(ward.did as Did, log);
  const live = await liveGuardians(state, makeGuardianLivenessResolver(env)); // REQ-4-4 -- a deactivated guardian never counts toward removal_threshold, nor is it worth attempting to sign for
  if (live.length === 0) throw new RegistrarError(`"${name}" has no guardians to relinquish -- it's already ownerless`, 400);

  const signerKeys: Record<string, string> = {};
  for (const guardianDid of live) {
    const guardianWard = await getWardByDid(env, guardianDid);
    if (guardianWard && (await getWardCustodyMode(env, guardianWard.did)) === "registrar") signerKeys[guardianDid] = await decryptWardPrivateKey(env, guardianWard);
  }
  const signers = Object.keys(signerKeys);
  if (!meetsThreshold(state.guardianPolicy.removal_threshold, signers, live)) {
    throw new RegistrarError(
      `not enough of "${name}"'s current guardians (${live.join(", ")}) are custodied by this registrar to meet its own removal_threshold -- a guardian on a different registrar has to relinquish through that registrar directly`,
      400,
    );
  }

  const op = await signGuardianRelinquish({ type: "guardian_relinquish", prev: latestCid }, signerKeys, signers);
  const result = await submitOperation(env, name, op);
  // WS-1.13 (audit): same convention as every other submitOperation
  // result mapped to a response -- 400, not 500.
  if (!result.accepted) throw new RegistrarError(`relinquish failed: ${result.reason}`, 400);

  const document = await resolveDocument(env, name);
  return { did: ward.did, document };
}

/**
 * A guardian voluntarily steps down from one ward's guardian set
 * (REQ-7.2-7a) -- self-contained because the only signer this needs is the
 * departing guardian's own key, which this registrar custodies exactly
 * when `callerDid` names one of its own wards. Unlike every other
 * convenience endpoint above, the "target identity" for auth purposes
 * (index.ts) is the CALLER (the departing guardian), never the `name` in
 * the URL (the ward being left) -- the ward's own session has no say in
 * whether one of its guardians steps down.
 */
export async function removeSelfAsGuardian(env: Env, name: string, callerDid: Did): Promise<{ did: string; document: unknown }> {
  const ward = await getWardByName(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const callerWard = await getWardByDid(env, callerDid);
  if (!callerWard) throw new RegistrarError(`"${callerDid}" is not a ward this registrar custodies -- it can't produce that guardian's signature`, 400);
  const log = await loadLog(env, ward.did);
  const latestCid = log[log.length - 1]?.cid;
  if (!latestCid) throw new RegistrarError(`"${name}" has no genesis operation to remove a guardian from`, 500);

  const callerPrivateKey = await decryptWardPrivateKey(env, callerWard);
  const op = await signGuardianRemove({ type: "guardian_remove", outgoing: callerDid, prev: latestCid }, { [callerDid]: callerPrivateKey }, [callerDid]);
  const result = await submitOperation(env, name, op);
  if (!result.accepted) throw new RegistrarError(`remove-self failed: ${result.reason}`, 400);

  const document = await resolveDocument(env, name);
  return { did: ward.did, document };
}

/**
 * Forced removal of a named guardian (REQ-7.2-7b) -- self-contained only
 * when the *other* current guardians (excluding `outgoingDid` itself) this
 * registrar can sign for, among themselves, already meet `removal_threshold`
 * evaluated against the full current guardian set (REQ-7.2-7's own
 * correction -- never the shrunken remaining-guardians pool). Same shape as
 * relinquishWard, just excluding one specific guardian from both the signer
 * pool and the eligible set computed for display.
 */
export async function forceRemoveGuardian(env: Env, name: string, outgoingDid: Did): Promise<{ did: string; document: unknown }> {
  const ward = await getWardByName(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const log = await loadLog(env, ward.did);
  const latestCid = log[log.length - 1]?.cid;
  if (!latestCid) throw new RegistrarError(`"${name}" has no genesis operation to remove a guardian from`, 500);
  const state = replay(ward.did as Did, log);
  const live = await liveGuardians(state, makeGuardianLivenessResolver(env));
  if (!live.includes(outgoingDid)) throw new RegistrarError(`"${outgoingDid}" is not a current guardian of "${name}"`, 400);

  const others = live.filter((d) => d !== outgoingDid);
  const signerKeys: Record<string, string> = {};
  for (const guardianDid of others) {
    const guardianWard = await getWardByDid(env, guardianDid);
    if (guardianWard && (await getWardCustodyMode(env, guardianWard.did)) === "registrar") signerKeys[guardianDid] = await decryptWardPrivateKey(env, guardianWard);
  }
  const signers = Object.keys(signerKeys);
  if (!meetsThreshold(state.guardianPolicy.removal_threshold, signers, live)) {
    throw new RegistrarError(
      `not enough of "${name}"'s OTHER current guardians are custodied by this registrar to meet its own removal_threshold against the full guardian set -- use the asynchronous collection endpoints instead`,
      400,
    );
  }

  const op = await signGuardianRemove({ type: "guardian_remove", outgoing: outgoingDid, prev: latestCid }, signerKeys, signers);
  const result = await submitOperation(env, name, op);
  if (!result.accepted) throw new RegistrarError(`forced removal failed: ${result.reason}`, 400);

  const document = await resolveDocument(env, name);
  return { did: ward.did, document };
}

/**
 * The zero-to-one `guardian_add` case (REQ-7.2-5) as a standalone
 * convenience, for a ward that's already guardian-less and wasn't adopted
 * at creation time -- self-contained because the only two required
 * signers are the incoming guardian's own key and the ward's own
 * operational key, both producible server-side when both are this
 * registrar's own wards. Rejected outright if the ward already has any
 * current guardian (that's an ordinary REQ-7.2-4 addition, needing the
 * EXISTING committee's own approval -- see §3).
 */
export async function adoptWard(env: Env, name: string, incomingDid: Did): Promise<{ did: string; document: unknown }> {
  const ward = await getWardByName(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const incomingWard = await getWardByDid(env, incomingDid);
  if (!incomingWard) throw new RegistrarError(`"${incomingDid}" is not a ward this registrar custodies -- it can't produce that guardian's signature`, 400);
  const log = await loadLog(env, ward.did);
  const latestCid = log[log.length - 1]?.cid;
  if (!latestCid) throw new RegistrarError(`"${name}" has no genesis operation to adopt from`, 500);
  const state = replay(ward.did as Did, log);
  const live = await liveGuardians(state, makeGuardianLivenessResolver(env));
  if (live.length > 0) throw new RegistrarError(`"${name}" already has a current guardian -- adding another needs the existing committee's own approval (see §3)`, 400);

  const incomingPrivateKey = await decryptWardPrivateKey(env, incomingWard);
  const wardPrivateKey = await decryptWardPrivateKey(env, ward);
  const op = await signGuardianAdd(
    { type: "guardian_add", incoming: incomingDid, prev: latestCid, anchor: await genesisAnchor(env, incomingDid) },
    { [incomingDid]: incomingPrivateKey, [ward.did]: wardPrivateKey },
    [incomingDid, ward.did],
  );
  const result = await submitOperation(env, name, op);
  if (!result.accepted) throw new RegistrarError(`adopt failed: ${result.reason}`, 400);

  const document = await resolveDocument(env, name);
  return { did: ward.did, document };
}

/**
 * A registrar-held ward rotates to a key it supplies, and this registrar
 * never keeps a usable copy -- `takeCustodyOfWardKey` overwrites
 * `private_key_enc` with a non-ciphertext sentinel, not a new one, and
 * records `custody_mode: "self"` in `ward_custody`. From then on this
 * registrar can sign nothing on this ward's behalf; every endpoint above
 * that would have (rotate, tombstone, relinquish, remove-self, adopt)
 * refuses through `decryptWardPrivateKey`'s check instead. Signing
 * this rotation is the ward's one remaining chance to use a key this
 * registrar still custodies, since after this call there won't be one.
 *
 * The root identity is excluded outright -- it has to keep producing a
 * registrar attestation for every new registration (registerWard above),
 * which only works with a key this registrar can read at request time.
 *
 * `force` bypasses the two warnings below, not the hard refusals (already
 * self-held, is root, or no genesis to rotate from) -- those stay errors
 * regardless, since there's nothing coherent to do about them here.
 *
 * `newKeyProof`, v0.4 (REQ-7.2-12): this registrar never holds the
 * private half of `publicKey` -- that's the entire point of this
 * endpoint -- so it can't produce the new key's proof-of-possession
 * proof the way `rotateWard`/`registerWard` do for a server-generated
 * key. The caller must construct this proof locally before calling
 * here, over the identical content this function independently
 * reconstructs below (same `operationalKeys`/`services`/`prev` shape
 * `signCustodialRotate` would build); a stale `prev` or wrong content
 * just fails `verifyByRules`'s proof-of-possession check the same way
 * any other invalid signature does, through `submitOperation`.
 */
export async function takeCustody(
  env: Env,
  name: string,
  publicKey: string,
  newKeyProof: DataIntegrityProof,
  force?: boolean,
): Promise<{ did: string; document: unknown; warnings: string[] }> {
  if (name === ROOT_WARD_NAME) {
    throw new RegistrarError("the bare-domain root identity can't take custody of its key -- it has to keep signing registrar attestations for every new registration on this deployment", 400);
  }
  const ward = await getWardByName(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  if ((await getWardCustodyMode(env, ward.did)) === "self") throw new RegistrarError(`"${name}" already holds its key -- there's nothing left here to take custody of`, 409);
  const log = await loadLog(env, ward.did);
  const latestCid = log[log.length - 1]?.cid;
  if (!latestCid) throw new RegistrarError(`"${name}" has no genesis operation to rotate from`, 500);
  const state = replay(ward.did as Did, log);

  const live = await liveGuardians(state, makeGuardianLivenessResolver(env));
  const warnings: string[] = [];
  if (live.length === 0) {
    warnings.push("this identity has no guardian. Losing the key you're about to hold would be unrecoverable, by anyone, ever.");
  }
  for (const guardianDid of live) {
    const guardianWard = await getWardByDid(env, guardianDid);
    if (guardianWard && (await getWardCustodyMode(env, guardianWard.did)) === "registrar" && meetsThreshold(state.guardianPolicy.recovery_threshold, [guardianDid], live)) {
      warnings.push(
        `this registrar custodies guardian "${guardianDid}"'s key, and that one guardian's signature alone satisfies this identity's recovery_threshold (${JSON.stringify(state.guardianPolicy.recovery_threshold)}). After taking custody, this registrar can no longer authorize operations as this identity directly, but it can still rotate this identity's key at any time by signing as that guardian instead (REQ-7.2-1b has no 72-hour restriction) -- taking custody here doesn't fully remove this registrar from this identity's trust model.`,
      );
    }
  }
  if (warnings.length > 0 && !force) {
    throw new RegistrarError(`refusing without force -- ${warnings.join(" ")}`, 409);
  }

  const oldPrivateKey = await decryptWardPrivateKey(env, ward);
  const partial = {
    type: "custodial_rotate" as const,
    operationalKeys: [publicKey],
    services: state.services,
    prev: latestCid,
  };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const authProof = await createProof(unsecuredDoc, `${ward.did}#key-0`, oldPrivateKey);
  const op = { ...partial, proof: [authProof, newKeyProof] };
  const result = await submitOperation(env, name, op);
  // WS-1.13 (audit): submitOperation's own rejection reasons (a bad
  // newKeyProof, a stale prev, ...) are the caller's own mistake, same
  // as every other call site that maps this exact boolean+reason result
  // to a response -- index.ts's /operations handler always uses 400 for
  // it. This was the one place still using 500 instead.
  if (!result.accepted) throw new RegistrarError(`take-custody failed: ${result.reason}`, 400);

  await takeCustodyOfWardKey(env, ward.did, publicKey);

  const document = await resolveDocument(env, name);
  return { did: ward.did, document, warnings };
}

const ROOT_WARD_NAME = ""; // the `wards.name` sentinel for the bare-domain identity (spec §2.1) -- empty string, not NULL, so the table's own existing PRIMARY KEY on `name` enforces "at most one root ward" for free, no schema change needed. Never produced by assertValidName (which requires 3-32 chars), so it can never collide with a real registration.

/**
 * The bare-domain identity (spec §2.1) is never registered by an external
 * caller the way a name is -- there's exactly one per deployment, and it
 * belongs to whoever legitimately operates this domain by construction
 * (same as every other resolution in this method: by being the party DNS
 * and TLS actually route the request to). Auto-provisioned lazily, on
 * first access -- mirrors oidc.ts's getOrCreateSigningKeypair exactly,
 * for the same reason: a Cloudflare Worker has no persistent "startup" to
 * hook, so first-access-wins is the only correct place for this.
 */
export async function getOrCreateRootWard(env: Env): Promise<WardRow> {
  const existing = await getWardByName(env, ROOT_WARD_NAME);
  if (existing) {
    // Lazy, one-time upgrade -- same "first access wins" reasoning as the
    // creation path below, just for a deployment whose root ward was
    // already provisioned before ROOT_WARD_LOGIN_SECRET existed (every
    // live deployment at the time this was added). Only ever sets it from
    // null; never overwrites an already-set one, so this stays a one-shot
    // bootstrap, not a standing "the env var always wins" override.
    if (!existing.login_secret_hash && env.ROOT_WARD_LOGIN_SECRET) {
      const hash = await hashPassword(env.ROOT_WARD_LOGIN_SECRET);
      await setLoginSecretHash(env, ROOT_WARD_NAME, hash);
      return { ...existing, login_secret_hash: hash };
    }
    return existing;
  }

  const did = didFor(null, env.REGISTRAR_DOMAIN);
  const keypair =
    env.ROOT_WARD_PUBLIC_KEY && env.ROOT_WARD_PRIVATE_KEY
      ? { publicKey: env.ROOT_WARD_PUBLIC_KEY, privateKey: env.ROOT_WARD_PRIVATE_KEY }
      : await generateKeypair();
  // No registrar attestation for the root ward -- it IS this registrar's
  // identity; nothing else exists yet to vouch for it. Fix 7: self-
  // attested instead -- verifyCustodialCreate treats its own proof of
  // possession as satisfying the attestation requirement whenever
  // op.did equals the registrar DID it's checking against. creator
  // names itself (REQ-7.1-4 requires a DID; there is no other party to
  // name for the one identity a deployment bootstraps on its own).
  const genesis = await signCustodialCreate(
    {
      type: "custodial_create",
      did,
      name: null,
      operationalKeys: [keypair.publicKey],
      services: {},
      outgoing: [],
      incoming: [],
      prev: null,
      creator: did,
    },
    {},
    { [keypair.publicKey]: keypair.privateKey },
  );
  const cid = await cidFor(genesis);
  const createdAt = new Date().toISOString();
  const privateKeyEnc = await encryptSecret(keypair.privateKey, env.KEY_ENCRYPTION_KEY);
  // ROOT_WARD_LOGIN_SECRET (env.ts) is the only way this identity ever
  // gets a usable login credential -- there's no registration flow to set
  // one through, by design (spec/header comment above: there's exactly
  // one of these per deployment, claimed by construction, not by request).
  // Left null, exactly as before, when the operator hasn't set one -- the
  // root identity still resolves and attests other wards' genesis either
  // way, it just can't log in anywhere until this is set.
  const loginSecretHash = env.ROOT_WARD_LOGIN_SECRET ? await hashPassword(env.ROOT_WARD_LOGIN_SECRET) : null;
  const ward: WardRow = { name: ROOT_WARD_NAME, did, public_key: keypair.publicKey, private_key_enc: privateKeyEnc, created_at: createdAt, login_secret_hash: loginSecretHash };
  // WS-1.12 (audit): "first access wins" (this function's own header
  // comment) means a SECOND, concurrent first-access must defer to
  // whichever one actually won the insert, not return its own locally
  // generated (and never persisted) keypair as if it had -- that keypair
  // would silently diverge from what every later call to this function
  // actually resolves. The `existing` check above is the normal path;
  // this is only reached by the loser of a genuine race.
  try {
    await insertWard(env, ward);
  } catch (e) {
    if (isUniqueConstraintError(e)) {
      const winner = await getWardByName(env, ROOT_WARD_NAME);
      if (winner) return winner;
    }
    throw e;
  }
  await appendOperation(env, { cid, did, prev_cid: null, op_type: genesis.type, payload: JSON.stringify(genesis), created_at: createdAt });
  return ward;
}

export async function loadLog(env: Env, did: string): Promise<LogEntry[]> {
  const rows = await getOperationLog(env, did);
  return rows.map((r) => ({ cid: r.cid, op: JSON.parse(r.payload) as Operation, acceptedAt: r.created_at }));
}

/** REQ-12-4: a ward's anchor is its genesis entry's cid -- the first entry in the log, always, regardless of how many operations have followed. Used to populate guardian_add's optional `anchor` field for a guardian this registrar already custodies, where the log is already a local lookup away. */
async function genesisAnchor(env: Env, did: string): Promise<string | undefined> {
  const log = await loadLog(env, did);
  return log[0]?.cid;
}

/**
 * L2 freshness (spec §12.2, REQ-12-1) -- signs a fresh statement naming
 * the ward's current log head, anchor, and length, timestamped now. Never
 * stored or cached: computed and signed anew on every call, with the
 * root identity's key (the same signer REQ-7.1-5's genesis attestation
 * uses), so there's nothing to go stale between requests and no new
 * schema needed. A caller holding this statement can show it to a THIRD
 * party later as evidence of freshness as of that timestamp, without
 * that third party needing to resolve this registrar itself.
 */
export async function getLogHead(env: Env, name: string | null): Promise<LogHeadStatement> {
  const ward = await findWard(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const log = await loadLog(env, ward.did);
  const anchor = log[0]?.cid;
  const headCid = log[log.length - 1]?.cid;
  if (!anchor || !headCid) throw new RegistrarError(`"${name}" has no genesis operation yet`, 500);
  // WS-1.15 (audit): read-only lookup, never provisioning -- a GET must
  // stay safe. Every ward that reaches this point already has a real
  // log, which could only have been accepted by acceptGenesis/
  // registerWard, and both of those already call getOrCreateRootWard
  // themselves before a genesis is ever accepted -- so root is
  // guaranteed to already exist by the time `ward` resolves at all; this
  // never actually needs to create it.
  const rootWard = await getWardByName(env, ROOT_WARD_NAME);
  if (!rootWard) throw new RegistrarError("this registrar's root identity has not been provisioned yet", 500);
  const rootPrivateKey = await decryptWardPrivateKey(env, rootWard);
  const logHash = await logHashFor(log); // Fix 5: commits to every entry's full proof set, not just the latest entryHash -- see LogHeadStatement's own comment
  return signLogHeadStatement(
    { did: ward.did as Did, anchor, headCid, seq: log.length, logHash, timestamp: new Date().toISOString(), registrar: rootWard.did as Did },
    rootPrivateKey,
  );
}

/**
 * `name: null` resolves the bare-domain root identity -- WS-1.15
 * (audit): read-only, never provisioning. A GET (document/log/log-head
 * resolution, every caller of this function) has to stay safe; silently
 * creating the root identity -- a real keypair, a real genesis entry --
 * as a side effect of a plain lookup is exactly the "write on read" bug
 * this closes. getOrCreateRootWard's own lazy provisioning still exists,
 * just restricted to the WRITE paths that actually need the root
 * identity to produce a signature with (acceptGenesis, registerWard,
 * submitOperation's own receipt) -- those already call it directly, not
 * through this function.
 */
export async function findWard(env: Env, name: string | null): Promise<WardRow | null> {
  return getWardByName(env, name ?? ROOT_WARD_NAME);
}

export async function resolveState(env: Env, name: string | null): Promise<{ did: string; state: ResolvedState } | null> {
  const ward = await findWard(env, name);
  if (!ward) return null;
  const log = await loadLog(env, ward.did);
  return { did: ward.did, state: replay(ward.did, log) };
}

export async function resolveDocument(env: Env, name: string | null): Promise<unknown | null> {
  const resolved = await resolveState(env, name);
  if (!resolved) return null;
  return toDidDocument(resolved.state);
}

export async function resolveLog(env: Env, name: string | null): Promise<LogEntry[] | null> {
  const ward = await findWard(env, name);
  if (!ward) return null;
  return loadLog(env, ward.did);
}

/**
 * Verifies and appends one externally-signed operation. The one real write
 * path external callers have -- every signature is checked against live-
 * resolved keys (own wards, or external DIDs resolved via fetch, see
 * makeExternalResolver below), never a cached snapshot (spec §4.2).
 *
 * `custodial_rotate`/`guardian_add`/`guardian_remove`/`guardian_relinquish`/
 * `policy_update`/`custodial_tombstone` all go through rules.ts's
 * verifyByRules -- one shared, spec-traced acceptance gate rather than a
 * bespoke per-type call. `guardian_transfer` (v0.1) is no longer accepted
 * for new submissions -- superseded by guardian_add/guardian_remove; it
 * stays supported for REPLAYING any already-accepted history (document.ts),
 * just not for new writes. `custodial_create` (v0.3, REQ-8-2) delegates to
 * acceptGenesis above, before the findWard check below -- a fresh genesis
 * has no ward row yet by definition, which every other operation type
 * requires.
 */
/**
 * `sigTimestamps`, when given (registrar API spec §3's own async collection,
 * the only caller that has this information): REQ-4-2's own point-in-time
 * key resolution for whichever signer each timestamp names, rather than
 * verifying every signature against whatever's current right now -- see
 * `makeExternalResolver`. A signer not named here is verified against its
 * current key, correct for the ordinary direct-submit path, where every
 * signature was necessarily just produced.
 */
export async function submitOperation(
  env: Env,
  name: string | null,
  op: Operation,
  sigTimestamps?: Record<Did, string>,
): Promise<{ accepted: true; cid?: string; document?: unknown } | { accepted: false; reason: string }> {
  if (op.type === "custodial_create") {
    if (name === null) return { accepted: false, reason: "the bare-domain root identity can't be created this way" };
    const result = await acceptGenesis(env, name, op);
    return result.accepted ? { accepted: true, cid: result.cid, document: result.document } : result;
  }
  const ward = await findWard(env, name);
  if (!ward) return { accepted: false, reason: `no such ward "${name}"` };
  const log = await loadLog(env, ward.did);
  const state = replay(ward.did, log);
  const latestCid = log[log.length - 1]?.cid ?? null;

  if (state.deactivated) {
    return { accepted: false, reason: "this identity is deactivated -- no further operations are accepted (REQ-6-5)" };
  }

  // WS-1.5 (audit): a cid is content-addressed and deterministic (REQ-6-4),
  // so an operation that was once superseded by a nullification (REQ-6-10)
  // still has exactly the same cid if resubmitted verbatim -- proofs are
  // public, carry no nonce or expiry, so anyone could otherwise replay a
  // superseded guardian-signed custodial_rotate with the same prev and
  // nullify the current head all over again within a fresh 72h window.
  // Rejecting any cid that already appears ANYWHERE in the log (not just
  // the currently-active chain) closes this regardless of which branch it
  // originally landed on.
  const candidateCid = await cidFor(op);
  if (log.some((e) => e.cid === candidateCid)) {
    return { accepted: false, reason: "this exact operation (by content hash) already appears in this identity's log -- resubmitting a superseded entry verbatim is not a new nullification (REQ-6-8, audit WS-1.5)" };
  }

  const ctx: VerificationContext = {
    wardDid: ward.did,
    state,
    resolveKey: makeExternalResolver(env),
    isGuardianLive: makeGuardianLivenessResolver(env),
    sigTimestamps,
  };

  const opPrev = (op as { prev?: string | null }).prev ?? null;
  let alreadyVerifiedAsNullification = false;
  if (opPrev !== latestCid) {
    if (op.type !== "custodial_rotate") {
      return { accepted: false, reason: `prev must be the current log head (${latestCid})` };
    }
    const nullCheck = await checkNullification(log, op, ctx);
    if (!nullCheck.ok) {
      return { accepted: false, reason: nullCheck.reason ?? `prev must be the current log head (${latestCid})` };
    }
    alreadyVerifiedAsNullification = true; // checkNullification already confirmed the guardian signer requirement
  }

  let result: { valid: boolean; reason?: string };
  if (alreadyVerifiedAsNullification) {
    result = { valid: true };
  } else {
    switch (op.type) {
      case "custodial_rotate":
      case "guardian_add":
      case "guardian_remove":
      case "guardian_relinquish":
      case "policy_update":
      case "custodial_tombstone":
        result = await verifyByRules(op, ctx);
        break;
      case "guardian_transfer":
        return { accepted: false, reason: "guardian_transfer is superseded in v0.2 -- submit guardian_add and/or guardian_remove instead" };
      default:
        return { accepted: false, reason: `operation type "${(op as { type: string }).type}" is not appendable this way` };
    }
  }

  if (!result.valid) return { accepted: false, reason: result.reason ?? "verification failed" };

  // WS-4.1 (audit): every operation this registrar accepts gets its own
  // signed acceptance receipt appended, one more independent proof in the
  // same set -- the one trustworthy acceptance time REQ-6-8/6-9's
  // nullification window (and any future time-sensitive check) reads,
  // never the unsigned `created_at` row this same timestamp also becomes.
  // Appended AFTER verification and never changes `candidateCid`/`cid`
  // (REQ-6-4 strips every proof before hashing), so it's safe to add here
  // regardless of which branch (ordinary append or nullification) accepted it.
  const acceptedAt = new Date().toISOString();
  const rootWard = await getOrCreateRootWard(env);
  const rootPrivateKey = await decryptWardPrivateKey(env, rootWard);
  const receipt = await signReceipt(unsecuredDocument(op as any), rootWard.did as Did, rootPrivateKey, acceptedAt);
  const existingProof = (op as { proof?: DataIntegrityProof[] }).proof ?? [];
  const acceptedOp = { ...op, proof: [...existingProof, receipt] } as Operation;

  // WS-1.12 (audit): expectedExistingCount closes the race between the
  // verification above (against a log read at the start of this call)
  // and this insert actually landing -- a concurrent request that
  // verified against the same prev would otherwise also succeed,
  // forking the log by accident. Ordinary append: nobody has used this
  // exact (did, prev_cid) pair yet (0). Nullification: exactly the one
  // original entry being superseded already has (1) -- checkNullification
  // already enforced "one level only," so this can never be a second
  // legitimate nullifier racing in; a count of 1 where 0 was expected
  // (or vice versa) only ever means this request lost a race.
  const inserted = await appendOperationIfCountMatches(
    env,
    {
      cid: candidateCid,
      did: ward.did,
      prev_cid: opPrev,
      op_type: acceptedOp.type,
      payload: JSON.stringify(acceptedOp),
      created_at: acceptedAt,
    },
    alreadyVerifiedAsNullification ? 1 : 0,
  );
  if (!inserted) {
    return { accepted: false, reason: "a concurrent operation for this identity was accepted in the meantime -- re-fetch the current log and resubmit (WS-1.12, audit)" };
  }
  return { accepted: true };
}

/**
 * REQ-4-4: whether a guardian DID is currently excluded from every ward it
 * guards, because its OWN identity has been deactivated. A local guardian
 * (this registrar's own ward) is checked directly against its own replayed
 * state, no network involved. An external guardian's deactivation status is
 * method-internal (REQ-3-3 keeps it out of the plain DID Document), so it
 * has to be resolved from that guardian's own operation log, fetched from
 * its own registrar, and replayed here -- mirrors makeExternalResolver's
 * own federation pattern exactly. Fails open (treated as live) on a parse
 * or network failure: a transient unreachability shouldn't silently and
 * permanently exclude a legitimate, merely-unreachable guardian from every
 * threshold it's part of.
 */
export function makeGuardianLivenessResolver(env: Env): GuardianLivenessResolver {
  return async (did: Did): Promise<boolean> => {
    const local = await getWardByDid(env, did);
    if (local) {
      const log = await loadLog(env, local.did);
      return !replay(local.did as Did, log).deactivated;
    }
    let name: string | null, domain: string;
    try {
      ({ name, domain } = parseDid(did));
    } catch {
      return true;
    }
    try {
      const resp = await fetch(`https://${domain}${wellKnownPath(name)}/log`);
      if (!resp.ok) return true;
      const log = (await resp.json()) as LogEntry[];
      return !replay(did, log).deactivated;
    } catch {
      return true;
    }
  };
}

/**
 * Resolves a guardian's keys, whether it's one of this instance's own wards
 * or an external DID at another registrar entirely -- a real did:guardian
 * deployment is federated (spec §5), so a guardian named in `incoming` need
 * not be custodied here.
 *
 * `asOf`, when given, resolves REQ-4-2's point-in-time question instead of
 * "what's current right now": replays that DID's own log (local via
 * `loadLog`, external via its own `/log`, same federation pattern
 * `makeGuardianLivenessResolver` already uses) and returns whichever
 * `operationalKeys` were in force at that moment -- an entry with no
 * recorded `acceptedAt` (shouldn't happen for an already-accepted
 * operation, but a replay-only verifier might hand this a bare log with
 * none) is kept rather than dropped, since there's no acceptance time to
 * compare against. Omitted, this returns the fast path: whatever's current
 * right now, no log fetch needed.
 */
export function makeExternalResolver(env: Env) {
  return async (did: Did, asOf?: Date): Promise<string[] | undefined> => {
    const local = await getWardByDid(env, did);
    if (!asOf) {
      // Audit WS-1.1/1.2: `wards.public_key` is set once at genesis
      // (registerWard/acceptGenesis) and only ever updated by rotateWard
      // and takeCustody -- a self-held ward rotated through the generic
      // POST .../operations path (submitOperation, never touches that
      // column at all) leaves it permanently stale. A verification against
      // "now" MUST read whatever the log's own latest state actually says,
      // the same as the asOf branch below already does -- never a cached
      // column that can silently disagree with the log it's supposed to
      // summarize. Replaying the full log on every resolution is the same
      // cost this function already pays for every `asOf` call; there is no
      // cheaper "trust the DB" shortcut that's actually correct.
      if (local) {
        const log = await loadLog(env, local.did);
        try {
          return replay(local.did as Did, log).operationalKeys;
        } catch {
          return undefined;
        }
      }
      // External DID: resolve via its own registrar's .well-known endpoint --
      // the same deterministic, single-parse split used everywhere else in
      // this method (spec §5), not a bespoke re-implementation of it.
      let name: string | null, domain: string;
      try {
        ({ name, domain } = parseDid(did));
      } catch {
        return undefined;
      }
      try {
        const resp = await fetch(`https://${domain}${wellKnownPath(name)}`);
        if (!resp.ok) return undefined;
        const doc = (await resp.json()) as { verificationMethod?: { publicKeyMultibase: string }[] };
        return doc.verificationMethod?.map((vm) => vm.publicKeyMultibase);
      } catch {
        return undefined;
      }
    }

    let log: LogEntry[];
    if (local) {
      log = await loadLog(env, local.did);
    } else {
      let name: string | null, domain: string;
      try {
        ({ name, domain } = parseDid(did));
      } catch {
        return undefined;
      }
      try {
        const resp = await fetch(`https://${domain}${wellKnownPath(name)}/log`);
        if (!resp.ok) return undefined;
        log = (await resp.json()) as LogEntry[];
      } catch {
        return undefined;
      }
    }
    const asOfMs = asOf.getTime();
    const logAsOf = log.filter((e) => !e.acceptedAt || new Date(e.acceptedAt).getTime() <= asOfMs);
    try {
      return replay(did, logAsOf).operationalKeys;
    } catch {
      return undefined;
    }
  };
}

/**
 * The one place this registrar ever decrypts a ward's operational key --
 * every session-authenticated convenience endpoint below (rotate,
 * tombstone, relinquish, remove-self, adopt) and the OIDC/zz-integration
 * layer that signs as a guardian go through this, never `decryptSecret`
 * directly, so "this ward took custody of its key" has exactly one place
 * to be enforced. Throws rather than returning undefined: every caller
 * here already committed to signing on this ward's behalf and has no
 * fallback if it can't -- a guardian-set-building loop that should skip
 * a self-held guardian instead (relinquishWard, forceRemoveGuardian,
 * registerWard's same-registrar convenience) checks `custody_mode`
 * before calling this, rather than catching.
 */
export async function decryptWardPrivateKey(env: Env, ward: WardRow): Promise<string> {
  if ((await getWardCustodyMode(env, ward.did)) === "self") {
    throw new RegistrarError(
      `"${ward.name || ward.did}" took custody of its key -- this registrar can no longer sign on its behalf. Sign and submit the operation directly with that key instead.`,
      409,
    );
  }
  return decryptSecret(ward.private_key_enc, env.KEY_ENCRYPTION_KEY);
}

export { DEFAULT_GUARDIAN_POLICY };
