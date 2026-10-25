import {
  generateKeypair,
  signCustodialCreate,
  signCustodialRotate,
  signGuardianAdd,
  signGuardianRemove,
  signGuardianRelinquish,
  signCustodialTombstone,
  signRegistrarAttestation,
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
} from "@did-guardian/lib";
import type { Did, GuardianLivenessResolver, LogEntry, Operation, ResolvedState, VerificationContext } from "@did-guardian/lib";
import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { appendOperation, getOperationLog, getWardByDid, getWardByName, insertWard, setLoginSecretHash, updateWardKeys, type WardRow } from "./db.js";
import { encryptSecret, decryptSecret, hashSecret, randomSecret } from "./secretBox.js";

export class RegistrarError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

/** REQ-2-1, via the single source of truth in @did-guardian/lib -- registrar.ts previously had its own copy that let a double-hyphen and even a single-character name through. */
export function assertValidName(name: string): void {
  if (!isValidName(name)) {
    throw new RegistrarError(`invalid name "${name}" -- must be 3-32 lowercase alphanumeric/hyphen characters, no leading/trailing/double hyphens`, 400);
  }
}

/**
 * Registers a brand-new identity. Genesis itself is always guardian-less
 * now (REQ-7.1-1) -- `incoming` is always `[]`, and `signCustodialCreate`'s
 * own loop over it is trivially a no-op, so genesis never needs a guardian
 * signature at all. `creator` (REQ-7.1-4) is this registrar's own bare-
 * domain root identity for an ordinary self-service signup (no other party
 * initiated it); a `registrar` attestation (REQ-7.1-5), signed with that
 * same root identity's own key, is attached unconditionally -- cheap, since
 * the root ward is already auto-provisioned on first access regardless.
 *
 * `guardianDid`, when given, establishes a real first guardian immediately
 * afterward via a genuine, separately-signed `guardian_add` (REQ-7.2-5,
 * zero-to-one) -- two log entries, one API call, not genesis itself
 * carrying a guardian directly. Only ever reached with a caller-supplied
 * value when index.ts's own route handler has already verified a trusted
 * OIDC client credential (clientAuth.ts) -- an unauthenticated caller's
 * `guardian_did` is never honored, never even reaches this function. Safe
 * specifically because this registrar custodies both keys: the new ward's
 * own (always true) and the guardian's (only true when `guardianDid`
 * identifies one of this same registrar's own wards, checked below) -- so
 * both required signatures are producible server-side, with no separate
 * interactive signing round-trip needed. If the guardian_add fails, genesis
 * itself has already succeeded -- the ward exists, ownerless, rather than
 * half-created; the caller gets a clear error naming just that failure.
 */
export async function registerWard(env: Env, name: string, guardianDid?: string | null): Promise<{ did: string; document: unknown; login_secret: string }> {
  assertValidName(name);
  if (await getWardByName(env, name)) {
    throw new RegistrarError(`name "${name}" is already taken`, 409);
  }

  const did = didFor(name, env.REGISTRAR_DOMAIN);
  const keypair = await generateKeypair();
  const rootWard = await getOrCreateRootWard(env);
  const rootPrivateKey = await decryptSecret(rootWard.private_key_enc, env.KEY_ENCRYPTION_KEY);

  const genesisPartial = {
    type: "custodial_create" as const,
    name,
    operationalKeys: [keypair.publicKey],
    verificationMethods: { "key-1": keypair.publicKey },
    services: {},
    outgoing: [] as [],
    incoming: [] as Did[],
    prev: null,
    creator: rootWard.did,
  };
  const attestation = await signRegistrarAttestation(genesisPartial, rootWard.did, rootPrivateKey);
  const genesis = await signCustodialCreate({ ...genesisPartial, registrar: attestation }, {});
  const cid = await cidFor(genesis);
  const createdAt = new Date().toISOString();

  // The login secret proves control of this ward to THIS registrar's own
  // login/OIDC flow -- a separate credential from the operational key,
  // needed because the custodial model here means the key itself isn't
  // provable client-side (the server holds it, not the caller). Returned
  // once, in plaintext, here only -- stored hashed, same as a password.
  const loginSecret = randomSecret();
  const loginSecretHash = await hashSecret(loginSecret);

  const privateKeyEnc = await encryptSecret(keypair.privateKey, env.KEY_ENCRYPTION_KEY);
  const ward: WardRow = { name, did, public_key: keypair.publicKey, private_key_enc: privateKeyEnc, created_at: createdAt, login_secret_hash: loginSecretHash };
  await insertWard(env, ward);
  await appendOperation(env, { cid, did, prev_cid: null, op_type: genesis.type, payload: JSON.stringify(genesis), created_at: createdAt });

  if (guardianDid) {
    const guardianWard = await getWardByDid(env, guardianDid);
    if (!guardianWard) {
      throw new RegistrarError(`guardian_did "${guardianDid}" is not a ward this registrar custodies -- it can't produce that ward's signature`, 400);
    }
    const guardianPrivateKey = await decryptSecret(guardianWard.private_key_enc, env.KEY_ENCRYPTION_KEY);
    const addOp = await signGuardianAdd(
      { type: "guardian_add", incoming: guardianDid, prev: cid },
      { [guardianDid]: guardianPrivateKey, [did]: keypair.privateKey }, // REQ-7.2-5: zero-to-one needs both the incoming guardian's own key and the ward's own operational key
      [guardianDid, did],
    );
    const result = await submitOperation(env, name, addOp);
    if (!result.accepted) {
      throw new RegistrarError(`"${name}" was created, but establishing "${guardianDid}" as its guardian failed: ${result.reason}`, 500);
    }
  }

  const log = await loadLog(env, did);
  const state = replay(did as Did, log);
  return { did, document: toDidDocument(state), login_secret: loginSecret };
}

/**
 * Replaces a ward's login secret with a freshly generated one -- the one
 * real recovery path for "I never saved it" or "I think it leaked,"
 * since there's no way to recover the original (only its hash is ever
 * stored). The old secret stops working the instant this runs: nothing
 * here keeps the previous hash around or allows more than one valid
 * secret at a time, same as a password reset invalidating the old
 * password. Callers (index.ts) already gate who may call this at all --
 * either an active session as this exact ward, or a trusted relying
 * party acting on an already-authenticated session of its own.
 */
export async function reissueLoginSecret(env: Env, name: string): Promise<string> {
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
  // Same exclusion as /email and /login-secret above -- the bare-
  // domain root identity (findWard's `null` case) isn't reachable
  // through this name-keyed path at all, deliberately: rotating the
  // domain's own root credential is a different, more sensitive
  // operation than anything this zz-driven feature needs.
  const ward = await getWardByName(env, name);
  if (!ward) throw new RegistrarError(`no such ward "${name}"`, 404);
  const log = await loadLog(env, ward.did);
  const latestCid = log[log.length - 1]?.cid;
  if (!latestCid) throw new RegistrarError(`"${name}" has no genesis operation to rotate from`, 500);
  const state = replay(ward.did as Did, log);

  const oldPrivateKey = await decryptSecret(ward.private_key_enc, env.KEY_ENCRYPTION_KEY);
  const newKeypair = await generateKeypair();
  const op = await signCustodialRotate(
    {
      type: "custodial_rotate",
      operationalKeys: [newKeypair.publicKey],
      verificationMethods: { "key-1": newKeypair.publicKey },
      services: state.services,
      prev: latestCid,
    },
    oldPrivateKey,
  );
  const result = await submitOperation(env, name, op);
  if (!result.accepted) throw new RegistrarError(`rotation failed: ${result.reason}`, 500);

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

  const ownKey = await decryptSecret(ward.private_key_enc, env.KEY_ENCRYPTION_KEY);
  const op = await signCustodialTombstone({ type: "custodial_tombstone", prev: latestCid }, { [ward.did]: ownKey }, [ward.did]);
  const result = await submitOperation(env, name, op);
  if (!result.accepted) throw new RegistrarError(`tombstone failed: ${result.reason}`, 500);

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
    if (guardianWard) signerKeys[guardianDid] = await decryptSecret(guardianWard.private_key_enc, env.KEY_ENCRYPTION_KEY);
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
  if (!result.accepted) throw new RegistrarError(`relinquish failed: ${result.reason}`, 500);

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

  const callerPrivateKey = await decryptSecret(callerWard.private_key_enc, env.KEY_ENCRYPTION_KEY);
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
    if (guardianWard) signerKeys[guardianDid] = await decryptSecret(guardianWard.private_key_enc, env.KEY_ENCRYPTION_KEY);
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

  const incomingPrivateKey = await decryptSecret(incomingWard.private_key_enc, env.KEY_ENCRYPTION_KEY);
  const wardPrivateKey = await decryptSecret(ward.private_key_enc, env.KEY_ENCRYPTION_KEY);
  const op = await signGuardianAdd(
    { type: "guardian_add", incoming: incomingDid, prev: latestCid },
    { [incomingDid]: incomingPrivateKey, [ward.did]: wardPrivateKey },
    [incomingDid, ward.did],
  );
  const result = await submitOperation(env, name, op);
  if (!result.accepted) throw new RegistrarError(`adopt failed: ${result.reason}`, 400);

  const document = await resolveDocument(env, name);
  return { did: ward.did, document };
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
  if (existing) return existing;

  const did = didFor(null, env.REGISTRAR_DOMAIN);
  const keypair =
    env.ROOT_WARD_PUBLIC_KEY && env.ROOT_WARD_PRIVATE_KEY
      ? { publicKey: env.ROOT_WARD_PUBLIC_KEY, privateKey: env.ROOT_WARD_PRIVATE_KEY }
      : await generateKeypair();
  // No registrar attestation for the root ward itself -- it IS this
  // registrar's own identity; nothing else exists yet to vouch for it.
  // creator names itself (REQ-7.1-4 requires a DID; there is no other
  // party to name for the one identity a deployment bootstraps on its own).
  const genesis = await signCustodialCreate(
    {
      type: "custodial_create",
      name: null,
      operationalKeys: [keypair.publicKey],
      verificationMethods: { "key-1": keypair.publicKey },
      services: {},
      outgoing: [],
      incoming: [],
      prev: null,
      creator: did,
    },
    {},
  );
  const cid = await cidFor(genesis);
  const createdAt = new Date().toISOString();
  const privateKeyEnc = await encryptSecret(keypair.privateKey, env.KEY_ENCRYPTION_KEY);
  const ward: WardRow = { name: ROOT_WARD_NAME, did, public_key: keypair.publicKey, private_key_enc: privateKeyEnc, created_at: createdAt, login_secret_hash: null };
  await insertWard(env, ward);
  await appendOperation(env, { cid, did, prev_cid: null, op_type: genesis.type, payload: JSON.stringify(genesis), created_at: createdAt });
  return ward;
}

export async function loadLog(env: Env, did: string): Promise<LogEntry[]> {
  const rows = await getOperationLog(env, did);
  return rows.map((r) => ({ cid: r.cid, op: JSON.parse(r.payload) as Operation, acceptedAt: r.created_at }));
}

/** `name: null` auto-provisions the bare-domain root identity (never missing); a real name that isn't registered yet stays a plain miss. */
export async function findWard(env: Env, name: string | null): Promise<WardRow | null> {
  return name === null ? await getOrCreateRootWard(env) : await getWardByName(env, name);
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
 * just not for new writes. `custodial_create` isn't reachable here at all --
 * genesis has its own path (registerWard).
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
): Promise<{ accepted: true } | { accepted: false; reason: string }> {
  const ward = await findWard(env, name);
  if (!ward) return { accepted: false, reason: `no such ward "${name}"` };
  const log = await loadLog(env, ward.did);
  const state = replay(ward.did, log);
  const latestCid = log[log.length - 1]?.cid ?? null;

  if (state.deactivated) {
    return { accepted: false, reason: "this identity is deactivated -- no further operations are accepted (REQ-6-5)" };
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

  const cid = await cidFor(op);
  await appendOperation(env, {
    cid,
    did: ward.did,
    prev_cid: opPrev,
    op_type: op.type,
    payload: JSON.stringify(op),
    created_at: new Date().toISOString(),
  });
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
      if (local) return [local.public_key];
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

/** For this instance's own wards to sign as a guardian of another ward -- used by the OIDC/zz-integration layer, not the public HTTP API directly. */
export async function decryptWardPrivateKey(env: Env, ward: WardRow): Promise<string> {
  return decryptSecret(ward.private_key_enc, env.KEY_ENCRYPTION_KEY);
}

export { DEFAULT_GUARDIAN_POLICY };
