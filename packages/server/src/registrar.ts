// The did:guardian registrar (spec §10). Three resources (REQ-10-1) and
// one acceptance path (REQ-10-5) that every route funnels through -- no
// route appends to `logs` on its own.
import {
  checkAcceptance,
  createProof,
  DEFAULT_POLICY,
  generateKeypair,
  parseGuardianDid,
  resolve as resolveDid,
  sameKeys,
  verifyLog,
  type CreateOp,
  type Did,
  type DidDocument,
  type Key,
  type Log,
  type Operation,
} from "@did-guardian/lib";
import {
  appendOperation,
  deleteAllLoginSessionsForWard,
  getHeldKey,
  getLog,
  getNameEntry,
  insertHeldKey,
  insertNameEntry,
  invalidateLoginSecretHash,
  setHeldKeyLoginSecretHash,
} from "./db.js";
import { makeResolveLog } from "./logResolver.js";
import { signAttestation } from "./signing.js";
import { RegistrarError } from "./registrarError.js";
import { didFor, type Env } from "./env.js";
import { encryptSecret, hashSecret } from "./secretBox.js";

export { RegistrarError };

/** REQ-4-5: the path segment for a DID on this registrar's own domain. */
export function segmentFor(did: Did, env: Env): string | undefined {
  const parsed = parseGuardianDid(did);
  if (!parsed || parsed.domain !== env.REGISTRAR_DOMAIN) return undefined;
  return parsed.name ?? "_";
}

export function didForSegment(env: Env, segment: string): Did {
  return didFor(segment === "_" ? null : segment, env.REGISTRAR_DOMAIN) as Did;
}

/**
 * REQ-10-10: this registrar MUST create its root identity before it
 * accepts any other create. Called lazily, on first use -- idempotent
 * (a root that already exists is returned as-is, never recreated).
 */
export async function ensureRootIdentity(env: Env): Promise<Did> {
  const rootDid = didFor(null, env.REGISTRAR_DOMAIN) as Did;
  const existing = await getLog(env, rootDid);
  if (existing.length > 0) {
    // Lazily set the login secret if it's configured but hasn't been
    // hashed and stored yet (e.g. set on an already-provisioned deployment).
    if (env.ROOT_WARD_LOGIN_SECRET) {
      const held = await getHeldKey(env, rootDid);
      if (held && !held.login_secret_hash) await setHeldKeyLoginSecretHash(env, rootDid, await hashSecret(env.ROOT_WARD_LOGIN_SECRET));
    }
    return rootDid;
  }

  // An operator may bring their own root keypair instead of one this
  // registrar generates (env.ts's own documented ROOT_WARD_PUBLIC_KEY/
  // ROOT_WARD_PRIVATE_KEY) -- both or neither; one without the other is
  // ignored, same as a deployment that set neither.
  const keypair =
    env.ROOT_WARD_PUBLIC_KEY && env.ROOT_WARD_PRIVATE_KEY
      ? { publicKey: env.ROOT_WARD_PUBLIC_KEY, privateKey: env.ROOT_WARD_PRIVATE_KEY }
      : await generateKeypair();

  const createOp: CreateOp = {
    type: "create",
    did: rootDid,
    keys: [keypair.publicKey as Key],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
    proof: [],
  };
  const proof = await createProof(createOp, keypair.publicKey as Key, keypair.privateKey);
  const signed: CreateOp = { ...createOp, proof: [proof] };

  const now = new Date().toISOString();
  const ok = await appendOperation(env, rootDid, 0, "", signed, now);
  if (!ok) {
    // Lost a race with another request also bootstrapping the root -- the
    // winner's root is just as valid as the one this request would have
    // created; use it.
    return rootDid;
  }
  await insertNameEntry(env, env.REGISTRAR_DOMAIN, "", rootDid, now);
  await insertHeldKey(env, {
    did: rootDid,
    public_key: keypair.publicKey,
    private_key_enc: await encryptSecret(keypair.privateKey, env.KEY_ENCRYPTION_KEY),
    login_secret_hash: env.ROOT_WARD_LOGIN_SECRET ? await hashSecret(env.ROOT_WARD_LOGIN_SECRET) : null,
    created_at: now,
  });
  return rootDid;
}

/** REQ-10-1: `GET .../<segment>/log`. */
export async function getResourceLog(env: Env, segment: string): Promise<Log | undefined> {
  const did = didForSegment(env, segment);
  const log = await getLog(env, did);
  return log.length > 0 ? log : undefined;
}

/** REQ-10-1: `GET .../<segment>`, the DID document. */
export async function getResourceDocument(env: Env, segment: string): Promise<DidDocument | undefined> {
  const did = didForSegment(env, segment);
  const log = await getLog(env, did);
  if (log.length === 0) return undefined;
  const result = await resolveDid(did, log, makeResolveLog(env));
  return result.result === "valid" ? result.document : undefined;
}

/**
 * REQ-10-1: `POST .../<segment>/operations`, the one acceptance path.
 * `candidate` must already carry every proof it needs -- a route that
 * needs this registrar to sign with a held key does so itself (signAs/
 * signAttestation) before calling this; this function only ever adds
 * the create attestation (REQ-10-9), never an ordinary proof.
 */
export async function submitOperation(env: Env, did: Did, candidate: Operation): Promise<Operation> {
  const parsed = parseGuardianDid(did);
  if (!parsed) throw new RegistrarError("REQ-4-1: not a valid did:guardian identifier");

  const existingLog = await getLog(env, did);
  const resolveLog = makeResolveLog(env);
  let toAccept = candidate;

  if (candidate.type === "create") {
    if (existingLog.length > 0) throw new RegistrarError("REQ-8-1: a later operation must not be a create");
    if (parsed.domain !== env.REGISTRAR_DOMAIN) throw new RegistrarError(`REQ-10-9: this registrar only creates identities on ${env.REGISTRAR_DOMAIN}`);

    // REQ-10-10: the root identity is this registrar's own, bootstrapped
    // only by ensureRootIdentity (at startup/first use), never accepted
    // as a submitted operation -- an externally-submitted root create
    // would let the first anonymous caller claim the attestation key.
    if (parsed.name === null) throw new RegistrarError("REQ-10-10: the root identity cannot be created by a submitted operation");

    // REQ-10-10: the root identity must exist before any other
    // create -- bootstrapped here, lazily, on the first one (never
    // from a GET: REQ-10-2).
    await ensureRootIdentity(env);

    // REQ-10-9: the name must be unused -- a pre-check here for a clear
    // rejection reason; insertNameEntry's own unique constraint (after
    // acceptance, below) is what actually makes this race-free.
    const existingName = await getNameEntry(env, parsed.domain, parsed.name);
    if (existingName) throw new RegistrarError("REQ-10-12: this name is already used");

    // REQ-10-9: add the attestation before REQ-10-5 applies.
    toAccept = { ...candidate, attestation: await signAttestation(env, candidate) };
  } else if (existingLog.length === 0) {
    throw new RegistrarError("REQ-10-5: this identity has no log yet");
  }

  const result = await checkAcceptance(did, existingLog, toAccept, resolveLog);
  if (!result.accepted) throw new RegistrarError(result.reason ?? "REQ-10-5: rejected");

  if (toAccept.type === "create") {
    // parsed.name is never null here -- a root create was already
    // rejected above.
    const now = new Date().toISOString();
    const ok = await insertNameEntry(env, parsed.domain, parsed.name as string, did, now);
    if (!ok) throw new RegistrarError("REQ-10-12: this name is already used");
  }

  const seq = existingLog.length;
  const prev = seq === 0 ? "" : (toAccept as { prev: string }).prev;
  const appended = await appendOperation(env, did, seq, prev, toAccept, new Date().toISOString());
  if (!appended) throw new RegistrarError("REQ-10-8: the log has moved on since this operation was prepared; retry against its current version");

  // R2-0.5 (round-2 audit, re-wired; scope and login_secret coverage
  // per thoward-59's review): login_secret/sessions and the
  // operational key are unrelated credentials -- a session proves
  // login_secret, not possession of any key -- so an accepted `update`
  // that actually changes `keys` must invalidate every existing
  // session AND the login_secret itself for this DID, regardless of
  // who signed it or which path produced it (self-service,
  // take-custody, or a guardian's own recovery), or whoever holds a
  // stolen login_secret just keeps a working session (or logs back in
  // outright) straight through the rotation meant to recover from
  // exactly that. Scoped to an actual keys change, not every update --
  // editing a service endpoint or alsoKnownAs alone must not log
  // anyone out.
  if (toAccept.type === "update" && existingLog.length > 0) {
    const priorVerified = await verifyLog(did, existingLog);
    const priorKeys = priorVerified.result === "valid" ? priorVerified.state!.keys : [];
    if (!sameKeys(priorKeys, toAccept.keys)) {
      await deleteAllLoginSessionsForWard(env, did);
      await invalidateLoginSecretHash(env, did);
    }
  }

  return toAccept;
}
