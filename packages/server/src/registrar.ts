import {
  generateKeypair,
  signCustodialCreate,
  cidFor,
  replay,
  toDidDocument,
  verifyCustodialRotate,
  verifyGuardianTransfer,
  verifyGuardianRelinquish,
  verifyCustodialTombstone,
  parseDid,
  wellKnownPath,
  DEFAULT_GUARDIAN_POLICY,
} from "@did-guardian/lib";
import type { Did, LogEntry, Operation, ResolvedState } from "@did-guardian/lib";
import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { appendOperation, getOperationLog, getWardByDid, getWardByName, insertWard, type WardRow } from "./db.js";
import { encryptSecret, decryptSecret, hashSecret, randomSecret } from "./secretBox.js";

const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])?$/;

export class RegistrarError extends Error {
  constructor(message: string, public status: number) {
    super(message);
  }
}

export function assertValidName(name: string): void {
  if (!NAME_RE.test(name)) {
    throw new RegistrarError(`invalid name "${name}" -- must be 3-32 lowercase alphanumeric/hyphen characters, no leading/trailing/double hyphens`, 400);
  }
}

/**
 * Registers a brand-new, ownerless (`incoming: []`) identity. Establishing a
 * guardian is always done afterward via a real, signed `guardian_transfer`
 * (spec §4.1/§4.3) -- kept out of registration itself so this endpoint never
 * needs to verify an externally-supplied guardian signature, concentrating
 * all of that complexity in one place (`submitOperation` below).
 */
export async function registerWard(env: Env, name: string): Promise<{ did: string; document: unknown; login_secret: string }> {
  assertValidName(name);
  if (await getWardByName(env, name)) {
    throw new RegistrarError(`name "${name}" is already taken`, 409);
  }

  const did = didFor(name, env.REGISTRAR_DOMAIN);
  const keypair = await generateKeypair();
  const genesis = await signCustodialCreate(
    {
      type: "custodial_create",
      name,
      operationalKeys: [keypair.publicKey],
      verificationMethods: { "key-1": keypair.publicKey },
      services: {},
      outgoing: [],
      incoming: [],
      prev: null,
    },
    {},
  );
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

  const state = replay(did, [{ cid, op: genesis }]);
  return { did, document: toDidDocument(state), login_secret: loginSecret };
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

async function loadLog(env: Env, did: string): Promise<LogEntry[]> {
  const rows = await getOperationLog(env, did);
  return rows.map((r) => ({ cid: r.cid, op: JSON.parse(r.payload) as Operation }));
}

/** `name: null` auto-provisions the bare-domain root identity (never missing); a real name that isn't registered yet stays a plain miss. */
async function findWard(env: Env, name: string | null): Promise<WardRow | null> {
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
 * resolveExternal below), never a cached snapshot (spec §4.8).
 */
export async function submitOperation(env: Env, name: string | null, op: Operation): Promise<{ accepted: true } | { accepted: false; reason: string }> {
  const ward = await findWard(env, name);
  if (!ward) return { accepted: false, reason: `no such ward "${name}"` };
  const log = await loadLog(env, ward.did);
  const state = replay(ward.did, log);
  const latestCid = log[log.length - 1]?.cid ?? null;

  if ((op as { prev?: string | null }).prev !== latestCid) {
    return { accepted: false, reason: `prev must be the current log head (${latestCid})` };
  }

  const resolve = makeExternalResolver(env);
  let result: { valid: boolean; reason?: string };
  switch (op.type) {
    case "custodial_rotate":
      result = await verifyCustodialRotate(op, state.operationalKeys, resolve);
      break;
    case "guardian_transfer":
      result = await verifyGuardianTransfer(op, ward.did, state.guardians, resolve);
      break;
    case "guardian_relinquish":
      result = await verifyGuardianRelinquish(op, state.guardians, state.guardianPolicy.removal_threshold, resolve);
      break;
    case "custodial_tombstone":
      result = await verifyCustodialTombstone(op, [ward.did, ...state.guardians], state.guardianPolicy.tombstone_threshold, resolve);
      break;
    default:
      return { accepted: false, reason: `operation type "${(op as { type: string }).type}" is not appendable this way` };
  }

  if (!result.valid) return { accepted: false, reason: result.reason ?? "verification failed" };

  const cid = await cidFor(op);
  await appendOperation(env, {
    cid,
    did: ward.did,
    prev_cid: latestCid,
    op_type: op.type,
    payload: JSON.stringify(op),
    created_at: new Date().toISOString(),
  });
  return { accepted: true };
}

/**
 * Resolves a guardian's keys, whether it's one of this instance's own wards
 * or an external DID at another registrar entirely -- a real did:guardian
 * deployment is federated (spec §5), so a guardian named in `incoming` need
 * not be custodied here.
 */
function makeExternalResolver(env: Env) {
  return async (did: Did): Promise<string[] | undefined> => {
    const local = await getWardByDid(env, did);
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
  };
}

/** For this instance's own wards to sign as a guardian of another ward -- used by the OIDC/zz-integration layer, not the public HTTP API directly. */
export async function decryptWardPrivateKey(env: Env, ward: WardRow): Promise<string> {
  return decryptSecret(ward.private_key_enc, env.KEY_ENCRYPTION_KEY);
}

export { DEFAULT_GUARDIAN_POLICY };
