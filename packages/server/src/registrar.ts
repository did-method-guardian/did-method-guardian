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
  DEFAULT_GUARDIAN_POLICY,
} from "@did-guardian/lib";
import type { Did, LogEntry, Operation, ResolvedState } from "@did-guardian/lib";
import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { appendOperation, getOperationLog, getWardByDid, getWardByName, insertWard, type WardRow } from "./db.js";
import { encryptSecret, decryptSecret } from "./secretBox.js";

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
export async function registerWard(env: Env, name: string): Promise<{ did: string; document: unknown }> {
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

  const privateKeyEnc = await encryptSecret(keypair.privateKey, env.KEY_ENCRYPTION_KEY);
  const ward: WardRow = { name, did, public_key: keypair.publicKey, private_key_enc: privateKeyEnc, created_at: createdAt };
  await insertWard(env, ward);
  await appendOperation(env, { cid, did, prev_cid: null, op_type: genesis.type, payload: JSON.stringify(genesis), created_at: createdAt });

  const state = replay(did, [{ cid, op: genesis }]);
  return { did, document: toDidDocument(state) };
}

async function loadLog(env: Env, did: string): Promise<LogEntry[]> {
  const rows = await getOperationLog(env, did);
  return rows.map((r) => ({ cid: r.cid, op: JSON.parse(r.payload) as Operation }));
}

export async function resolveState(env: Env, name: string): Promise<{ did: string; state: ResolvedState } | null> {
  const ward = await getWardByName(env, name);
  if (!ward) return null;
  const log = await loadLog(env, ward.did);
  return { did: ward.did, state: replay(ward.did, log) };
}

export async function resolveDocument(env: Env, name: string): Promise<unknown | null> {
  const resolved = await resolveState(env, name);
  if (!resolved) return null;
  return toDidDocument(resolved.state);
}

export async function resolveLog(env: Env, name: string): Promise<LogEntry[] | null> {
  const ward = await getWardByName(env, name);
  if (!ward) return null;
  return loadLog(env, ward.did);
}

/**
 * Verifies and appends one externally-signed operation. The one real write
 * path external callers have -- every signature is checked against live-
 * resolved keys (own wards, or external DIDs resolved via fetch, see
 * resolveExternal below), never a cached snapshot (spec §4.8).
 */
export async function submitOperation(env: Env, name: string, op: Operation): Promise<{ accepted: true } | { accepted: false; reason: string }> {
  const ward = await getWardByName(env, name);
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
    // External DID: resolve via its own registrar's .well-known endpoint.
    const parts = did.split(":");
    if (parts[0] !== "did" || parts[1] !== "guardian" || parts.length < 4) return undefined;
    const [, , extName, ...labels] = parts;
    const domain = labels.join(".");
    try {
      const resp = await fetch(`https://${domain}/.well-known/guardian/${extName}`);
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
