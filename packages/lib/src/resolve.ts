import { toDidDocument, toResolutionMetadata, type DidDocument, type ResolutionMetadata } from "./document.js";
import { anchorOf, isSupportedCryptosuite, operationHash, parseGuardianDid, verifyProofSignature } from "./operations.js";
import { verifyLog } from "./verifyLog.js";
import type { CreateOp, Did, Entry, Key, Log, WardRecord } from "./types.js";

/**
 * Splits an identifier into its registrar domain and (optional) name.
 * Deterministic, single parse -- no retry/fallback needed (spec §2/§5): the
 * domain is always dot-joined and a name can never contain a dot, so
 * "one colon after the method name" vs. "none" fully disambiguates bare
 * (`did:guardian:acme.com`) from named (`did:guardian:acme.com:alice`).
 * Domain-first, matching did:web's own convention (`did:web:<domain>:
 * <path...>`) -- did:guardian is the method-specific-id's domain followed
 * by at most one flat name segment, a deliberate subset of that same
 * grammar, not a coincidence.
 */
export function parseDid(did: Did): { name: string | null; domain: string } {
  const parts = did.split(":");
  if (parts[0] !== "did" || parts[1] !== "guardian" || parts.length < 3) {
    throw new Error(`not a valid did:guardian identifier: ${did}`);
  }
  const rest = parts.slice(2);
  const domain = rest[0];
  if (rest.length < 1 || rest.length > 2 || !domain) {
    throw new Error(`not a valid did:guardian identifier: ${did}`);
  }
  return rest.length === 1 ? { name: null, domain } : { name: rest[1], domain };
}

/** `name: null` resolves to the reserved `_` segment -- the bare-domain identity's own well-known path (spec §2.1/§5), never a real registration (the name ABNF forbids `_`). */
export function wellKnownPath(name: string | null): string {
  return `/.well-known/guardian/${name ?? "_"}`;
}

/** Fetches the current log of `did` -- live resolution for REQ-5-14's cross-log checks (REQ-10-7), and for the resolution functions below. Returns `undefined` if the log cannot be retrieved. */
export type LogResolver = (did: Did) => Log | undefined | Promise<Log | undefined>;

export type Outcome = "valid" | "invalid" | "unsupported";

export async function findByHash(log: Log, hash: string): Promise<number> {
  for (let i = 0; i < log.length; i++) {
    if ((await operationHash(log[i])) === hash) return i;
  }
  return -1;
}

/**
 * REQ-11-2: verifies a `create`'s attestation. Unsupported only for an
 * unrecognized cryptosuite; every other failure (an unreachable root log,
 * a version or key index that doesn't exist, a bad signature, a
 * deactivated root) is invalid.
 */
export async function verifyAttestation(create: CreateOp, resolveLog: LogResolver, implementedExtensions: ReadonlySet<string> = new Set()): Promise<Outcome> {
  const attestation = create.attestation;
  if (!attestation) return "valid"; // the root identity's own create has none (REQ-7-7)
  if (!isSupportedCryptosuite(attestation.cryptosuite)) return "unsupported";

  const m = /^(did:guardian:[^?#]+)\?versionId=([^#]+)#key-(0|[1-9][0-9]*)$/.exec(attestation.verificationMethod);
  if (!m) return "invalid";
  const rootDid = m[1] as Did;
  const version = m[2];
  const index = Number(m[3]);

  const rootLog = await resolveLog(rootDid);
  if (!rootLog) return "invalid";
  const opIndex = await findByHash(rootLog, version);
  if (opIndex === -1) return "invalid";

  const prefixResult = await verifyLog(rootDid, rootLog.slice(0, opIndex + 1), implementedExtensions);
  if (prefixResult.result === "unsupported") return "unsupported";
  if (prefixResult.result !== "valid") return "invalid";
  const state = prefixResult.state!;
  if (state.deactivated) return "invalid";
  if (index >= state.keys.length) return "invalid";

  const ok = await verifyProofSignature(create, attestation, state.keys[index]);
  return ok ? "valid" : "invalid";
}

export interface ResolveResult {
  result: Outcome;
  reason?: string;
  document?: DidDocument;
  metadata?: ResolutionMetadata;
}

/** REQ-11-1: resolves a DID to its document. `implementedExtensions` defaults to empty, same as `verifyLog`. */
export async function resolve(did: Did, log: Log, resolveLog: LogResolver, implementedExtensions: ReadonlySet<string> = new Set()): Promise<ResolveResult> {
  const verified = await verifyLog(did, log, implementedExtensions);
  if (verified.result !== "valid") return { result: verified.result, reason: verified.reason };

  const domain = parseGuardianDid(did)!.domain;
  const isRoot = did === `did:guardian:${domain}`;
  if (!isRoot) {
    const attestationResult = await verifyAttestation(log[0] as CreateOp, resolveLog, implementedExtensions);
    if (attestationResult !== "valid") return { result: attestationResult };
  }

  const state = verified.state!;
  const version = await operationHash(log[log.length - 1]);
  const anchor = await anchorOf(log[0] as CreateOp);
  return { result: "valid", document: toDidDocument(did, state), metadata: toResolutionMetadata(version, anchor, state) };
}

/** REQ-5-5: two lists of keys are equal if they contain the same keys, in any order. Each list is already known distinct (REQ-6-1), so same length plus full containment is set equality. */
export function sameKeys(a: Key[], b: Key[]): boolean {
  if (a.length !== b.length) return false;
  const bSet = new Set(b);
  return a.every((k) => bSet.has(k));
}

export type MutualityResult = "unavailable" | "different identity" | "deactivated" | "withdrawn" | "keys out of date" | "mutual";

/**
 * REQ-11-5: one entry's own mutuality report. `wardDid`/`wardAnchor`
 * identify the identity whose `guardians`/`successor` this entry came
 * from. `skipKeysCheck` is REQ-10-7's own exception to REQ-10-6 item 3
 * (standing, below) -- never used for REQ-11-5 itself, which has no
 * such exception.
 */
export async function checkMutuality(
  wardDid: Did,
  wardAnchor: string,
  entry: Entry,
  resolveLog: LogResolver,
  skipKeysCheck = false,
  implementedExtensions: ReadonlySet<string> = new Set(),
): Promise<MutualityResult> {
  const log = await resolveLog(entry.did);
  if (!log) return "unavailable";
  const verified = await verifyLog(entry.did, log, implementedExtensions);
  if (verified.result !== "valid") return "unavailable";

  const anchor = await anchorOf(log[0] as CreateOp);
  if (anchor !== entry.anchor) return "different identity";

  const state = verified.state!;
  if (state.deactivated) return "deactivated";

  const consentIndex = await findByHash(log, entry.consent);
  const consentOp = consentIndex === -1 ? undefined : log[consentIndex];
  const consentNamesThisWard = consentOp?.type === "acceptWard" && consentOp.ward.did === wardDid && consentOp.ward.anchor === wardAnchor;
  const stillAWard = state.wards.some((w) => w.did === wardDid && w.anchor === wardAnchor);
  if (!consentNamesThisWard || !stillAWard) return "withdrawn";

  if (!skipKeysCheck && !sameKeys(state.keys, entry.keys)) return "keys out of date";
  return "mutual";
}

export type WardReportResult = "unavailable" | "different identity" | "guardian" | "successor" | "not related";

/** REQ-11-6: one ward record's own report, from the perspective of `thisDid` (the identity whose `wards` this record came from). */
export async function checkWardReport(
  thisDid: Did,
  record: WardRecord,
  resolveLog: LogResolver,
  implementedExtensions: ReadonlySet<string> = new Set(),
): Promise<WardReportResult> {
  const log = await resolveLog(record.did);
  if (!log) return "unavailable";
  const verified = await verifyLog(record.did, log, implementedExtensions);
  if (verified.result !== "valid") return "unavailable";

  const anchor = await anchorOf(log[0] as CreateOp);
  if (anchor !== record.anchor) return "different identity";

  const state = verified.state!;
  if (state.guardians.some((g) => g.did === thisDid)) return "guardian";
  if (state.successor?.did === thisDid) return "successor";
  return "not related";
}
