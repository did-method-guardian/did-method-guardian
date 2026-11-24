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
  // F-12 (audit): this used to do only structural splitting (segment
  // count), never REQ-4-2/REQ-4-3's own character-class validation of
  // `domain`/`name` -- callers build request URLs and redirect
  // targets straight from this function's output (registrar-client.ts,
  // oidc.ts, several CLI commands), so an unvalidated segment (a
  // stray "/", "..", "#", control characters) could land in a URL.
  // parseGuardianDid (operations.ts) is the real, already-validating
  // parser; this is now a thin, throwing wrapper around it.
  const parsed = parseGuardianDid(did);
  if (!parsed) throw new Error(`not a valid did:guardian identifier: ${did}`);
  return { name: parsed.name, domain: parsed.domain };
}

/** `name: null` resolves to the reserved `_` segment -- the bare-domain identity's own well-known path (spec §2.1/§5), never a real registration (the name ABNF forbids `_`). */
export function wellKnownPath(name: string | null): string {
  return `/.well-known/guardian/${name ?? "_"}`;
}

/**
 * Fetches the current log of `did` -- live resolution for REQ-5-14's
 * cross-log checks (REQ-10-7), and for the resolution functions below.
 * `undefined` means the log could not be fetched. `null` means the
 * registrar affirmatively reports that `did` has no log at all --
 * distinct from `undefined`, and relevant only to REQ-10-7's
 * `acceptWard` row ("a DID has no log only if its registrar reports
 * that it has none"); every other caller here treats both the same
 * way (falsy), since neither "no log" nor "couldn't fetch it" lets a
 * resolver establish anything about that identity.
 */
export type LogResolver = (did: Did) => Log | null | undefined | Promise<Log | null | undefined>;

export type Outcome = "valid" | "invalid" | "unsupported";

/**
 * REQ-5-6 compares hashes, never raw content, so a log that has not
 * been through `verifyLog` yet (every caller here) can contain an
 * operation that is not even JCS-safe -- `operationHash` throws on
 * that, which must never silently abort the whole scan (audit r4,
 * Z-2): a malformed operation is simply never a match, and scanning
 * continues past it, since a later, well-formed operation might
 * still be the one actually being searched for.
 */
export async function findByHash(log: Log, hash: string): Promise<number> {
  for (let i = 0; i < log.length; i++) {
    try {
      if ((await operationHash(log[i])) === hash) return i;
    } catch {
      // not a match -- keep scanning.
    }
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
  // rootLog comes from resolveLog -- another party's own log, fetched
  // over the network for a registrar, never something this function
  // already validated. findByHash itself never throws on a malformed
  // entry (not even JCS-safe content, say) -- it just never matches
  // one -- so this is a plain -1 check, not a try/catch.
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

/** REQ-11-3's own recorded {anchor, version} for the DID being resolved -- see pin.ts's PinRecord, which this mirrors; resolve() only ever needs the one for `did` itself (README: "only the pin for did is used"), never a whole store. */
export interface ResolvePin {
  anchor: string;
  version: string;
}

/**
 * REQ-11-4 against a previously recorded pin, for REQ-11-9's benefit.
 *
 * Audit r4 (Z-2): checking only "is the recorded version's hash
 * present somewhere in this log" is not enough -- an attacker who
 * forks right after the anchor can append the honestly-signed,
 * actually-pinned operation AFTER the fork, purely so its hash is
 * still found somewhere, while resolving with a `versionId` that
 * truncates the effective log back to the fork before that pinned
 * operation is ever reached. REQ-11-4 (r7d) now requires verifying
 * the log from its first operation through whichever of the recorded
 * version or the `versionId` operation comes LATER in the log --
 * which the fork itself fails (its forked operation's own `prev`
 * never chains to the pinned one two slots further on), reported
 * correctly as rolled back or forked instead of silently resolving
 * through the fork to the attacker's own key.
 *
 * `log` has not been through `verifyLog` yet at this point, so a
 * malformed `log[0]` could throw out of `anchorOf` -- treated as
 * rolled back or forked (a log that cannot even be checked against
 * the recorded pin is never treated as matching it). `findByHash`
 * itself never throws (a malformed operation anywhere else in the
 * scan is simply never a match, continuing the scan) -- so a pinned
 * version this can't find by hashing counts as "the recorded version
 * is absent," not as "no report at all."
 */
async function pinReport(
  did: Did,
  log: Log,
  pin: ResolvePin | undefined,
  versionId: string | undefined,
  implementedExtensions: ReadonlySet<string>,
): Promise<"different identity" | "rolled back or forked" | undefined> {
  if (!pin || log.length === 0) return undefined;
  let anchor: string;
  try {
    anchor = await anchorOf(log[0] as CreateOp);
  } catch {
    return "rolled back or forked";
  }
  if (anchor !== pin.anchor) return "different identity";

  const pinnedIndex = await findByHash(log, pin.version);
  if (pinnedIndex === -1) return "rolled back or forked";
  const versionIdIndex = versionId !== undefined ? await findByHash(log, versionId) : -1;
  const throughIndex = Math.max(pinnedIndex, versionIdIndex);

  const verified = await verifyLog(did, log.slice(0, throughIndex + 1), implementedExtensions);
  return verified.result === "valid" ? undefined : "rolled back or forked";
}

/**
 * REQ-11-1: resolves a DID to its document. `implementedExtensions`
 * defaults to empty, same as `verifyLog`. REQ-9-5: `versionId`, if
 * given, is the operation hash of some operation in `log` -- the
 * document is derived from the state right after that operation
 * instead of the log's own current end, and only the log up to and
 * including it needs to verify (a later operation, if any, is never
 * looked at at all, not even for shape). `pin`, if given, is this
 * same DID's own previously recorded anchor/version (REQ-11-3) -- a
 * mismatch is REQ-11-9's own "no DID document," checked against the
 * log exactly as given, before `versionId` ever narrows it.
 */
export async function resolve(
  did: Did,
  log: Log,
  resolveLog: LogResolver,
  implementedExtensions: ReadonlySet<string> = new Set(),
  versionId?: string,
  pin?: ResolvePin,
): Promise<ResolveResult> {
  const report = await pinReport(did, log, pin, versionId, implementedExtensions);
  if (report) return { result: "invalid", reason: `REQ-11-9: REQ-11-4 reports ${report} for this DID -- no DID document` };

  let effectiveLog = log;
  if (versionId !== undefined) {
    // findByHash itself never throws on a malformed entry elsewhere in
    // the log -- it is simply never a match -- so this is a plain -1
    // check, not a try/catch.
    const index = await findByHash(log, versionId);
    if (index === -1) return { result: "invalid", reason: `REQ-9-5: no operation with hash ${versionId} in this log` };
    effectiveLog = log.slice(0, index + 1);
  }

  const verified = await verifyLog(did, effectiveLog, implementedExtensions);
  if (verified.result !== "valid") return { result: verified.result, reason: verified.reason };

  const domain = parseGuardianDid(did)!.domain;
  const isRoot = did === `did:guardian:${domain}`;
  if (!isRoot) {
    const attestationResult = await verifyAttestation(effectiveLog[0] as CreateOp, resolveLog, implementedExtensions);
    if (attestationResult !== "valid") return { result: attestationResult };
  }

  const state = verified.state!;
  const version = await operationHash(effectiveLog[effectiveLog.length - 1]);
  const anchor = await anchorOf(effectiveLog[0] as CreateOp);
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
