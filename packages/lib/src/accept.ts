import { anchorOf, isSupportedOperationType, keyOfVerificationMethod, operationHash, parseGuardianDid, sameEntry, verifyProofSignature } from "./operations.js";
import { makePinningResolver, type PinStore } from "./pin.js";
import { checkMutuality, findByHash, sameKeys, verifyAttestation, type LogResolver } from "./resolve.js";
import { checkApprovals, isSuccessorToNullWaiver, membershipApproved } from "./rules.js";
import { verifyLog } from "./verifyLog.js";
import type { CreateOp, Did, Entry, Key, Log, Operation, State } from "./types.js";

/** REQ-5-14/REQ-5-16: the keys with a valid proof on `op` -- assumes `op`'s own shape already passed REQ-5-10/5-11 (true of anything that reached here through `verifyLog`). */
async function approvingKeys(op: Operation): Promise<Set<Key>> {
  const keys = new Set<Key>();
  for (const proof of op.proof) {
    const key = keyOfVerificationMethod(proof.verificationMethod);
    if (key && (await verifyProofSignature(op, proof, key))) keys.add(key);
  }
  return keys;
}

export interface AcceptResult {
  accepted: boolean;
  reason?: string;
}

const reject = (reason: string): AcceptResult => ({ accepted: false, reason });
const ACCEPT: AcceptResult = { accepted: true };

/** REQ-10-6: an entry has standing for `wardDid`/`wardAnchor`. `skipKeysCheckFor`, when it names this same entry's DID, is REQ-10-7's own exception to item 3 for an `updateGuardian` of that entry. */
async function hasStanding(
  wardDid: Did,
  wardAnchor: string,
  entry: Entry,
  resolveLog: LogResolver,
  implementedExtensions: ReadonlySet<string>,
  skipKeysCheckFor?: Did,
): Promise<boolean> {
  const result = await checkMutuality(wardDid, wardAnchor, entry, resolveLog, skipKeysCheckFor === entry.did, implementedExtensions);
  return result === "mutual";
}

/** The path segment implied by a DID's own `<name>` (or `_` for a root identity), for REQ-10-5 item 1 and REQ-10-12. Returns undefined for a malformed DID -- callers that reach this with one have already failed elsewhere. */
function pathSegmentOf(did: Did): string | undefined {
  const parsed = parseGuardianDid(did);
  return parsed ? parsed.name ?? "_" : undefined;
}

/**
 * REQ-10-7 (r7/r7b): every cross-log check made at acceptance, for the
 * entries and signers this specific candidate operation involves --
 * the DIDs of its new entries; the guardians and successors whose
 * keys approve it; the `guardian` of a `removeGuardian` with
 * `evidence`; the successor in a promotion or in the
 * `successor`-to-`null` exception of REQ-7-6; and the `ward` of an
 * `acceptWard`. `resolveLog` is expected to already be REQ-10-15's own
 * pinning wrapper when the caller wants that (checkAcceptance builds
 * it); this function has no idea either way. `signers` is every key
 * with a valid proof on `candidate` (REQ-5-14/REQ-5-16) -- the same
 * set `checkApprovals` already computed once, reused here so this
 * never re-verifies a signature.
 */
async function checkCrossLogRules(
  wardDid: Did,
  wardAnchor: string,
  stateBefore: State | undefined,
  candidate: Operation,
  signers: Set<Key>,
  resolveLog: LogResolver,
  implementedExtensions: ReadonlySet<string>,
): Promise<AcceptResult> {
  const guardians = stateBefore?.guardians ?? [];
  const successor = stateBefore?.successor ?? null;
  const updatingGuardian = candidate.type === "updateGuardian" ? candidate.guardian : undefined;

  // Row 2's own prerequisite: which currently-approving guardians or
  // successors actually have standing right now. Built once, used both
  // to reduce the signer set REQ-7-6 is re-evaluated against (row 2)
  // and, for updateGuardian, to build the post-update entry row 1
  // checks against below.
  const withoutStanding = new Set<Key>();
  for (const entry of [...guardians, ...(successor ? [successor] : [])]) {
    const approves = entry.keys.some((k) => signers.has(k));
    if (!approves) continue;
    if (!(await hasStanding(wardDid, wardAnchor, entry, resolveLog, implementedExtensions, updatingGuardian))) {
      for (const k of entry.keys) withoutStanding.add(k);
    }
  }
  const standingSigners = new Set([...signers].filter((k) => !withoutStanding.has(k)));

  // Row 1: a create's own new entries, addGuardian's new entry,
  // updateGuardian's post-update entry, or setPolicy's changed
  // successor -- each must have standing. updateGuardian's own entry
  // is checked with its NEW keys already applied (not the stale ones
  // in `guardians`/`successor`), and with item 3 NOT skipped -- the
  // whole point of this row, for that operation, is confirming the new
  // keys genuinely match what the guardian's own current log says.
  switch (candidate.type) {
    case "create":
      for (const entry of [...candidate.guardians, ...(candidate.successor ? [candidate.successor] : [])]) {
        if (!(await hasStanding(wardDid, wardAnchor, entry, resolveLog, implementedExtensions))) return reject(`REQ-10-7: the new entry for ${entry.did} does not have standing`);
      }
      break;
    case "addGuardian":
      if (!(await hasStanding(wardDid, wardAnchor, candidate.entry, resolveLog, implementedExtensions))) return reject(`REQ-10-7: the new entry for ${candidate.entry.did} does not have standing`);
      break;
    case "updateGuardian": {
      const namedEntry = (successor?.did === candidate.guardian ? successor : guardians.find((g) => g.did === candidate.guardian)) as Entry;
      const updatedEntry: Entry = { ...namedEntry, keys: candidate.keys };
      if (!(await hasStanding(wardDid, wardAnchor, updatedEntry, resolveLog, implementedExtensions))) {
        return reject(`REQ-10-7: the updated entry for ${candidate.guardian} does not have standing`);
      }
      break;
    }
    case "setPolicy": {
      const successorChanged = candidate.successor !== null && !(successor && sameEntry(candidate.successor, successor));
      if (candidate.successor !== null && successorChanged) {
        if (!(await hasStanding(wardDid, wardAnchor, candidate.successor, resolveLog, implementedExtensions))) return reject(`REQ-10-7: the new entry for ${candidate.successor.did} does not have standing`);
      }
      break;
    }
  }

  // Row 2: every operation, not only ones a guardian or successor
  // approves -- REQ-7-6, re-evaluated counting only the approvals from
  // entries that still have standing right now. A create has no prior
  // state and nothing here to filter, so it's skipped as a pure
  // optimization (checkCreateApprovals never looks at stateBefore).
  if (stateBefore) {
    const reduced = checkApprovals(candidate, stateBefore, standingSigners);
    if (!reduced.valid) return reject(`REQ-10-7: ${reduced.reason} (counting only guardians/successors with standing)`);
  }

  switch (candidate.type) {
    case "removeGuardian": {
      const removed = guardians.find((g) => g.did === candidate.guardian) as Entry;

      // Row 3: evidence.
      if (candidate.evidence !== undefined) {
        const guardianLog = await resolveLog(candidate.guardian);
        if (!guardianLog) return reject("REQ-10-7: the guardian's log could not be retrieved");
        const guardianVerified = await verifyLog(candidate.guardian, guardianLog, implementedExtensions);
        if (guardianVerified.result !== "valid") return reject("REQ-10-7: the guardian's log does not verify");
        const anchor = await anchorOf(guardianLog[0] as CreateOp);
        if (anchor !== removed.anchor) return reject("REQ-10-7: evidence -- the guardian's anchor does not match the entry");

        const evidenceIndex = await findByHash(guardianLog, candidate.evidence);
        if (evidenceIndex === -1) return reject("REQ-10-7: evidence must name an operation in the guardian's log");
        const consentIndex = await findByHash(guardianLog, removed.consent);
        if (consentIndex === -1 || evidenceIndex <= consentIndex) return reject("REQ-10-7: evidence must follow the entry's consent");

        const evidenceOp = guardianLog[evidenceIndex];
        const isReleaseOfThisWard = evidenceOp.type === "releaseWard" && evidenceOp.ward === wardDid;
        const stateAfterEvidence = (await verifyLog(candidate.guardian, guardianLog.slice(0, evidenceIndex + 1), implementedExtensions)).state;
        const deactivatedAfterEvidence = stateAfterEvidence?.deactivated === true;
        if (!isReleaseOfThisWard && !deactivatedAfterEvidence) {
          return reject("REQ-10-7: evidence must be a releaseWard of this identity, or an operation after which the guardian's state is deactivated");
        }

        const state = guardianVerified.state!;
        const stillAWard = state.wards.some((w) => w.did === wardDid && w.anchor === wardAnchor);
        if (!state.deactivated && stillAWard) {
          return reject("REQ-10-7: items 2 and 5 of REQ-10-6 both still hold for the guardian -- evidence does not apply");
        }
      }

      // Row 4: promotion.
      const remainingGuardians = guardians.filter((g) => g.did !== candidate.guardian);
      const promotesSuccessor = remainingGuardians.length === 0 && successor !== null;
      if (promotesSuccessor && !(await hasStanding(wardDid, wardAnchor, successor, resolveLog, implementedExtensions))) {
        return reject(`REQ-10-7: the successor's entry for ${successor.did} does not have standing`);
      }
      break;
    }

    case "setPolicy": {
      // Row 5 (r7b, Z-1 fix): the successor-to-null waiver's own
      // registrar-side gate -- only relevant when the waiver was
      // actually needed (membership, counting only standing
      // approvals, would not otherwise be met), and requires PROVABLE
      // withdrawal or deactivation of the successor being dropped, the
      // same test as the evidence row -- "the successor merely lacks
      // standing for some other reason" (an unreachable log, a stale
      // key) is not enough on its own.
      if (guardians.length > 0 && stateBefore && isSuccessorToNullWaiver(candidate, stateBefore) && !membershipApproved(stateBefore, standingSigners)) {
        const successorEntry = successor as Entry;
        const succLog = await resolveLog(successorEntry.did);
        if (!succLog) return reject("REQ-10-7: the current successor's log could not be retrieved");
        const succVerified = await verifyLog(successorEntry.did, succLog, implementedExtensions);
        if (succVerified.result !== "valid") return reject("REQ-10-7: the current successor's log does not verify");
        const succAnchor = await anchorOf(succLog[0] as CreateOp);
        if (succAnchor !== successorEntry.anchor) return reject("REQ-10-7: the current successor's anchor does not match the entry");
        const succState = succVerified.state!;
        const stillAWard = succState.wards.some((w) => w.did === wardDid && w.anchor === wardAnchor);
        if (!succState.deactivated && stillAWard) {
          return reject("REQ-10-7: the current successor has neither deactivated nor released this identity -- items 2 and 5 of REQ-10-6 both still hold");
        }
      }
      break;
    }

    case "acceptWard": {
      // Row 6: a DID has no log only if its registrar reports that it
      // has none (`null`) -- an unfetchable log (`undefined`) is NOT
      // the same as "no log" and must still reject (Z-4: the pre-r7b
      // code silently skipped this check on any fetch failure at all).
      const wardLog = await resolveLog(candidate.ward.did);
      if (wardLog === undefined) return reject("REQ-10-7: the ward's log could not be retrieved");
      if (wardLog !== null) {
        const wardVerified = await verifyLog(candidate.ward.did, wardLog, implementedExtensions);
        if (wardVerified.result !== "valid") return reject("REQ-10-7: the ward's log does not verify");
        const actualAnchor = await anchorOf(wardLog[0] as CreateOp);
        if (actualAnchor !== candidate.ward.anchor) return reject("REQ-10-7: the ward record must name that DID's own current anchor");
      }
      break;
    }
  }

  return ACCEPT;
}

export interface RequestContext {
  /** The identity this request is authenticated as, or null for an anonymous one. */
  authenticatedAs: Did | null;
  /** Every identity whose registrar-held key produced a proof ON `candidate` for this request -- never counting `attestation`, which REQ-10-9 governs separately. */
  registrarProofs: Did[];
}

/**
 * REQ-10-13/REQ-10-14 (r7b): whether this registrar's own use of its
 * held keys, within the one request that produced `candidate`, stayed
 * inside the bounds those two requirements set. A held key may sign
 * for its own identity when the request is authenticated as it, or
 * for the `create` of that identity in the request that creates it --
 * nothing else. Returns a rejection reason, or undefined if every
 * registrar-held proof the request produced was allowed. `request`
 * omitted entirely means this isn't being checked (the pre-r7b
 * behavior, where this registrar's own signing discipline was trusted
 * rather than verified against an explicit record of what it did).
 */
export function checkHeldKeyUsage(did: Did, candidate: Operation, request: RequestContext | undefined): string | undefined {
  if (!request) return undefined;
  const allowed = new Set<Did>();
  if (request.authenticatedAs) allowed.add(request.authenticatedAs);
  if (candidate.type === "create") allowed.add(did);
  const extra = request.registrarProofs.filter((d) => !allowed.has(d));
  if (extra.length > 0) {
    return `REQ-10-13/REQ-10-14: this request produced registrar-held proofs for ${extra.join(", ")}, not allowed for a request authenticated as ${request.authenticatedAs ?? "no identity"}`;
  }
  return undefined;
}

/** Everything about this request a registrar needs to tell `checkAcceptance` beyond the operation itself -- all optional, and each one a no-op when omitted, so every pre-r7 caller keeps working unchanged. */
export interface RegistrarContext {
  /** REQ-10-5 item 1: the path segment the request actually targeted. Checked only for a `create` against an empty log; if omitted, item 1's segment clause is simply not checked (the pre-r7 behavior). */
  segment?: string;
  /** REQ-10-12: names for which this registrar has already ACCEPTED a `create`. A name here makes a new `create` for it rejected; a name this registrar only ever REJECTED creates for must not be passed here at all. */
  acceptedNames?: ReadonlySet<string>;
  /** REQ-10-15: where this registrar records {anchor, version} for every log it fetches under REQ-10-7. Omit it and REQ-10-7's fetches are unpinned, same as every pre-r7b caller. */
  pinStore?: PinStore;
  /** REQ-10-13/REQ-10-14: see `checkHeldKeyUsage`. Omit it and this isn't checked here at all. */
  request?: RequestContext;
}

/**
 * REQ-10-5: a registrar accepts an operation only if all three hold.
 * `candidate` must already be fully formed -- for a `create`, with its
 * `attestation` already added (REQ-10-9 is the caller's job, before
 * this: the registrar signs its own attestation and never needs to
 * verify its own signature here). `registrarContext` is everything
 * r7/r7b added that a bare log-and-operation pair can't express on its
 * own (REQ-10-5 item 1, REQ-10-12, REQ-10-15) -- entirely optional, see
 * `RegistrarContext`.
 */
export async function checkAcceptance(
  did: Did,
  existingLog: Log,
  candidate: Operation,
  resolveLog: LogResolver,
  implementedExtensions: ReadonlySet<string> = new Set(),
  registrarContext: RegistrarContext = {},
): Promise<AcceptResult> {
  if (!isSupportedOperationType(candidate.type)) return reject(`REQ-10-5: operation type "${candidate.type}" is not implemented`);

  const heldKeyIssue = checkHeldKeyUsage(did, candidate, registrarContext.request);
  if (heldKeyIssue) return reject(heldKeyIssue);

  const isNewCreate = candidate.type === "create" && existingLog.length === 0;

  // REQ-10-5 step 1, including item 1's r7 wording: "...or it is a
  // create whose did has the path segment of the request and that
  // path segment has no log."
  const currentVersion = existingLog.length > 0 ? await operationHash(existingLog[existingLog.length - 1]) : null;
  if (!isNewCreate) {
    if ((candidate as { prev: string | null }).prev !== currentVersion) return reject("REQ-10-5: prev must equal the version of the log");
  } else if (registrarContext.segment !== undefined && pathSegmentOf(did) !== registrarContext.segment) {
    return reject("REQ-10-5: a create's did must have the path segment of the request");
  }

  // REQ-10-12 (r7: only an ACCEPTED create uses up a name -- a
  // registrar that only ever rejected creates for a name must not
  // pass it here at all, so this is purely additive).
  if (isNewCreate && registrarContext.acceptedNames) {
    const segment = pathSegmentOf(did);
    if (segment !== undefined && registrarContext.acceptedNames.has(segment)) return reject("REQ-10-12: a create was already accepted for this name");
  }

  // REQ-10-5 step 2.
  const newLog = [...existingLog, candidate];
  const verified = await verifyLog(did, newLog, implementedExtensions);
  if (verified.result === "unsupported") return reject("REQ-10-5: an unsupported result is a rejection");
  if (verified.result !== "valid") return reject(`REQ-10-5: ${verified.reason}`);

  // REQ-10-9/REQ-10-10 (F-11, audit): two distinct requirements, both
  // needed -- neither alone is REQ-10-9's "using ... the CURRENT
  // version of the root identity's log". This is not one of REQ-10-7's
  // own rows, so it stays on the raw `resolveLog`, never the REQ-10-15
  // pinning wrapper built below.
  //
  // 1. The attestation must still be genuinely valid right now: its
  //    own signature verifies, the root isn't deactivated, the key
  //    index exists. verifyAttestation (resolve.ts) is the real,
  //    complete check for this (REQ-11-2); it also covers REQ-10-10
  //    (the root must exist first), since a missing/empty root log is
  //    "invalid" there.
  //
  // 2. The versionId must still be the root's CURRENT head, not
  //    merely some version that was once (and may still be) genuinely
  //    valid -- an attestation signed just before the root rotates
  //    must not go on being accepted afterward.
  if (candidate.type === "create" && candidate.attestation) {
    const attestationResult = await verifyAttestation(candidate, resolveLog, implementedExtensions);
    if (attestationResult === "unsupported") return reject("REQ-10-9: the attestation's cryptosuite is not implemented");
    if (attestationResult !== "valid") return reject("REQ-10-9/REQ-10-10: the attestation does not verify");

    const m = /^(did:guardian:[^?#]+)\?versionId=([^#]+)#key-(0|[1-9][0-9]*)$/.exec(candidate.attestation.verificationMethod);
    const rootLog = m ? await resolveLog(m[1] as Did) : undefined;
    if (!rootLog || rootLog.length === 0) return reject("REQ-10-10: the root identity does not exist");
    const currentRootVersion = await operationHash(rootLog[rootLog.length - 1]);
    if (m![2] !== currentRootVersion) return reject("REQ-10-9: the attestation must use the current version of the root identity's log");
  }

  // REQ-10-5 step 3 (REQ-10-7), through REQ-10-15's own pinning
  // wrapper when a store was given -- every fetch REQ-10-7 makes below
  // goes through it, recorded whatever this operation's own outcome
  // turns out to be.
  const stateBefore = existingLog.length > 0 ? (await verifyLog(did, existingLog, implementedExtensions)).state : undefined;
  const wardAnchor = await anchorOf((existingLog[0] ?? candidate) as CreateOp);
  const signers = await approvingKeys(candidate);
  const pinnedResolveLog = registrarContext.pinStore ? makePinningResolver(resolveLog, registrarContext.pinStore) : resolveLog;
  const crossLog = await checkCrossLogRules(did, wardAnchor, stateBefore, candidate, signers, pinnedResolveLog, implementedExtensions);
  if (!crossLog.accepted) return crossLog;

  return ACCEPT;
}
