import { anchorOf, isSupportedOperationType, keyOfVerificationMethod, operationHash, verifyProofSignature } from "./operations.js";
import { checkMutuality, findByHash, sameKeys, type LogResolver } from "./resolve.js";
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

/**
 * REQ-10-7: every cross-log check made at acceptance, for the entries
 * and signers this specific candidate operation involves. `signers` is
 * every key with a valid proof on `candidate` (REQ-5-14/REQ-5-16) --
 * the same set `checkApprovals` already computed, reused here so this
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

  // "a guardian or successor approves an operation: its entry has standing" --
  // except item 3 (keys) for the one entry an updateGuardian is itself updating.
  const updatingGuardian = candidate.type === "updateGuardian" ? candidate.guardian : undefined;
  for (const entry of [...guardians, ...(successor ? [successor] : [])]) {
    const approves = entry.keys.some((k) => signers.has(k));
    if (!approves) continue;
    if (!(await hasStanding(wardDid, wardAnchor, entry, resolveLog, implementedExtensions, updatingGuardian))) {
      return reject(`REQ-10-7: ${entry.did}'s entry does not have standing`);
    }
  }

  switch (candidate.type) {
    case "create": {
      for (const entry of [...candidate.guardians, ...(candidate.successor ? [candidate.successor] : [])]) {
        if (!(await hasStanding(wardDid, wardAnchor, entry, resolveLog, implementedExtensions))) return reject(`REQ-10-7: the new entry for ${entry.did} does not have standing`);
      }
      return ACCEPT;
    }
    case "addGuardian": {
      if (!(await hasStanding(wardDid, wardAnchor, candidate.entry, resolveLog, implementedExtensions))) return reject(`REQ-10-7: the new entry for ${candidate.entry.did} does not have standing`);
      return ACCEPT;
    }
    case "setPolicy": {
      const successorChanged = candidate.successor !== null && candidate.successor.did !== successor?.did;
      if (candidate.successor !== null && successorChanged) {
        if (!(await hasStanding(wardDid, wardAnchor, candidate.successor, resolveLog, implementedExtensions))) return reject(`REQ-10-7: the new entry for ${candidate.successor.did} does not have standing`);
      }
      return ACCEPT;
    }
    case "updateGuardian": {
      const guardianLog = await resolveLog(candidate.guardian);
      if (!guardianLog) return reject("REQ-10-7: the guardian's log could not be retrieved");
      const guardianVerified = await verifyLog(candidate.guardian, guardianLog, implementedExtensions);
      if (guardianVerified.result !== "valid") return reject("REQ-10-7: the guardian's log does not verify");
      if (!sameKeys(candidate.keys, guardianVerified.state!.keys)) return reject("REQ-10-7: updateGuardian's new keys must equal the keys in the current state of guardian");
      return ACCEPT;
    }
    case "removeGuardian": {
      const removed = guardians.find((g) => g.did === candidate.guardian);
      if (candidate.evidence !== undefined && removed) {
        const guardianLog = await resolveLog(candidate.guardian);
        if (!guardianLog) return reject("REQ-10-7: the guardian's log could not be retrieved");
        const guardianVerified = await verifyLog(candidate.guardian, guardianLog, implementedExtensions);
        if (guardianVerified.result !== "valid") return reject("REQ-10-7: the guardian's log does not verify");
        const anchor = await anchorOf(guardianLog[0] as CreateOp);
        if (anchor !== removed.anchor) return reject("REQ-10-7: evidence -- the guardian's anchor does not match the entry");

        const evidenceIndex = await findByHash(guardianLog, candidate.evidence);
        const evidenceOp = evidenceIndex === -1 ? undefined : guardianLog[evidenceIndex];
        const isEvidenceType = evidenceOp?.type === "deactivate" || (evidenceOp?.type === "releaseWard" && evidenceOp.ward === wardDid);
        if (!isEvidenceType) return reject("REQ-10-7: evidence must be a deactivate, or a releaseWard whose ward is this identity");
        const consentIndex = await findByHash(guardianLog, removed.consent);
        if (consentIndex === -1 || evidenceIndex <= consentIndex) return reject("REQ-10-7: evidence must follow the entry's consent");

        const standing = await hasStanding(wardDid, wardAnchor, removed, resolveLog, implementedExtensions);
        if (standing) return reject("REQ-10-7: evidence is valid only once the entry's standing is already lost by deactivation or release");
      }
      const remainingGuardians = guardians.filter((g) => g.did !== candidate.guardian);
      const promotesSuccessor = remainingGuardians.length === 0 && successor !== null;
      if (promotesSuccessor && !(await hasStanding(wardDid, wardAnchor, successor, resolveLog, implementedExtensions))) {
        return reject(`REQ-10-7: the successor's entry for ${successor.did} does not have standing`);
      }
      return ACCEPT;
    }
    case "acceptWard": {
      const wardLog = await resolveLog(candidate.ward.did);
      if (wardLog) {
        const wardVerified = await verifyLog(candidate.ward.did, wardLog, implementedExtensions);
        if (wardVerified.result === "valid") {
          const actualAnchor = await anchorOf(wardLog[0] as CreateOp);
          if (actualAnchor !== candidate.ward.anchor) return reject("REQ-10-7: the ward record must name that DID's own current anchor");
        }
      }
      return ACCEPT;
    }
    default:
      return ACCEPT;
  }
}

/**
 * REQ-10-5: a registrar accepts an operation only if all three hold.
 * `candidate` must already be fully formed -- for a `create`, with its
 * `attestation` already added (REQ-10-9 is the caller's job, before
 * this: the registrar signs its own attestation and never needs to
 * verify its own signature here). `signers` is the set of keys with a
 * valid proof on `candidate` (REQ-5-16) -- callers that already ran
 * `verifyLog` on the appended log have this from `checkApprovals`'s own
 * work; this function does not re-verify signatures.
 */
export async function checkAcceptance(
  did: Did,
  existingLog: Log,
  candidate: Operation,
  resolveLog: LogResolver,
  implementedExtensions: ReadonlySet<string> = new Set(),
): Promise<AcceptResult> {
  if (!isSupportedOperationType(candidate.type)) return reject(`REQ-10-5: operation type "${candidate.type}" is not implemented`);

  // REQ-10-5 step 1.
  const currentVersion = existingLog.length > 0 ? await operationHash(existingLog[existingLog.length - 1]) : null;
  if (!(candidate.type === "create" && existingLog.length === 0)) {
    if ((candidate as { prev: string | null }).prev !== currentVersion) return reject("REQ-10-5: prev must equal the version of the log");
  }

  // REQ-10-5 step 2.
  const newLog = [...existingLog, candidate];
  const verified = await verifyLog(did, newLog, implementedExtensions);
  if (verified.result === "unsupported") return reject("REQ-10-5: an unsupported result is a rejection");
  if (verified.result !== "valid") return reject(`REQ-10-5: ${verified.reason}`);

  // REQ-10-9: a create's attestation must use the CURRENT version of the
  // root identity's log -- not merely a version that was once valid.
  // (REQ-10-9 names this as part of producing the attestation; checked
  // again here in case it is stale by the time this operation is
  // accepted, e.g. the root rotated in between.)
  if (candidate.type === "create" && candidate.attestation) {
    const m = /^(did:guardian:[^?#]+)\?versionId=([^#]+)#key-(0|[1-9][0-9]*)$/.exec(candidate.attestation.verificationMethod);
    if (m) {
      const rootLog = await resolveLog(m[1] as Did);
      if (rootLog && rootLog.length > 0) {
        const currentRootVersion = await operationHash(rootLog[rootLog.length - 1]);
        if (m[2] !== currentRootVersion) return reject("REQ-10-9: the attestation must use the current version of the root identity's log");
      }
    }
  }

  // REQ-10-5 step 3 (REQ-10-7).
  const stateBefore = existingLog.length > 0 ? (await verifyLog(did, existingLog, implementedExtensions)).state : undefined;
  const wardAnchor = await anchorOf((existingLog[0] ?? candidate) as CreateOp);
  const signers = await approvingKeys(candidate);
  const crossLog = await checkCrossLogRules(did, wardAnchor, stateBefore, candidate, signers, resolveLog, implementedExtensions);
  if (!crossLog.accepted) return crossLog;

  return ACCEPT;
}
