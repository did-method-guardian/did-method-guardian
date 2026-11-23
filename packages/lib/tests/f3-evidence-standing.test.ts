// F-3 (audit, MEDIUM): REQ-10-7 row 4 allows evidence-based removal
// only when the entry's standing was lost because of REQ-10-6 item 2
// (deactivated) or item 5 (no longer a ward) -- not for any reason at
// all. A guardian that released, then genuinely re-consented, then
// separately rotated its keys has lost standing via item 3 (keys out
// of date); the stale releaseWard from before the re-consent must not
// work as "evidence" for that.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkAcceptance, createProof, DEFAULT_POLICY, generateKeypair, operationHash, anchorOf } from "../src/index.js";
import type { AcceptWardOp, CreateOp, Did, Entry, Key, Log, LogResolver, ReleaseWardOp, RemoveGuardianOp, UpdateOp } from "../src/index.js";

// Both bare-domain (root) identities, on different domains -- a root
// create needs no attestation (REQ-7-7), which keeps this test
// self-contained without also having to build a real attestation
// chain for either side.
const WARD_DID = "did:guardian:ward.example" as Did;
const GUARDIAN_DID = "did:guardian:guardian.example" as Did;

interface Scenario {
  wardLog: Log;
  guardianLog: Log;
  staleReleaseHash: string;
  wardKey: { publicKey: Key; privateKey: string };
}

async function buildScenario(): Promise<Scenario> {
  const wardKey = await generateKeypair();
  const wardCreateBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did: WARD_DID,
    keys: [wardKey.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const wardCreateProof = await createProof(wardCreateBase, wardKey.publicKey, wardKey.privateKey);
  const wardCreateOp: CreateOp = { ...wardCreateBase, proof: [wardCreateProof] };
  const wardAnchor = await anchorOf(wardCreateOp);

  const guardianKey1 = await generateKeypair();
  const guardianCreateBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did: GUARDIAN_DID,
    keys: [guardianKey1.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const guardianCreateProof = await createProof(guardianCreateBase, guardianKey1.publicKey, guardianKey1.privateKey);
  const guardianCreateOp: CreateOp = { ...guardianCreateBase, proof: [guardianCreateProof] };
  const guardianAnchor = await anchorOf(guardianCreateOp);

  // acceptWard #1 -- the original consent the ward's own entry.consent will point at.
  const accept1Base: Omit<AcceptWardOp, "proof"> = { type: "acceptWard", ward: { did: WARD_DID, anchor: wardAnchor }, prev: await operationHash(guardianCreateOp) };
  const accept1Proof = await createProof(accept1Base, guardianKey1.publicKey, guardianKey1.privateKey);
  const accept1Op: AcceptWardOp = { ...accept1Base, proof: [accept1Proof] };
  const consentHash = await operationHash(accept1Op);

  // The ward's own log: create, then addGuardian naming bob's entry (consent = accept1's own hash).
  const entry: Entry = { did: GUARDIAN_DID, anchor: guardianAnchor, keys: [guardianKey1.publicKey], consent: consentHash };
  const addGuardianBase = { type: "addGuardian" as const, entry, prev: await operationHash(wardCreateOp) };
  const addGuardianProof1 = await createProof(addGuardianBase, guardianKey1.publicKey, guardianKey1.privateKey); // every key in entry
  const addGuardianProof2 = await createProof(addGuardianBase, wardKey.publicKey, wardKey.privateKey); // one current key
  const addGuardianOp = { ...addGuardianBase, proof: [addGuardianProof1, addGuardianProof2].sort((a, b) => (a.verificationMethod < b.verificationMethod ? -1 : 1)) };
  const wardLog: Log = [wardCreateOp, addGuardianOp];

  // releaseWard -- the guardian withdraws. THIS becomes stale "evidence."
  const releaseBase: Omit<ReleaseWardOp, "proof"> = { type: "releaseWard", ward: WARD_DID, prev: await operationHash(accept1Op) };
  const releaseProof = await createProof(releaseBase, guardianKey1.publicKey, guardianKey1.privateKey);
  const releaseOp: ReleaseWardOp = { ...releaseBase, proof: [releaseProof] };
  const staleReleaseHash = await operationHash(releaseOp);

  // acceptWard #2 -- a genuine re-consent, after the release above.
  const accept2Base: Omit<AcceptWardOp, "proof"> = { type: "acceptWard", ward: { did: WARD_DID, anchor: wardAnchor }, prev: await operationHash(releaseOp) };
  const accept2Proof = await createProof(accept2Base, guardianKey1.publicKey, guardianKey1.privateKey);
  const accept2Op: AcceptWardOp = { ...accept2Base, proof: [accept2Proof] };

  // update -- the guardian separately rotates its own key afterward.
  const guardianKey2 = await generateKeypair();
  const updateBase: Omit<UpdateOp, "proof"> = { type: "update", keys: [guardianKey2.publicKey], services: [], alsoKnownAs: [], prev: await operationHash(accept2Op) };
  const updateProofNew = await createProof(updateBase, guardianKey2.publicKey, guardianKey2.privateKey);
  const updateProofOld = await createProof(updateBase, guardianKey1.publicKey, guardianKey1.privateKey);
  const updateOp: UpdateOp = { ...updateBase, proof: [updateProofNew, updateProofOld].sort((a, b) => (a.verificationMethod < b.verificationMethod ? -1 : 1)) };

  const guardianLog: Log = [guardianCreateOp, accept1Op, releaseOp, accept2Op, updateOp];
  return { wardLog, guardianLog, staleReleaseHash, wardKey };
}

test("F-3: a stale releaseWard is not valid evidence once the guardian has genuinely re-consented and is a current ward of record (even though its keys have since rotated)", async () => {
  const { wardLog, guardianLog, staleReleaseHash, wardKey } = await buildScenario();
  const resolveLog: LogResolver = async (did) => (did === GUARDIAN_DID ? guardianLog : undefined);

  const removeBase: Omit<RemoveGuardianOp, "proof"> = {
    type: "removeGuardian",
    guardian: GUARDIAN_DID,
    evidence: staleReleaseHash,
    prev: await operationHash(wardLog[wardLog.length - 1]),
  };
  const removeProof = await createProof(removeBase, wardKey.publicKey, wardKey.privateKey);
  const removeOp: RemoveGuardianOp = { ...removeBase, proof: [removeProof] };

  const result = await checkAcceptance(WARD_DID, wardLog, removeOp, resolveLog);
  assert.equal(result.accepted, false, "stale release-then-re-consent evidence must not justify removal once the guardian is a current ward of record");
});

test("F-3 (sanity): a releaseWard that is still current (no re-consent afterward) IS valid evidence", async () => {
  const { wardLog, wardKey } = await buildScenario();

  // A fresh, independent scenario where the guardian releases and
  // never re-consents -- this is the genuinely-valid case the fix
  // must not break.
  const wardCreateOp = wardLog[0] as CreateOp;
  const guardianKey1 = await generateKeypair();
  const guardianCreateBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did: GUARDIAN_DID,
    keys: [guardianKey1.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const guardianCreateProof = await createProof(guardianCreateBase, guardianKey1.publicKey, guardianKey1.privateKey);
  const guardianCreateOp: CreateOp = { ...guardianCreateBase, proof: [guardianCreateProof] };
  const guardianAnchor = await anchorOf(guardianCreateOp);
  const wardAnchor = await anchorOf(wardCreateOp);

  const acceptBase: Omit<AcceptWardOp, "proof"> = { type: "acceptWard", ward: { did: WARD_DID, anchor: wardAnchor }, prev: await operationHash(guardianCreateOp) };
  const acceptProof = await createProof(acceptBase, guardianKey1.publicKey, guardianKey1.privateKey);
  const acceptOp: AcceptWardOp = { ...acceptBase, proof: [acceptProof] };
  const consentHash = await operationHash(acceptOp);

  const entry: Entry = { did: GUARDIAN_DID, anchor: guardianAnchor, keys: [guardianKey1.publicKey], consent: consentHash };
  const addGuardianBase = { type: "addGuardian" as const, entry, prev: await operationHash(wardCreateOp) };
  const addGuardianProof1 = await createProof(addGuardianBase, guardianKey1.publicKey, guardianKey1.privateKey);
  const addGuardianProof2 = await createProof(addGuardianBase, wardKey.publicKey, wardKey.privateKey);
  const addGuardianOp = { ...addGuardianBase, proof: [addGuardianProof1, addGuardianProof2].sort((a, b) => (a.verificationMethod < b.verificationMethod ? -1 : 1)) };
  const freshWardLog: Log = [wardCreateOp, addGuardianOp];

  const releaseBase: Omit<ReleaseWardOp, "proof"> = { type: "releaseWard", ward: WARD_DID, prev: await operationHash(acceptOp) };
  const releaseProof = await createProof(releaseBase, guardianKey1.publicKey, guardianKey1.privateKey);
  const releaseOp: ReleaseWardOp = { ...releaseBase, proof: [releaseProof] };
  const releaseHash = await operationHash(releaseOp);
  const freshGuardianLog: Log = [guardianCreateOp, acceptOp, releaseOp];
  const resolveLog: LogResolver = async (did) => (did === GUARDIAN_DID ? freshGuardianLog : undefined);

  const removeBase: Omit<RemoveGuardianOp, "proof"> = {
    type: "removeGuardian",
    guardian: GUARDIAN_DID,
    evidence: releaseHash,
    prev: await operationHash(freshWardLog[freshWardLog.length - 1]),
  };
  const removeProof = await createProof(removeBase, wardKey.publicKey, wardKey.privateKey);
  const removeOp: RemoveGuardianOp = { ...removeBase, proof: [removeProof] };

  const result = await checkAcceptance(WARD_DID, freshWardLog, removeOp, resolveLog);
  assert.equal(result.accepted, true, `a genuinely still-released guardian must still be removable with evidence (reason: ${result.reason})`);
});
