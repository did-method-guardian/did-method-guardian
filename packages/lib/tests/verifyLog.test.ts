import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createProof,
  didReferenceVerificationMethod,
  generateKeypair,
  keyReferenceVerificationMethod,
  operationHash,
  unsecuredDocument,
  verifyLog,
} from "../src/index.js";
import type { CreateOp, DeactivateOp, Did, Keypair, Log, LogResolver, UpdateOp } from "../src/index.js";

const DOMAIN = "example.com";
const ROOT_DID = `did:guardian:${DOMAIN}`;

/** A small fixture world: a root identity, a guardian (bob), and a ward (alice) with bob as her only guardian. */
async function buildWorld() {
  const rootKey = await generateKeypair();
  const bobKey = await generateKeypair();
  const aliceKey = await generateKeypair();
  const bobDid: Did = `did:guardian:${DOMAIN}:bob`;
  const aliceDid: Did = `did:guardian:${DOMAIN}:alice`;

  const rootCreate: Omit<CreateOp, "proof"> = { type: "create", did: ROOT_DID, keys: [rootKey.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
  const rootPop = await createProof(unsecuredDocument(rootCreate), keyReferenceVerificationMethod(rootKey.publicKey), rootKey.privateKey);
  const rootOp: CreateOp = { ...rootCreate, proof: [rootPop] };
  const rootLog: Log = [rootOp];
  const rootHash = await operationHash(rootOp);

  const bobCreate: Omit<CreateOp, "proof"> = { type: "create", did: bobDid, keys: [bobKey.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
  const bobPop = await createProof(unsecuredDocument(bobCreate), keyReferenceVerificationMethod(bobKey.publicKey), bobKey.privateKey);
  const bobAttestation = await createProof(unsecuredDocument(bobCreate), didReferenceVerificationMethod(ROOT_DID, rootHash, 0), rootKey.privateKey);
  const bobOp: CreateOp = { ...bobCreate, proof: [bobPop, bobAttestation] };
  const bobLog: Log = [bobOp];
  const bobHash = await operationHash(bobOp);

  const aliceCreate: Omit<CreateOp, "proof"> = { type: "create", did: aliceDid, keys: [aliceKey.publicKey], guardians: [bobDid], policy: {}, services: [], alsoKnownAs: [], prev: null };
  const alicePop = await createProof(unsecuredDocument(aliceCreate), keyReferenceVerificationMethod(aliceKey.publicKey), aliceKey.privateKey);
  const bobConsent = await createProof(unsecuredDocument(aliceCreate), didReferenceVerificationMethod(bobDid, bobHash, 0), bobKey.privateKey);
  const rootAttestation = await createProof(unsecuredDocument(aliceCreate), didReferenceVerificationMethod(ROOT_DID, rootHash, 0), rootKey.privateKey);
  const aliceOp: CreateOp = { ...aliceCreate, proof: [alicePop, bobConsent, rootAttestation] };
  const aliceLog: Log = [aliceOp];

  const logs = new Map<Did, Log>([[ROOT_DID, rootLog], [bobDid, bobLog], [aliceDid, aliceLog]]);
  const resolveLog: LogResolver = (did) => logs.get(did);

  return { rootKey, bobKey, aliceKey, bobDid, aliceDid, rootOp, bobOp, aliceOp, bobHash, logs, resolveLog };
}

test("REQ-8-1: a minimal, self-contained root log verifies", async () => {
  const { rootOp, resolveLog } = await buildWorld();
  const result = await verifyLog(ROOT_DID, [rootOp], resolveLog);
  assert.equal(result.valid, true, result.reason);
});

test("REQ-7-4/REQ-8-1: a guardian-attested create verifies", async () => {
  const { aliceDid, aliceOp, resolveLog } = await buildWorld();
  const result = await verifyLog(aliceDid, [aliceOp], resolveLog);
  assert.equal(result.valid, true, result.reason);
});

test("REQ-7-4: update via guardian recovery (one guardian, recovery defaults to majority -> 1) verifies", async () => {
  const { aliceDid, aliceOp, bobDid, bobKey, bobHash, logs, resolveLog } = await buildWorld();
  const newKey = await generateKeypair();
  const aliceHash = await operationHash(aliceOp);
  const partial: Omit<UpdateOp, "proof"> = { type: "update", keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: aliceHash };
  const pop = await createProof(unsecuredDocument(partial), keyReferenceVerificationMethod(newKey.publicKey), newKey.privateKey);
  const guardianApproval = await createProof(unsecuredDocument(partial), didReferenceVerificationMethod(bobDid, bobHash, 0), bobKey.privateKey);
  const updateOp: UpdateOp = { ...partial, proof: [pop, guardianApproval] };

  logs.set(aliceDid, [aliceOp, updateOp]);
  const result = await verifyLog(aliceDid, [aliceOp, updateOp], resolveLog);
  assert.equal(result.valid, true, result.reason);
  assert.deepEqual(result.state?.keys, [newKey.publicKey]);
});

test("REQ-7-4: update with no approving signer at all is rejected", async () => {
  const { aliceDid, aliceOp, resolveLog } = await buildWorld();
  const newKey = await generateKeypair();
  const aliceHash = await operationHash(aliceOp);
  const partial: Omit<UpdateOp, "proof"> = { type: "update", keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: aliceHash };
  const pop = await createProof(unsecuredDocument(partial), keyReferenceVerificationMethod(newKey.publicKey), newKey.privateKey);
  const updateOp: UpdateOp = { ...partial, proof: [pop] };

  const result = await verifyLog(aliceDid, [aliceOp, updateOp], resolveLog);
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-7-4/);
});

test("REQ-5-13/REQ-5-14: a tampered signature is rejected", async () => {
  const { aliceDid, aliceOp, bobDid, bobKey, bobHash, resolveLog } = await buildWorld();
  const newKey = await generateKeypair();
  const aliceHash = await operationHash(aliceOp);
  const partial: Omit<UpdateOp, "proof"> = { type: "update", keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: aliceHash };
  const pop = await createProof(unsecuredDocument(partial), keyReferenceVerificationMethod(newKey.publicKey), newKey.privateKey);
  const guardianApproval = await createProof(unsecuredDocument(partial), didReferenceVerificationMethod(bobDid, bobHash, 0), bobKey.privateKey);
  const tampered = { ...guardianApproval, proofValue: guardianApproval.proofValue.slice(0, -4) + "AAAA" };
  const updateOp: UpdateOp = { ...partial, proof: [pop, tampered] };

  const result = await verifyLog(aliceDid, [aliceOp, updateOp], resolveLog);
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-5-14/);
});

test("REQ-8-1 step 4: no operation may follow a deactivate", async () => {
  const { aliceDid, aliceOp, bobDid, bobKey, bobHash, aliceKey, resolveLog } = await buildWorld();
  const aliceHash = await operationHash(aliceOp);
  const deactivatePartial: Omit<DeactivateOp, "proof"> = { type: "deactivate", prev: aliceHash };
  const keyProof = await createProof(unsecuredDocument(deactivatePartial), keyReferenceVerificationMethod(aliceKey.publicKey), aliceKey.privateKey);
  const guardianProof = await createProof(unsecuredDocument(deactivatePartial), didReferenceVerificationMethod(bobDid, bobHash, 0), bobKey.privateKey);
  const deactivateOp: DeactivateOp = { ...deactivatePartial, proof: [keyProof, guardianProof] };
  const deactivateHash = await operationHash(deactivateOp);

  const confirmResult = await verifyLog(aliceDid, [aliceOp, deactivateOp], resolveLog);
  assert.equal(confirmResult.valid, true, confirmResult.reason);

  const newKey = await generateKeypair();
  const afterPartial: Omit<UpdateOp, "proof"> = { type: "update", keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: deactivateHash };
  const afterPop = await createProof(unsecuredDocument(afterPartial), keyReferenceVerificationMethod(newKey.publicKey), newKey.privateKey);
  const afterOp: UpdateOp = { ...afterPartial, proof: [afterPop] };

  const result = await verifyLog(aliceDid, [aliceOp, deactivateOp, afterOp], resolveLog);
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-8-1/);
});

test("REQ-8-4: an unreachable referenced log is reported as not verified", async () => {
  const { aliceDid, aliceOp, bobDid, bobKey, bobHash } = await buildWorld();
  const newKey = await generateKeypair();
  const aliceHash = await operationHash(aliceOp);
  const partial: Omit<UpdateOp, "proof"> = { type: "update", keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: aliceHash };
  const pop = await createProof(unsecuredDocument(partial), keyReferenceVerificationMethod(newKey.publicKey), newKey.privateKey);
  const guardianApproval = await createProof(unsecuredDocument(partial), didReferenceVerificationMethod(bobDid, bobHash, 0), bobKey.privateKey);
  const updateOp: UpdateOp = { ...partial, proof: [pop, guardianApproval] };

  const unreachableResolver: LogResolver = () => undefined;
  const result = await verifyLog(aliceDid, [aliceOp, updateOp], unreachableResolver);
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-8-4/);
});

test("REQ-6-3: a create naming itself as a guardian is rejected", async () => {
  const key: Keypair = await generateKeypair();
  const did: Did = `did:guardian:${DOMAIN}:selfref`;
  const partial: Omit<CreateOp, "proof"> = { type: "create", did, keys: [key.publicKey], guardians: [did], policy: {}, services: [], alsoKnownAs: [], prev: null };
  const pop = await createProof(unsecuredDocument(partial), keyReferenceVerificationMethod(key.publicKey), key.privateKey);
  const op: CreateOp = { ...partial, proof: [pop] };
  const result = await verifyLog(did, [op], () => undefined);
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-6-3/);
});
