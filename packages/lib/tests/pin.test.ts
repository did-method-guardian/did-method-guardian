// REQ-11-3/REQ-11-4 (audit F-14/thoward-59's design note): checkPin,
// a pluggable-store rollback/fork detector any resolver (CLI today,
// a registrar later if the pending REQ-10-15 amendment lands) can
// reuse without its own comparison logic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkPin, createProof, DEFAULT_POLICY, generateKeypair, operationHash, type CreateOp, type Did, type Log, type PinRecord, type PinStore, type UpdateOp } from "../src/index.js";

async function buildLog(): Promise<Log> {
  const key1 = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did: "did:guardian:example.com" as Did,
    keys: [key1.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const createProof1 = await createProof(createBase, key1.publicKey, key1.privateKey);
  const createOp: CreateOp = { ...createBase, proof: [createProof1] };

  const key2 = await generateKeypair();
  const updateBase: Omit<UpdateOp, "proof"> = {
    type: "update",
    keys: [key2.publicKey],
    services: [],
    alsoKnownAs: [],
    prev: await operationHash(createOp),
  };
  const newKeyProof = await createProof(updateBase, key2.publicKey, key2.privateKey);
  const oldKeyProof = await createProof(updateBase, key1.publicKey, key1.privateKey);
  const updateOp: UpdateOp = { ...updateBase, proof: [newKeyProof, oldKeyProof].sort((a, b) => (a.verificationMethod < b.verificationMethod ? -1 : 1)) };

  return [createOp, updateOp];
}

function memoryStore(): PinStore & { records: Map<Did, PinRecord> } {
  const records = new Map<Did, PinRecord>();
  return {
    records,
    get: (did) => records.get(did),
    set: (did, record) => {
      records.set(did, record);
    },
  };
}

test("checkPin: a never-before-seen DID is 'new', and advance() records it", async () => {
  const log = await buildLog();
  const store = memoryStore();
  const result = await checkPin("did:guardian:example.com" as Did, log, store);
  assert.equal(result.status, "new");
  assert.equal(result.recorded, undefined);
  await result.advance();
  assert.deepEqual(store.records.get("did:guardian:example.com" as Did), result.current);
});

test("checkPin: the same log fetched again, with nothing new, is 'same-identity'", async () => {
  const log = await buildLog();
  const store = memoryStore();
  await (await checkPin("did:guardian:example.com" as Did, log, store)).advance();
  const second = await checkPin("did:guardian:example.com" as Did, log, store);
  assert.equal(second.status, "same-identity");
});

test("checkPin: the log growing (a later operation added) is still 'same-identity' -- the recorded version just needs to still be present", async () => {
  const log = await buildLog();
  const store = memoryStore();
  // Pin after only the create.
  await (await checkPin("did:guardian:example.com" as Did, [log[0]], store)).advance();
  // Fetch again later, now with the update appended too.
  const grown = await checkPin("did:guardian:example.com" as Did, log, store);
  assert.equal(grown.status, "same-identity");
});

test("checkPin: a different anchor (a different identity entirely) is 'different-identity'", async () => {
  const log = await buildLog();
  const store = memoryStore();
  await (await checkPin("did:guardian:example.com" as Did, log, store)).advance();

  const otherLog = await buildLog(); // a fresh create -- a different anchor
  const result = await checkPin("did:guardian:example.com" as Did, otherLog, store);
  assert.equal(result.status, "different-identity");
});

test("checkPin: a log that no longer contains the previously recorded version is 'rolled-back-or-forked'", async () => {
  const log = await buildLog();
  const store = memoryStore();
  await (await checkPin("did:guardian:example.com" as Did, log, store)).advance(); // pins at the update

  // A rollback: the fetched log now has only the create.
  const rolledBack = await checkPin("did:guardian:example.com" as Did, [log[0]], store);
  assert.equal(rolledBack.status, "rolled-back-or-forked");
});

test("checkPin: advance() is callable even after a rolled-back-or-forked result -- a caller may choose to trust it anyway", async () => {
  const log = await buildLog();
  const store = memoryStore();
  await (await checkPin("did:guardian:example.com" as Did, log, store)).advance();
  const rolledBack = await checkPin("did:guardian:example.com" as Did, [log[0]], store);
  await rolledBack.advance();
  const after = await checkPin("did:guardian:example.com" as Did, [log[0]], store);
  assert.equal(after.status, "same-identity");
});
