// WS-2.1 (audit): end-to-end tests for the real verifyLog, built from
// genuine keys and signatures throughout -- unlike checkNullification's
// own unit tests (document-v2.test.ts), which can get away with
// placeholder proofs for genesis and for the entry being nullified
// (checkNullification never re-verifies either one), verifyLog
// cryptographically verifies EVERY entry, so every entry here has to be
// real.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "../src/crypto.js";
import { signCustodialCreate, signCustodialRotate, signCustodialRotateByGuardians, signCustodialTombstone, signRegistrarAttestation, cidFor } from "../src/operations.js";
import { verifyLog } from "../src/verifyLog.js";
import type { Did, LogEntry, CustodialCreateOp } from "../src/types.js";

const DID: Did = "did:guardian:example.com:alice";
const REGISTRAR_DID: Did = "did:guardian:example.com";

async function makeResolver(keys: Record<string, string>) {
  return (did: string) => (keys[did] ? [keys[did]] : undefined);
}

async function attestedGenesis(partial: Omit<CustodialCreateOp, "proof" | "creator">, incomingKeys: Record<string, string>, registrar: { publicKey: string; privateKey: string }, operationalPrivateKeys: Record<string, string>) {
  const withCreator = { ...partial, creator: REGISTRAR_DID };
  const attestation = await signRegistrarAttestation(withCreator, REGISTRAR_DID, registrar.privateKey);
  const signed = await signCustodialCreate(withCreator, incomingKeys, operationalPrivateKeys);
  return { ...signed, proof: [...signed.proof, attestation] };
}

test("verifyLog accepts a clean genesis + rotate log and returns the right anchor and final state", async () => {
  const registrar = await generateKeypair();
  const ward = await generateKeypair();
  const genesis = await attestedGenesis({ type: "custodial_create", did: DID, name: "alice", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null }, {}, registrar, { [ward.publicKey]: ward.privateKey });
  const genesisCid = await cidFor(genesis);
  const genesisEntry: LogEntry = { cid: genesisCid, op: genesis };

  const newKey = await generateKeypair();
  const rotate = await signCustodialRotate({ type: "custodial_rotate", operationalKeys: [newKey.publicKey], services: {}, prev: genesisCid }, DID, ward.privateKey, { [newKey.publicKey]: newKey.privateKey });
  const rotateCid = await cidFor(rotate);
  const rotateEntry: LogEntry = { cid: rotateCid, op: rotate };

  const resolve = await makeResolver({ [REGISTRAR_DID]: registrar.publicKey });
  const result = await verifyLog(DID, [genesisEntry, rotateEntry], resolve);
  assert.equal(result.valid, true, (result as any).reason);
  if (result.valid) {
    assert.equal(result.anchor, genesisCid);
    assert.equal(result.registrarDid, REGISTRAR_DID);
    assert.deepEqual(result.state.operationalKeys, [newKey.publicKey]);
  }
});

test("verifyLog rejects a tampered cid instead of trusting a stored value at face value", async () => {
  const registrar = await generateKeypair();
  const ward = await generateKeypair();
  const genesis = await attestedGenesis({ type: "custodial_create", did: DID, name: "alice", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null }, {}, registrar, { [ward.publicKey]: ward.privateKey });
  const genesisEntry: LogEntry = { cid: "zTamperedCid", op: genesis }; // the real cid is NOT this

  const resolve = await makeResolver({ [REGISTRAR_DID]: registrar.publicKey });
  const result = await verifyLog(DID, [genesisEntry], resolve);
  assert.equal(result.valid, false);
  assert.match((result as any).reason, /cid mismatch/);
});

test("verifyLog rejects an entry whose prev names something not in the chain at all, cleanly rather than throwing", async () => {
  const registrar = await generateKeypair();
  const ward = await generateKeypair();
  const guardianDid: Did = "did:guardian:example.com:board";
  const guardian = await generateKeypair();
  const genesis = await attestedGenesis(
    { type: "custodial_create", did: DID, name: "alice", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [guardianDid], policy: { recovery_threshold: "any" }, prev: null },
    { [guardianDid]: guardian.privateKey },
    registrar,
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const genesisEntry: LogEntry = { cid: genesisCid, op: genesis };

  // Guardian-signed (passes checkNullification's own ward-proof gate) but
  // naming a prev that doesn't exist anywhere in the chain at all --
  // reconstructChain would throw on this; checkNullification must catch
  // that itself and return a clean rejection instead.
  const newKey = await generateKeypair();
  const rotate = await signCustodialRotateByGuardians(
    { type: "custodial_rotate", operationalKeys: [newKey.publicKey], services: {}, prev: "zNotInTheChainAtAll" },
    { [guardianDid]: guardian.privateKey },
    [guardianDid],
    { [newKey.publicKey]: newKey.privateKey },
  );
  const rotateEntry: LogEntry = { cid: await cidFor(rotate), op: rotate };

  const resolve = await makeResolver({ [REGISTRAR_DID]: registrar.publicKey, [guardianDid]: guardian.publicKey });
  const result = await verifyLog(DID, [genesisEntry, rotateEntry], resolve);
  assert.equal(result.valid, false);
  assert.match((result as any).reason, /does not name any operation in the current chain/);
});

test("verifyLog rejects an operation that appears after this identity's own tombstone (REQ-6-5)", async () => {
  const registrar = await generateKeypair();
  const ward = await generateKeypair();
  const genesis = await attestedGenesis({ type: "custodial_create", did: DID, name: "alice", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null }, {}, registrar, { [ward.publicKey]: ward.privateKey });
  const genesisCid = await cidFor(genesis);
  const genesisEntry: LogEntry = { cid: genesisCid, op: genesis };

  const tombstone = await signCustodialTombstone({ type: "custodial_tombstone", prev: genesisCid }, { [DID]: ward.privateKey }, [DID]);
  const tombstoneCid = await cidFor(tombstone);
  const tombstoneEntry: LogEntry = { cid: tombstoneCid, op: tombstone };

  const newKey = await generateKeypair();
  const rotateAfter = await signCustodialRotate({ type: "custodial_rotate", operationalKeys: [newKey.publicKey], services: {}, prev: tombstoneCid }, DID, ward.privateKey, { [newKey.publicKey]: newKey.privateKey });
  const rotateAfterEntry: LogEntry = { cid: await cidFor(rotateAfter), op: rotateAfter };

  const resolve = await makeResolver({ [REGISTRAR_DID]: registrar.publicKey });
  const result = await verifyLog(DID, [genesisEntry, tombstoneEntry, rotateAfterEntry], resolve);
  assert.equal(result.valid, false);
  assert.match((result as any).reason, /REQ-6-5/);
});

test("verifyLog rejects a genesis naming itself as its own guardian (REQ-7.1-9)", async () => {
  const registrar = await generateKeypair();
  const ward = await generateKeypair();
  const genesis = await attestedGenesis({ type: "custodial_create", did: DID, name: "alice", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [DID], prev: null }, { [DID]: ward.privateKey }, registrar, { [ward.publicKey]: ward.privateKey });
  const genesisEntry: LogEntry = { cid: await cidFor(genesis), op: genesis };

  const resolve = await makeResolver({ [REGISTRAR_DID]: registrar.publicKey, [DID]: ward.publicKey });
  const result = await verifyLog(DID, [genesisEntry], resolve);
  assert.equal(result.valid, false);
  assert.match((result as any).reason, /REQ-7\.1-9/);
});

test("verifyLog rejects a genesis naming the same guardian twice in incoming", async () => {
  const registrar = await generateKeypair();
  const ward = await generateKeypair();
  const guardianDid: Did = "did:guardian:example.com:board";
  const guardian = await generateKeypair();
  const genesis = await attestedGenesis(
    { type: "custodial_create", did: DID, name: "alice", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [guardianDid, guardianDid] as any, prev: null },
    { [guardianDid]: guardian.privateKey },
    registrar,
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisEntry: LogEntry = { cid: await cidFor(genesis), op: genesis };

  const resolve = await makeResolver({ [REGISTRAR_DID]: registrar.publicKey, [guardianDid]: guardian.publicKey });
  const result = await verifyLog(DID, [genesisEntry], resolve);
  assert.equal(result.valid, false);
  assert.match((result as any).reason, /same guardian twice/);
});

test("verifyLog rejects a genesis with no operational keys at all", async () => {
  const registrar = await generateKeypair();
  const genesis = await attestedGenesis({ type: "custodial_create", did: DID, name: "alice", operationalKeys: [], services: {}, outgoing: [], incoming: [], prev: null }, {}, registrar, {});
  const genesisEntry: LogEntry = { cid: await cidFor(genesis), op: genesis };

  const resolve = await makeResolver({ [REGISTRAR_DID]: registrar.publicKey });
  const result = await verifyLog(DID, [genesisEntry], resolve);
  assert.equal(result.valid, false);
  assert.match((result as any).reason, /REQ-7\.1-3/);
});

test("verifyLog accepts a genuine guardian-signed nullification -- a fork validated through checkNullification, and the final state reflects the nullifying branch", async () => {
  const registrar = await generateKeypair();
  const ward = await generateKeypair();
  const guardianDid: Did = "did:guardian:example.com:board";
  const guardian = await generateKeypair();

  const genesis = await attestedGenesis(
    { type: "custodial_create", did: DID, name: "alice", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [guardianDid], policy: { recovery_threshold: "any" }, prev: null },
    { [guardianDid]: guardian.privateKey },
    registrar,
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const genesisEntry: LogEntry = { cid: genesisCid, op: genesis };

  // The ward's own rotation, right after genesis -- this is what gets nullified.
  const wardKey = await generateKeypair();
  const wardRotate = await signCustodialRotate({ type: "custodial_rotate", operationalKeys: [wardKey.publicKey], services: {}, prev: genesisCid }, DID, ward.privateKey, { [wardKey.publicKey]: wardKey.privateKey });
  const wardRotateWithReceipt = { ...wardRotate, proof: [...wardRotate.proof, await signRegistrarAttestation(wardRotate as any, REGISTRAR_DID, registrar.privateKey)] };
  const wardRotateCid = await cidFor(wardRotateWithReceipt);
  const wardRotateEntry: LogEntry = { cid: wardRotateCid, op: wardRotateWithReceipt };

  // A guardian-signed rotation naming genesis (not the current head) as prev -- a nullification, well within the 72h window.
  const recoveryKey = await generateKeypair();
  const nullifyingRotate = await signCustodialRotateByGuardians(
    { type: "custodial_rotate", operationalKeys: [recoveryKey.publicKey], services: {}, prev: genesisCid },
    { [guardianDid]: guardian.privateKey },
    [guardianDid],
    { [recoveryKey.publicKey]: recoveryKey.privateKey },
  );
  const nullifyingCid = await cidFor(nullifyingRotate);
  const nullifyingEntry: LogEntry = { cid: nullifyingCid, op: nullifyingRotate };

  const resolve = await makeResolver({ [REGISTRAR_DID]: registrar.publicKey, [guardianDid]: guardian.publicKey });
  const result = await verifyLog(DID, [genesisEntry, wardRotateEntry, nullifyingEntry], resolve);
  assert.equal(result.valid, true, (result as any).reason);
  if (result.valid) {
    assert.deepEqual(result.state.operationalKeys, [recoveryKey.publicKey], "the final state must reflect the nullifying branch, not the nullified one");
  }
});
