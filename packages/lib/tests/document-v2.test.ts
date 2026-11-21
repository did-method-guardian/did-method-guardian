// v0.2 replay/nullification tests -- REQ-6-6/6-8/6-9/6-10/6-11, REQ-7.1-7.
// Kept separate from document.test.ts (v0.1, guardian_transfer-based,
// deliberately untouched) for the same reason rules.test.ts stands apart
// from operations.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "../src/crypto.js";
import { createProof, popVerificationMethod, unsecuredDocument } from "../src/operations.js";
import { checkNullification, reconstructChain, replay } from "../src/document.js";
import type { VerificationContext } from "../src/rules.js";
import { DEFAULT_GUARDIAN_POLICY } from "../src/types.js";
import type { CustodialCreateOp, DataIntegrityProof, Did, GuardianAddOp, GuardianRemoveOp, LogEntry, PolicyUpdateOp } from "../src/types.js";

const wardDid: Did = "did:guardian:example.com:alice";

// `replay`/`reconstructChain` never verify a proof's own cryptographic
// validity -- only `checkNullification`'s own rule-driven path (via
// rotateRule.isSatisfied) does, and those specific tests build real
// proofs with createProof. Everywhere else, a placeholder is enough.
function fakeProof(verificationMethod: string, created: string = "2026-01-01T00:00:00.000Z"): DataIntegrityProof {
  return { type: "DataIntegrityProof", cryptosuite: "ecdsa-jcs-2019", verificationMethod, proofPurpose: "assertionMethod", created, proofValue: "zTest" };
}

const REGISTRAR_DID: Did = "did:guardian:example.com";
/** WS-4.1: the registrar's own acceptance receipt -- checkNullification's window check (REQ-6-9) reads this, never the storage-layer LogEntry.acceptedAt. */
function fakeReceipt(createdAt: string): DataIntegrityProof {
  return fakeProof(`${REGISTRAR_DID}#key-0`, createdAt);
}

function genesisEntry(overrides: Partial<CustodialCreateOp> = {}): LogEntry {
  const op: CustodialCreateOp = {
    type: "custodial_create",
    did: wardDid,
    name: "alice",
    operationalKeys: ["ward-pk"],
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
    creator: "did:guardian:example.com",
    proof: [fakeProof("did:guardian:example.com#key-0")],
    ...overrides,
  };
  return { cid: "cid-genesis", op };
}

test("REQ-7.1-7: replay merges genesis.policy over the stated defaults, field by field", () => {
  const entry = genesisEntry({ policy: { removal_threshold: "unanimous" } });
  const state = replay(wardDid, [entry]);
  assert.equal(state.guardianPolicy.removal_threshold, "unanimous");
  assert.deepEqual(state.guardianPolicy.recovery_threshold, DEFAULT_GUARDIAN_POLICY.recovery_threshold);
  assert.equal(state.guardianPolicy.min_guardian_count, DEFAULT_GUARDIAN_POLICY.min_guardian_count);
});

test("a policy field this version doesn't recognize survives replay untouched, not stripped or rejected", () => {
  const entry = genesisEntry({ policy: { witnesses: ["did:guardian:example.com:watcher"] } as any });
  const state = replay(wardDid, [entry]);
  assert.deepEqual((state.guardianPolicy as any).witnesses, ["did:guardian:example.com:watcher"]);
});

test("replay applies guardian_add then guardian_remove in order", () => {
  const g1: Did = "did:guardian:example.com:g1";
  const g2: Did = "did:guardian:example.com:g2";
  const addG1: LogEntry = { cid: "cid-1", op: { type: "guardian_add", incoming: g1, prev: "cid-genesis", proof: [fakeProof(`${g1}#key-0`)] } as GuardianAddOp };
  const addG2: LogEntry = { cid: "cid-2", op: { type: "guardian_add", incoming: g2, prev: "cid-1", proof: [fakeProof(`${g2}#key-0`)] } as GuardianAddOp };
  const removeG1: LogEntry = { cid: "cid-3", op: { type: "guardian_remove", outgoing: g1, prev: "cid-2", proof: [fakeProof(`${g2}#key-0`)] } as GuardianRemoveOp };
  const state = replay(wardDid, [genesisEntry(), addG1, addG2, removeG1]);
  assert.deepEqual(state.guardians, [g2]);
});

test("replay applies policy_update wholesale", () => {
  const g1: Did = "did:guardian:example.com:g1";
  const addG1: LogEntry = { cid: "cid-1", op: { type: "guardian_add", incoming: g1, prev: "cid-genesis", proof: [fakeProof(`${g1}#key-0`)] } as GuardianAddOp };
  const newPolicy = { ...DEFAULT_GUARDIAN_POLICY, policy_threshold: "unanimous" as const };
  const update: LogEntry = { cid: "cid-2", op: { type: "policy_update", policy: newPolicy, prev: "cid-1", proof: [fakeProof(`${g1}#key-0`)] } as PolicyUpdateOp };
  const state = replay(wardDid, [genesisEntry(), addG1, update]);
  assert.equal(state.guardianPolicy.policy_threshold, "unanimous");
});

// --- REQ-6-6/6-10: reconstructChain --------------------------------------

test("reconstructChain is a no-op when every entry's prev matches the immediately preceding cid", () => {
  const genesis = genesisEntry();
  const e1: LogEntry = { cid: "cid-1", op: { type: "guardian_relinquish", prev: "cid-genesis", proof: [] } };
  const chain = reconstructChain([genesis, e1]);
  assert.deepEqual(chain.map((e) => e.cid), ["cid-genesis", "cid-1"]);
});

test("REQ-6-10: an entry naming an earlier prev truncates everything between it and the then-current head", () => {
  const genesis = genesisEntry();
  const e1: LogEntry = { cid: "cid-1", op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1")] } };
  const e2: LogEntry = { cid: "cid-2", op: { type: "custodial_rotate", operationalKeys: ["k2"], services: {}, prev: "cid-1", proof: [fakeProof("did:key:k2#k2")] } };
  // e3 nullifies e1 (names cid-genesis, not cid-2) -- e2 should be excluded.
  const e3: LogEntry = { cid: "cid-3", op: { type: "custodial_rotate", operationalKeys: ["k3"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k3#k3"), fakeProof("did:guardian:example.com:g1#key-0")] } };
  const chain = reconstructChain([genesis, e1, e2, e3]);
  assert.deepEqual(chain.map((e) => e.cid), ["cid-genesis", "cid-3"]);
});

test("REQ-6-11: a nullification can itself be nullified -- the same mechanism applied again, targeting the same earlier point, not a resurrection of the specific superseded entry", () => {
  const genesis = genesisEntry();
  const e1: LogEntry = { cid: "cid-1", op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1")] } };
  const e2: LogEntry = { cid: "cid-2", op: { type: "custodial_rotate", operationalKeys: ["k2"], services: {}, prev: "cid-1", proof: [fakeProof("did:key:k2#k2")] } };
  // nullify1 supersedes both e1 and e2 by pointing all the way back to genesis.
  const nullify1: LogEntry = { cid: "cid-3", op: { type: "custodial_rotate", operationalKeys: ["k3"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k3#k3"), fakeProof("did:guardian:example.com:g1#key-0")] } };
  // reversal: a further guardian-signed rotation naming the SAME prev nullify1 did -- nullify1 is now "the operation immediately following cid-genesis", so this supersedes nullify1 in exactly the way nullify1 superseded e1. cid-1/cid-2 are never reachable again by name; a guardian wanting that state back would have to recreate it as new op content.
  const reversal: LogEntry = { cid: "cid-4", op: { type: "custodial_rotate", operationalKeys: ["k4"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k4#k4"), fakeProof("did:guardian:example.com:g1#key-0")] } };
  const chain = reconstructChain([genesis, e1, e2, nullify1, reversal]);
  assert.deepEqual(chain.map((e) => e.cid), ["cid-genesis", "cid-4"]);
});

// --- REQ-6-8/6-9: checkNullification -------------------------------------

/** Genesis with `guardianDid` actually established via `incoming` (co-signed) and `recovery_threshold: "any"` set directly in genesis's own `policy` -- not a post-hoc ctx.state patch, which checkNullification's state-at-prev replay (WS-1.4) would now simply ignore. */
function guardianGenesisEntry(guardianDid: Did): LogEntry {
  return genesisEntry({
    incoming: [guardianDid],
    policy: { recovery_threshold: "any" },
    proof: [fakeProof(`${REGISTRAR_DID}#key-0`), fakeProof(`${guardianDid}#key-0`)],
  });
}

async function makeGuardianContext(wardDid: Did, guardianDid: Did, guardianPrivateKey: string, guardianPublicKey: string): Promise<VerificationContext> {
  return {
    wardDid,
    state: replay(wardDid, [guardianGenesisEntry(guardianDid)]),
    resolveKey: (did) => (did === guardianDid ? [guardianPublicKey] : undefined),
    isGuardianLive: () => true,
  };
}

test("REQ-6-8: a guardian-signed rotation naming an earlier prev, within the recovery window, is accepted as a nullification", async () => {
  const guardianDid: Did = "did:guardian:example.com:g1";
  const guardian = await generateKeypair();
  const ctx = await makeGuardianContext(wardDid, guardianDid, guardian.privateKey, guardian.publicKey);

  const e1: LogEntry = {
    cid: "cid-1",
    op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1"), fakeReceipt(new Date().toISOString())] },
    acceptedAt: new Date().toISOString(),
  };
  const recoveryKey = await generateKeypair(); // REQ-7.2-12: PoP must be real -- nullification enforces it like any other rotation
  const partial = { type: "custodial_rotate" as const, operationalKeys: [recoveryKey.publicKey], services: {}, prev: "cid-genesis" };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const guardianProof = await createProof(unsecuredDoc, `${guardianDid}#key-0`, guardian.privateKey);
  const popProof = await createProof(unsecuredDoc, popVerificationMethod(recoveryKey.publicKey), recoveryKey.privateKey);
  const op = { ...partial, proof: [popProof, guardianProof] };

  const result = await checkNullification([guardianGenesisEntry(guardianDid), e1], op, ctx);
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.nullifiedEntry?.cid, "cid-1");
});

test("REQ-6-8: a ward-signed rotation (not guardian-signed) may never nullify, even if it names an earlier prev", async () => {
  const ward = await generateKeypair();
  const ctx: VerificationContext = {
    wardDid,
    state: replay(wardDid, [genesisEntry({ operationalKeys: [ward.publicKey] })]),
    resolveKey: (did) => (did === wardDid ? [ward.publicKey] : undefined),
    isGuardianLive: () => true,
  };
  const e1: LogEntry = {
    cid: "cid-1",
    op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1")] },
    acceptedAt: new Date().toISOString(),
  };
  const partial = { type: "custodial_rotate" as const, operationalKeys: ["new-k"], services: {}, prev: "cid-genesis" };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const wardProof = await createProof(unsecuredDoc, `${wardDid}#key-0`, ward.privateKey);
  const op = { ...partial, proof: [wardProof] };

  const result = await checkNullification([genesisEntry(), e1], op, ctx);
  assert.equal(result.ok, false);
  assert.match(result.reason!, /REQ-6-8/);
});

test("REQ-6-9: a nullification naming a prev whose successor was accepted more than 72h ago is rejected", async () => {
  const guardianDid: Did = "did:guardian:example.com:g1";
  const guardian = await generateKeypair();
  const ctx = await makeGuardianContext(wardDid, guardianDid, guardian.privateKey, guardian.publicKey);

  const old = new Date(Date.now() - 73 * 60 * 60 * 1000).toISOString();
  const e1: LogEntry = {
    cid: "cid-1",
    op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1"), fakeReceipt(old)] },
    acceptedAt: old,
  };
  const recoveryKey = await generateKeypair();
  const partial = { type: "custodial_rotate" as const, operationalKeys: [recoveryKey.publicKey], services: {}, prev: "cid-genesis" };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const guardianProof = await createProof(unsecuredDoc, `${guardianDid}#key-0`, guardian.privateKey);
  const popProof = await createProof(unsecuredDoc, popVerificationMethod(recoveryKey.publicKey), recoveryKey.privateKey);
  const op = { ...partial, proof: [popProof, guardianProof] };

  const result = await checkNullification([guardianGenesisEntry(guardianDid), e1], op, ctx);
  assert.equal(result.ok, false);
  assert.match(result.reason!, /72 hours/);
});

test("audit WS-1.4: a nullifying rotation installing a key with NO proof of possession is rejected -- the same requirement every other rotation is held to", async () => {
  const guardianDid: Did = "did:guardian:example.com:g1";
  const guardian = await generateKeypair();
  const ctx = await makeGuardianContext(wardDid, guardianDid, guardian.privateKey, guardian.publicKey);

  const e1: LogEntry = {
    cid: "cid-1",
    op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1"), fakeReceipt(new Date().toISOString())] },
    acceptedAt: new Date().toISOString(),
  };
  const recoveryKey = await generateKeypair();
  const partial = { type: "custodial_rotate" as const, operationalKeys: [recoveryKey.publicKey], services: {}, prev: "cid-genesis" };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const guardianProof = await createProof(unsecuredDoc, `${guardianDid}#key-0`, guardian.privateKey);
  const op = { ...partial, proof: [guardianProof] }; // no PoP proof for recoveryKey.publicKey at all

  const result = await checkNullification([guardianGenesisEntry(guardianDid), e1], op, ctx);
  assert.equal(result.ok, false, "a key with no proof of possession must never be installed via nullification, same as any other rotation path");
  assert.match(result.reason!, /proof of possession/);
});

test("audit WS-4.2(d): a nullification can't itself be nullified -- one level only, closing the ping-pong two-guardian deadlock", async () => {
  const guardianDid: Did = "did:guardian:example.com:g1";
  const guardian = await generateKeypair();
  const ctx = await makeGuardianContext(wardDid, guardianDid, guardian.privateKey, guardian.publicKey);

  const e1: LogEntry = {
    cid: "cid-1",
    op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1"), fakeReceipt(new Date().toISOString())] },
    acceptedAt: new Date().toISOString(),
  };
  const e2: LogEntry = {
    cid: "cid-2",
    op: { type: "custodial_rotate", operationalKeys: ["k2"], services: {}, prev: "cid-1", proof: [fakeProof("did:key:k2#k2"), fakeReceipt(new Date().toISOString())] },
    acceptedAt: new Date().toISOString(),
  };
  // nullify1 already nullified e1 (and so e2) by naming cid-genesis -- itself a nullification, by construction (its own prev, cid-genesis, does not match e2's cid, the entry immediately preceding it in storage order).
  const nullify1: LogEntry = {
    cid: "cid-3",
    op: { type: "custodial_rotate", operationalKeys: ["k3"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k3#k3"), fakeProof(`${guardianDid}#key-0`), fakeReceipt(new Date().toISOString())] },
    acceptedAt: new Date().toISOString(),
  };

  const recoveryKey = await generateKeypair();
  const partial = { type: "custodial_rotate" as const, operationalKeys: [recoveryKey.publicKey], services: {}, prev: "cid-genesis" }; // attempts to nullify nullify1 by naming the SAME prev it did
  const unsecuredDoc = unsecuredDocument(partial as any);
  const guardianProof = await createProof(unsecuredDoc, `${guardianDid}#key-0`, guardian.privateKey);
  const popProof = await createProof(unsecuredDoc, popVerificationMethod(recoveryKey.publicKey), recoveryKey.privateKey);
  const op = { ...partial, proof: [popProof, guardianProof] };

  const result = await checkNullification([guardianGenesisEntry(guardianDid), e1, e2, nullify1], op, ctx);
  assert.equal(result.ok, false, "nullify1 is itself a nullification -- it must not be nullifiable a second time");
  assert.match(result.reason!, /itself a nullification/);
});

test("audit WS-4.1: a nullification target with no registrar receipt at all is rejected -- never falls back to trusting an unsigned acceptedAt", async () => {
  const guardianDid: Did = "did:guardian:example.com:g1";
  const guardian = await generateKeypair();
  const ctx = await makeGuardianContext(wardDid, guardianDid, guardian.privateKey, guardian.publicKey);

  const e1: LogEntry = {
    cid: "cid-1",
    // no receipt proof at all -- only a PoP proof, same as a log entry predating this registrar's own adoption of receipts would have
    op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1")] },
    acceptedAt: new Date().toISOString(), // recent by the unsigned, no-longer-trusted field -- must not matter
  };
  const recoveryKey = await generateKeypair();
  const partial = { type: "custodial_rotate" as const, operationalKeys: [recoveryKey.publicKey], services: {}, prev: "cid-genesis" };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const guardianProof = await createProof(unsecuredDoc, `${guardianDid}#key-0`, guardian.privateKey);
  const popProof = await createProof(unsecuredDoc, popVerificationMethod(recoveryKey.publicKey), recoveryKey.privateKey);
  const op = { ...partial, proof: [popProof, guardianProof] };

  const result = await checkNullification([guardianGenesisEntry(guardianDid), e1], op, ctx);
  assert.equal(result.ok, false, "a missing receipt must never be treated as 'recent enough' via the unsigned acceptedAt fallback");
  assert.match(result.reason!, /registrar receipt/);
});
