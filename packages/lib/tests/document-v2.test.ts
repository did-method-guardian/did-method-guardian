// v0.2 replay/nullification tests -- REQ-6-6/6-8/6-9/6-10/6-11, REQ-7.1-7.
// Kept separate from document.test.ts (v0.1, guardian_transfer-based,
// deliberately untouched) for the same reason rules.test.ts stands apart
// from operations.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "../src/crypto.js";
import { createProof, unsecuredDocument } from "../src/operations.js";
import { checkNullification, reconstructChain, replay } from "../src/document.js";
import type { VerificationContext } from "../src/rules.js";
import { DEFAULT_GUARDIAN_POLICY } from "../src/types.js";
import type { CustodialCreateOp, DataIntegrityProof, Did, GuardianAddOp, GuardianRemoveOp, LogEntry, PolicyUpdateOp } from "../src/types.js";

const wardDid: Did = "did:guardian:example.com:alice";

// `replay`/`reconstructChain` never verify a proof's own cryptographic
// validity -- only `checkNullification`'s own rule-driven path (via
// rotateRule.isSatisfied) does, and those specific tests build real
// proofs with createProof. Everywhere else, a placeholder is enough.
function fakeProof(verificationMethod: string): DataIntegrityProof {
  return { type: "DataIntegrityProof", cryptosuite: "ecdsa-jcs-2019", verificationMethod, proofPurpose: "assertionMethod", created: "2026-01-01T00:00:00.000Z", proofValue: "zTest" };
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

async function makeGuardianContext(wardDid: Did, guardianDid: Did, guardianPrivateKey: string, guardianPublicKey: string): Promise<VerificationContext> {
  return {
    wardDid,
    state: replay(wardDid, [genesisEntry()]),
    resolveKey: (did) => (did === guardianDid ? [guardianPublicKey] : undefined),
    isGuardianLive: () => true,
  };
}

test("REQ-6-8: a guardian-signed rotation naming an earlier prev, within the recovery window, is accepted as a nullification", async () => {
  const guardianDid: Did = "did:guardian:example.com:g1";
  const guardian = await generateKeypair();
  const ctx = await makeGuardianContext(wardDid, guardianDid, guardian.privateKey, guardian.publicKey);
  ctx.state = { ...ctx.state, guardians: [guardianDid], guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, recovery_threshold: "any" } };

  const e1: LogEntry = {
    cid: "cid-1",
    op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1")] },
    acceptedAt: new Date().toISOString(),
  };
  const partial = { type: "custodial_rotate" as const, operationalKeys: ["recovery-k"], services: {}, prev: "cid-genesis" };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const guardianProof = await createProof(unsecuredDoc, `${guardianDid}#key-0`, guardian.privateKey);
  const op = { ...partial, proof: [guardianProof] };

  const result = await checkNullification([genesisEntry(), e1], op, ctx);
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
  ctx.state = { ...ctx.state, guardians: [guardianDid], guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, recovery_threshold: "any" } };

  const old = new Date(Date.now() - 73 * 60 * 60 * 1000).toISOString();
  const e1: LogEntry = {
    cid: "cid-1",
    op: { type: "custodial_rotate", operationalKeys: ["k1"], services: {}, prev: "cid-genesis", proof: [fakeProof("did:key:k1#k1")] },
    acceptedAt: old,
  };
  const partial = { type: "custodial_rotate" as const, operationalKeys: ["recovery-k"], services: {}, prev: "cid-genesis" };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const guardianProof = await createProof(unsecuredDoc, `${guardianDid}#key-0`, guardian.privateKey);
  const op = { ...partial, proof: [guardianProof] };

  const result = await checkNullification([genesisEntry(), e1], op, ctx);
  assert.equal(result.ok, false);
  assert.match(result.reason!, /72 hours/);
});
