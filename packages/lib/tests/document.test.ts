import { test } from "node:test";
import assert from "node:assert/strict";
import { replay, toDidDocument } from "../src/document.js";
import type { CustodialCreateOp, CustodialRotateOp, GuardianTransferOp, CustodialTombstoneOp, DataIntegrityProof, LogEntry } from "../src/types.js";

function entry(op: LogEntry["op"], cid: string): LogEntry {
  return { cid, op };
}

// `replay`/`toDidDocument` never verify a proof's own cryptographic
// validity (that's operations.ts/rules.ts's job, before a log is ever
// trusted) -- only read its shape (verificationMethod, to find a
// registrar attestation) or ignore it entirely, so a placeholder proof is
// all this file needs. `toDidDocument` derives `verificationMethod`
// directly from `operationalKeys` by index now (no separate
// verificationMethods map, no SPKI conversion), so operationalKeys can be
// any placeholder string too.
function fakeProof(verificationMethod: string): DataIntegrityProof {
  return { type: "DataIntegrityProof", cryptosuite: "ecdsa-jcs-2019", verificationMethod, proofPurpose: "assertionMethod", created: "2026-01-01T00:00:00.000Z", proofValue: "zTest" };
}

test("replay resolves genesis correctly, guardians kept method-internal", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    did: "did:guardian:fred:example:com",
    name: "fred",
    operationalKeys: ["op1-pubkey"],
    services: { registrar: { type: "GuardianRegistrarService", endpoint: "https://example.com" } },
    outgoing: [],
    incoming: ["did:guardian:board:example:com"],
    prev: null,
    creator: "did:guardian:board:example:com",
    proof: [fakeProof("did:guardian:board:example:com#key-0")],
  };

  const state = replay("did:guardian:fred:example:com", [entry(genesis, "cid0")]);
  assert.deepEqual(state.guardians, ["did:guardian:board:example:com"]);
  assert.equal(state.deactivated, false);

  const doc = toDidDocument(state);
  assert.equal(doc.id, "did:guardian:fred:example:com");
  assert.equal(doc.verificationMethod.length, 1);
  assert.equal((doc as any).guardians, undefined, "guardians must never appear in the presented DID Document");
});

test("REQ-3-2: authentication, assertionMethod, and capabilityInvocation all reference every operational key's own verificationMethod", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    did: "did:guardian:fred:example:com",
    name: "fred",
    operationalKeys: ["op1-pubkey"],
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
    creator: "did:guardian:fred:example:com",
    proof: [fakeProof(`did:key:op1-pubkey#op1-pubkey`)],
  };
  const state = replay("did:guardian:fred:example:com", [entry(genesis, "cid0")]);
  const doc = toDidDocument(state);
  const vmId = "did:guardian:fred:example:com#key-0";
  assert.deepEqual(doc.authentication, [vmId]);
  assert.deepEqual(doc.assertionMethod, [vmId]);
  assert.deepEqual(doc.capabilityInvocation, [vmId]);
});

test("replay applies a rotation and a guardian transfer in order", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    did: "did:guardian:fred:example:com",
    name: "fred",
    operationalKeys: ["op1-pubkey"],
    services: {},
    outgoing: [],
    incoming: ["did:guardian:troy:example:com"],
    prev: null,
    creator: "did:guardian:troy:example:com",
    proof: [fakeProof("did:guardian:troy:example:com#key-0")],
  };
  const rotate: CustodialRotateOp = {
    type: "custodial_rotate",
    operationalKeys: ["op2-pubkey"],
    services: {},
    prev: "cid0",
    proof: [fakeProof(`did:key:op2-pubkey#op2-pubkey`)],
  };
  const transfer: GuardianTransferOp = {
    type: "guardian_transfer",
    outgoing: ["did:guardian:troy:example:com"],
    incoming: ["did:guardian:caleb:example:com"],
    prev: "cid1",
    sigs: {},
  };

  const state = replay("did:guardian:fred:example:com", [
    entry(genesis, "cid0"),
    entry(rotate, "cid1"),
    entry(transfer, "cid2"),
  ]);

  assert.deepEqual(state.operationalKeys, ["op2-pubkey"]);
  assert.deepEqual(state.guardians, ["did:guardian:caleb:example:com"]);
});

test("replay marks a tombstoned ward as deactivated but keeps full history", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    did: "did:guardian:fred:example:com",
    name: "fred",
    operationalKeys: ["op1-pubkey"],
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
    creator: "did:guardian:fred:example:com",
    proof: [fakeProof(`did:key:op1-pubkey#op1-pubkey`)],
  };
  const tombstone: CustodialTombstoneOp = { type: "custodial_tombstone", prev: "cid0", proof: [fakeProof("did:guardian:fred:example:com#key-0")] };

  const log = [entry(genesis, "cid0"), entry(tombstone, "cid1")];
  const state = replay("did:guardian:fred:example:com", log);
  assert.equal(state.deactivated, true);
  assert.equal(log.length, 2, "deactivation never removes prior log entries");

  // audit WS-1.16: deactivation has to be visible from the presented
  // document itself, not just internal ResolvedState -- a resolver that
  // never independently replays the log otherwise has no way to learn
  // REQ-6-5's own deactivated state at all.
  const doc = toDidDocument(state);
  assert.equal(doc.didDocumentMetadata.deactivated, true);
});

test("audit WS-1.16: an active (non-deactivated) identity's document still carries didDocumentMetadata.deactivated, as false -- its absence must never be mistaken for a registrar that doesn't support surfacing it", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    did: "did:guardian:fred:example:com",
    name: "fred",
    operationalKeys: ["op1-pubkey"],
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
    creator: "did:guardian:fred:example:com",
    proof: [fakeProof(`did:key:op1-pubkey#op1-pubkey`)],
  };
  const state = replay("did:guardian:fred:example:com", [entry(genesis, "cid0")]);
  const doc = toDidDocument(state);
  assert.equal(doc.didDocumentMetadata.deactivated, false);
});

test("audit WS-1.16: @context includes the Multikey security vocabulary, not just the base DID context", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    did: "did:guardian:fred:example:com",
    name: "fred",
    operationalKeys: ["op1-pubkey"],
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
    creator: "did:guardian:fred:example:com",
    proof: [fakeProof(`did:key:op1-pubkey#op1-pubkey`)],
  };
  const state = replay("did:guardian:fred:example:com", [entry(genesis, "cid0")]);
  const doc = toDidDocument(state);
  assert.ok(doc["@context"].includes("https://w3id.org/security/multikey/v1"), "the base DID context alone never defines the Multikey verification method type");
});
