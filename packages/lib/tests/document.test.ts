import { test } from "node:test";
import assert from "node:assert/strict";
import { replay, toDidDocument } from "../src/document.js";
import type { CustodialCreateOp, CustodialRotateOp, GuardianTransferOp, CustodialTombstoneOp, LogEntry } from "../src/types.js";

function entry(op: LogEntry["op"], cid: string): LogEntry {
  return { cid, op };
}

test("replay resolves genesis correctly, guardians kept method-internal", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    name: "fred",
    operationalKeys: ["did:key:op1"],
    verificationMethods: { "key-1": "did:key:op1" },
    services: { registrar: { type: "GuardianRegistrarService", endpoint: "https://example.com" } },
    outgoing: [],
    incoming: ["did:guardian:board:example:com"],
    prev: null,
    sigs: { "did:guardian:board:example:com": "sig1" },
  };

  const state = replay("did:guardian:fred:example:com", [entry(genesis, "cid0")]);
  assert.deepEqual(state.guardians, ["did:guardian:board:example:com"]);
  assert.equal(state.deactivated, false);

  const doc = toDidDocument(state);
  assert.equal(doc.id, "did:guardian:fred:example:com");
  assert.equal(doc.verificationMethod.length, 1);
  assert.equal((doc as any).guardians, undefined, "guardians must never appear in the presented DID Document");
});

test("replay applies a rotation and a guardian transfer in order", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    name: "fred",
    operationalKeys: ["did:key:op1"],
    verificationMethods: { "key-1": "did:key:op1" },
    services: {},
    outgoing: [],
    incoming: ["did:guardian:troy:example:com"],
    prev: null,
    sigs: {},
  };
  const rotate: CustodialRotateOp = {
    type: "custodial_rotate",
    operationalKeys: ["did:key:op2"],
    verificationMethods: { "key-1": "did:key:op2" },
    services: {},
    prev: "cid0",
    sig: "sig",
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

  assert.deepEqual(state.operationalKeys, ["did:key:op2"]);
  assert.deepEqual(state.guardians, ["did:guardian:caleb:example:com"]);
});

test("replay marks a tombstoned ward as deactivated but keeps full history", () => {
  const genesis: CustodialCreateOp = {
    type: "custodial_create",
    name: "fred",
    operationalKeys: ["did:key:op1"],
    verificationMethods: {},
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
    sigs: {},
  };
  const tombstone: CustodialTombstoneOp = { type: "custodial_tombstone", prev: "cid0", sigs: {} };

  const log = [entry(genesis, "cid0"), entry(tombstone, "cid1")];
  const state = replay("did:guardian:fred:example:com", log);
  assert.equal(state.deactivated, true);
  assert.equal(log.length, 2, "deactivation never removes prior log entries");
});
