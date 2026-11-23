// F-1 (audit, HIGH): setPolicy used to decide whether a successor
// "changed" by comparing `did` alone -- a same-DID entry with new
// keys needed no proof of possession, and a released successor's
// stale entry could be "refreshed" with no check at all. Fixed with
// sameEntry (operations.ts), compared directly here against
// checkSetPolicyApprovals (rules.ts) without needing a full log.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkSetPolicyApprovals } from "../src/rules.js";
import { sameEntry } from "../src/operations.js";
import type { Did, Entry, Key, SetPolicyOp, State } from "../src/index.js";

const WARD_KEY = "zWardKey" as Key;
const OLD_SUCCESSOR_KEY = "zOldSuccessorKey" as Key;
const NEW_SUCCESSOR_KEY = "zNewSuccessorKey" as Key;
const SUCCESSOR_DID = "did:guardian:example.com:bob" as Did;

function stateWith(successor: Entry): State {
  return {
    keys: [WARD_KEY],
    guardians: [],
    successor,
    wards: [],
    policy: {},
    services: [],
    alsoKnownAs: [],
    deactivated: false,
    critical: [],
  };
}

function setPolicyOp(successor: Entry): SetPolicyOp {
  return { type: "setPolicy", policy: {}, successor, prev: "zPrev", proof: [] };
}

test("sameEntry: differs on keys alone even when did/anchor/consent all match", () => {
  const a: Entry = { did: SUCCESSOR_DID, anchor: "zAnchor", consent: "zConsent", keys: [OLD_SUCCESSOR_KEY] };
  const b: Entry = { ...a, keys: [NEW_SUCCESSOR_KEY] };
  assert.equal(sameEntry(a, b), false);
});

test("F-1: same successor DID, but new keys with NO proof of possession -- must now be invalid, not silently accepted", () => {
  const currentSuccessor: Entry = { did: SUCCESSOR_DID, anchor: "zAnchor", consent: "zConsent", keys: [OLD_SUCCESSOR_KEY] };
  const refreshedWithNewKeys: Entry = { ...currentSuccessor, keys: [NEW_SUCCESSOR_KEY] }; // same did, different keys
  const stateBefore = stateWith(currentSuccessor);
  const op = setPolicyOp(refreshedWithNewKeys);

  // The ward's own current key signs, but nobody proves possession of
  // the new successor key -- this must now be rejected.
  const validKeys = new Set<Key>([WARD_KEY]);
  const result = checkSetPolicyApprovals(op, stateBefore, validKeys);
  assert.equal(result.valid, false);
});

test("F-1: same successor DID, new keys, WITH proof of possession of the new key -- valid", () => {
  const currentSuccessor: Entry = { did: SUCCESSOR_DID, anchor: "zAnchor", consent: "zConsent", keys: [OLD_SUCCESSOR_KEY] };
  const refreshedWithNewKeys: Entry = { ...currentSuccessor, keys: [NEW_SUCCESSOR_KEY] };
  const stateBefore = stateWith(currentSuccessor);
  const op = setPolicyOp(refreshedWithNewKeys);

  const validKeys = new Set<Key>([WARD_KEY, NEW_SUCCESSOR_KEY]);
  const result = checkSetPolicyApprovals(op, stateBefore, validKeys);
  assert.equal(result.valid, true);
});

test("F-1: the successor entry is genuinely unchanged (every member identical) -- no new proof of possession required", () => {
  const successor: Entry = { did: SUCCESSOR_DID, anchor: "zAnchor", consent: "zConsent", keys: [OLD_SUCCESSOR_KEY] };
  const stateBefore = stateWith(successor);
  const op = setPolicyOp({ ...successor }); // a fresh object, same values

  const validKeys = new Set<Key>([WARD_KEY]); // no proof from the successor's own key
  const result = checkSetPolicyApprovals(op, stateBefore, validKeys);
  assert.equal(result.valid, true);
});

test("F-1: same DID but a different anchor (a different identity's log entirely) with no PoP -- invalid", () => {
  const currentSuccessor: Entry = { did: SUCCESSOR_DID, anchor: "zAnchor1", consent: "zConsent1", keys: [OLD_SUCCESSOR_KEY] };
  const differentAnchorSameKeys: Entry = { ...currentSuccessor, anchor: "zAnchor2", consent: "zConsent2" }; // same keys, different anchor/consent
  const stateBefore = stateWith(currentSuccessor);
  const op = setPolicyOp(differentAnchorSameKeys);

  const validKeys = new Set<Key>([WARD_KEY]); // old keys never re-signed for the "new" entry
  const result = checkSetPolicyApprovals(op, stateBefore, validKeys);
  assert.equal(result.valid, false);
});
