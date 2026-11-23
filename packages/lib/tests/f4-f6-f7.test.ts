// F-4, F-6, F-7 (audit r3, MEDIUM/LOW): a grab-bag of shape/precedence
// fixes, each small enough not to need its own file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkValuesShape, isValidUri, isValidFragment, verifyLog, createProof, generateKeypair, operationHash, DEFAULT_POLICY } from "../src/index.js";
import type { CreateOp, DeactivateOp, Did } from "../src/index.js";

// --- F-4: -0 ---------------------------------------------------------------

test("F-4: -0 is rejected by checkValuesShape itself (REQ-5-2), not left to crash canonicalization later", () => {
  const result = checkValuesShape({ x: -0 });
  assert.equal(result.valid, false);
});

test("F-4 (sanity): ordinary 0 and other integers still pass", () => {
  assert.equal(checkValuesShape({ x: 0 }).valid, true);
  assert.equal(checkValuesShape({ x: 42 }).valid, true);
});

// --- F-6: unsupported must be checked before deactivated --------------------

test("F-6: an unsupported operation following a deactivate is reported unsupported, not invalid", async () => {
  const did = "did:guardian:f6.example" as Did;
  const key = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did,
    keys: [key.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const createProof1 = await createProof(createBase, key.publicKey, key.privateKey);
  const createOp: CreateOp = { ...createBase, proof: [createProof1] };

  const deactivateBase: Omit<DeactivateOp, "proof"> = { type: "deactivate", prev: await operationHash(createOp) };
  const deactivateProof = await createProof(deactivateBase, key.publicKey, key.privateKey);
  const deactivateOp: DeactivateOp = { ...deactivateBase, proof: [deactivateProof] };

  // An operation of an unrecognized type, placed after the deactivate.
  const unknownOp = { type: "not-a-real-type", prev: "whatever", proof: [] };

  const result = await verifyLog(did, [createOp, deactivateOp, unknownOp as never]);
  assert.equal(result.result, "unsupported", "an unsupported op after a deactivate must be unsupported, not invalid");
});

// --- F-7: RFC 3986 character classes ---------------------------------------

test("F-7: isValidUri rejects characters RFC 3986 requires to be pct-encoded", () => {
  assert.equal(isValidUri("https://example.com/{}"), false);
  assert.equal(isValidUri("https://example.com/é"), false);
  assert.equal(isValidUri("https://example.com/|pipe"), false);
  assert.equal(isValidUri('https://example.com/"quote"'), false);
  assert.equal(isValidUri("https://example.com/%zz"), false, "a malformed pct-encoding must not be accepted as literal characters");
});

test("F-7 (sanity): ordinary and correctly pct-encoded URIs still pass", () => {
  assert.equal(isValidUri("https://example.com/a/b?x=1&y=2#frag"), true);
  assert.equal(isValidUri("https://example.com/space%20here"), true);
  assert.equal(isValidUri("urn:example:a123"), true);
});

test("F-7: a bare '#' (empty fragment) is valid -- RFC 3986 allows a zero-length fragment", () => {
  assert.equal(isValidFragment("#"), true);
});

test("F-7: isValidFragment rejects the same disallowed characters", () => {
  assert.equal(isValidFragment("#{}"), false);
  assert.equal(isValidFragment("#%zz"), false);
});
