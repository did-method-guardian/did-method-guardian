import { test } from "node:test";
import assert from "node:assert/strict";
import { validatePolicy, DEFAULT_GUARDIAN_POLICY } from "../src/types.js";

test("audit WS-1.8: validatePolicy accepts the default policy unchanged", () => {
  assert.equal(validatePolicy(DEFAULT_GUARDIAN_POLICY).valid, true);
});

test("audit WS-1.8: validatePolicy rejects a non-object", () => {
  assert.equal(validatePolicy("not a policy").valid, false);
  assert.equal(validatePolicy(null).valid, false);
  assert.equal(validatePolicy([1, 2, 3]).valid, false);
});

test("audit WS-1.8: validatePolicy rejects a version that isn't a positive integer", () => {
  for (const version of [0, -1, 1.5, "1", NaN]) {
    const result = validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, version });
    assert.equal(result.valid, false, `version ${JSON.stringify(version)} should be rejected`);
  }
});

test("audit WS-1.8: validatePolicy rejects a version newer than this verifier understands (Fix 6)", () => {
  const result = validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, version: 999 });
  assert.equal(result.valid, false);
});

test("audit WS-1.8: validatePolicy rejects a malformed threshold on any threshold field", () => {
  for (const field of ["recovery_threshold", "tombstone_threshold", "removal_threshold", "addition_threshold", "policy_threshold"]) {
    for (const bad of ["literally_anything", { at_least: 0 }, { at_least: -3 }, { at_least: 1.5 }, { at_least: 1, extra: true }, 42]) {
      const result = validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, [field]: bad });
      assert.equal(result.valid, false, `${field} = ${JSON.stringify(bad)} should be rejected`);
    }
  }
});

test("audit WS-1.8: validatePolicy accepts every valid threshold kind", () => {
  for (const good of ["any", "majority", "unanimous", { at_least: 1 }, { at_least: 5 }]) {
    const result = validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, recovery_threshold: good });
    assert.equal(result.valid, true, `${JSON.stringify(good)} should be accepted`);
  }
});

test("audit WS-1.8: validatePolicy rejects a negative or non-integer min_guardian_count", () => {
  for (const bad of [-1, 1.5, "0"]) {
    const result = validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, min_guardian_count: bad });
    assert.equal(result.valid, false, `min_guardian_count ${JSON.stringify(bad)} should be rejected`);
  }
});

test("audit WS-1.8: validatePolicy rejects a malformed on_orphan", () => {
  for (const bad of ["literally_anything", { transfer_to: "" }, { transfer_to: 5 }, { transfer_to: "did:guardian:x", extra: true }]) {
    const result = validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, on_orphan: bad });
    assert.equal(result.valid, false, `on_orphan ${JSON.stringify(bad)} should be rejected`);
  }
  assert.equal(validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, on_orphan: { transfer_to: "did:guardian:example.com:bob" } }).valid, true);
});

test("audit WS-1.8: validatePolicy rejects an unexpected extra field", () => {
  const result = validatePolicy({ ...DEFAULT_GUARDIAN_POLICY, witness_threshold: "any" });
  assert.equal(result.valid, false);
});
