import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair, canonicalize, sha256Bytes, signRawBytes } from "../src/crypto.js";
import { validateProofShape, verifyPop, popVerificationMethod, unsecuredDocument } from "../src/operations.js";
import type { DataIntegrityProof } from "../src/types.js";

function validProof(overrides: Partial<DataIntegrityProof> = {}): DataIntegrityProof {
  return {
    type: "DataIntegrityProof",
    cryptosuite: "ecdsa-jcs-2019",
    verificationMethod: "did:key:zTest#zTest",
    proofPurpose: "assertionMethod",
    created: "2026-01-01T00:00:00.000Z",
    proofValue: "zSomeValue",
    ...overrides,
  };
}

test("audit WS-1.9: validateProofShape accepts a well-formed proof", () => {
  assert.equal(validateProofShape(validProof()).valid, true);
});

test("audit WS-1.9: validateProofShape rejects a wrong type", () => {
  assert.equal(validateProofShape(validProof({ type: "Ed25519Signature2020" as any })).valid, false);
});

test("audit WS-1.9: validateProofShape rejects an unrecognized cryptosuite", () => {
  assert.equal(validateProofShape(validProof({ cryptosuite: "eddsa-rdfc-2022" as any })).valid, false);
});

test("audit WS-1.9: validateProofShape rejects a proofPurpose other than this implementation's one current value", () => {
  assert.equal(validateProofShape(validProof({ proofPurpose: "capabilityInvocation" as any })).valid, false);
  assert.equal(validateProofShape(validProof({ proofPurpose: "authentication" as any })).valid, false);
});

test("audit WS-1.9: validateProofShape rejects an empty or missing verificationMethod", () => {
  assert.equal(validateProofShape(validProof({ verificationMethod: "" })).valid, false);
});

test("audit WS-1.9: validateProofShape rejects a malformed or missing created", () => {
  for (const bad of ["not a date", "2026-01-01", "2026-01-01 00:00:00Z", "2026-01-01T00:00:00+00:00", ""]) {
    assert.equal(validateProofShape(validProof({ created: bad })).valid, false, `created=${JSON.stringify(bad)} should be rejected`);
  }
  // both the no-fractional-seconds and the fractional-seconds forms toISOString() can produce are accepted
  assert.equal(validateProofShape(validProof({ created: "2026-01-01T00:00:00Z" })).valid, true);
  assert.equal(validateProofShape(validProof({ created: "2026-01-01T00:00:00.123Z" })).valid, true);
});

test("audit WS-1.9: validateProofShape rejects an empty proofValue", () => {
  assert.equal(validateProofShape(validProof({ proofValue: "" })).valid, false);
});

test("audit WS-1.9: validateProofShape rejects an unexpected extra field", () => {
  assert.equal(validateProofShape({ ...validProof(), extra: "field" } as any).valid, false);
});

test("audit WS-1.9: a mathematically valid signature over a malformed proof config is still rejected -- the shape check isn't just a weaker restatement of what the signature already covers", async () => {
  const key = await generateKeypair();
  const unsecuredDoc = unsecuredDocument({ type: "custodial_rotate", operationalKeys: [key.publicKey], services: {}, prev: "cid0" } as any);
  const verificationMethod = popVerificationMethod(key.publicKey);

  // Built by hand, not via createProof, to produce a real signature over
  // a proofConfig createProof itself would never construct -- an
  // unrecognized cryptosuite smuggled in by a client that has a valid
  // key but bypasses this library's own signing helper.
  const forgedProofConfig = { type: "DataIntegrityProof" as const, cryptosuite: "some-other-cryptosuite", verificationMethod, proofPurpose: "assertionMethod" as const, created: "2026-01-01T00:00:00.000Z" };
  const proofConfigHash = await sha256Bytes(new TextEncoder().encode(canonicalize(forgedProofConfig)));
  const documentHash = await sha256Bytes(new TextEncoder().encode(canonicalize(unsecuredDoc)));
  const signingInput = new Uint8Array(proofConfigHash.length + documentHash.length);
  signingInput.set(proofConfigHash, 0);
  signingInput.set(documentHash, proofConfigHash.length);
  const proofValue = await signRawBytes(signingInput, key.privateKey);
  const forgedProof = { ...forgedProofConfig, proofValue } as DataIntegrityProof;

  const result = await verifyPop(unsecuredDoc, [key.publicKey], [forgedProof]);
  assert.equal(result.valid, false, "a proof with an unrecognized cryptosuite must be rejected even when its signature is otherwise mathematically valid over that exact (malformed) content");
});
