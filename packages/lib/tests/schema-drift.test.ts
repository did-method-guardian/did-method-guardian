// Schema-drift guard (audit r3 #8, per thoward-59's review): the JSON
// Schemas in schemas/ are hand-written against spec/types.ts, with
// nothing mechanical keeping them honest against either one -- H2/H3
// (audit r3) were both the schema quietly diverging from what the
// method actually requires, one direction or the other, with no test
// anywhere to catch it. This validates every schema-conformant vector
// in interop_tests/cleanroom/vectors-final against operation.schema.json
// directly (same approach as the audit's own schema-check.mjs,
// reused here as a standing regression test rather than a one-off
// script), plus a few vectors/synthetic cases specifically chosen to
// confirm a schema-relevant invalid case is still rejected.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMAS_DIR = path.join(__dirname, "..", "..", "schemas");
const VECTORS_DIR = path.join(__dirname, "..", "..", "..", "..", "interop_tests", "cleanroom", "vectors-final");

function walk(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
}

function makeValidator() {
  const ajv = new Ajv2020.default({ strict: false, validateFormats: false });
  for (const f of walk(SCHEMAS_DIR).filter((f) => f.endsWith(".json"))) {
    ajv.addSchema(JSON.parse(fs.readFileSync(f, "utf-8")));
  }
  const validate = ajv.getSchema("https://guardianspec.org/schemas/operation.schema.json");
  if (!validate) throw new Error("operation.schema.json did not register under its own $id");
  return validate;
}

interface Vector {
  kind?: string;
  expect: { result: string };
  log: unknown[];
}

function loadVectors(): { name: string; vector: Vector }[] {
  return fs
    .readdirSync(VECTORS_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({ name: f, vector: JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, f), "utf-8")) as Vector }));
}

test("every operation in every schema-conformant (verify-kind, valid) vector's log passes operation.schema.json", () => {
  const validate = makeValidator();
  const vectors = loadVectors();
  let checked = 0;
  const failures: string[] = [];
  for (const { name, vector } of vectors) {
    if (vector.kind || vector.expect.result !== "valid") continue; // registrar/resolve vectors, and anything not valid, are out of scope here
    for (const op of vector.log) {
      checked++;
      if (!validate(op)) {
        failures.push(`${name}: ${(op as { type?: string }).type} -- ${validate.errors ? JSON.stringify(validate.errors).slice(0, 300) : ""}`);
      }
    }
  }
  assert.ok(checked > 100, `expected to check well over 100 operations from the conformance suite, only checked ${checked} -- did VECTORS_DIR resolve correctly?`);
  assert.deepEqual(failures, [], `${failures.length} operation(s) from valid vectors failed operation.schema.json:\n${failures.join("\n")}`);
});

test("H3: inv-6-11-membership-any.json's setPolicy (membership: \"any\") fails operation.schema.json, not just the real verifier", () => {
  const validate = makeValidator();
  const vectors = loadVectors();
  const found = vectors.find((v) => v.name === "inv-6-11-membership-any.json");
  assert.ok(found, "fixture inv-6-11-membership-any.json not found -- has it been renamed or regenerated away?");
  const setPolicyOp = found!.vector.log.find((op) => (op as { type?: string }).type === "setPolicy") as { policy?: { membership?: unknown } } | undefined;
  assert.ok(setPolicyOp, "expected a setPolicy operation in this vector's log");
  assert.equal(setPolicyOp!.policy?.membership, "any", "this vector's own premise (membership: \"any\") has changed -- update this test to match");
  assert.equal(validate(setPolicyOp), false, "membership: \"any\" must fail the schema (REQ-6-11 excludes it) -- M3/H3's own fix");
});

test("H3: an out-of-range membership integer (REQ-6-13: must be 1-32) fails operation.schema.json", () => {
  const validate = makeValidator();
  const tooLarge = { type: "setPolicy", policy: { membership: 33 }, successor: null, prev: "zQmAbc", proof: [] };
  const tooSmall = { type: "setPolicy", policy: { membership: 0 }, successor: null, prev: "zQmAbc", proof: [] };
  assert.equal(validate(tooLarge), false, "membership: 33 (above the 1-32 bound) must fail the schema");
  assert.equal(validate(tooSmall), false, "membership: 0 (below the 1-32 bound) must fail the schema");
});

test("H2: an attestation with a did:key verificationMethod (the pre-fix shape) fails the schema -- only did:guardian:...?versionId=...#key-n is valid (REQ-7-9)", () => {
  const validate = makeValidator();
  const createWithWrongAttestationShape = {
    type: "create",
    did: "did:guardian:example.com:alice",
    keys: ["zDnaeTHiJyzumHnEbZ7Yj85qyU6RLPzD32FBXLw9BvoSUNCha"],
    guardians: [],
    successor: null,
    policy: {},
    services: [],
    alsoKnownAs: [],
    prev: null,
    proof: [],
    attestation: {
      type: "DataIntegrityProof",
      cryptosuite: "ecdsa-jcs-2019",
      proofPurpose: "capabilityInvocation",
      verificationMethod: "did:key:zDnaeTHiJyzumHnEbZ7Yj85qyU6RLPzD32FBXLw9BvoSUNCha#zDnaeTHiJyzumHnEbZ7Yj85qyU6RLPzD32FBXLw9BvoSUNCha",
      proofValue: "z3tCPUTMxXiKSzuHz7Yk6R58krmnJBNBkEVQwgvKRDRYyTmyJP9c7tb4ifrdWQhoyttxBzQsisHr75CBsd5MPQGXB",
    },
  };
  assert.equal(validate(createWithWrongAttestationShape), false, "a did:key attestation verificationMethod must fail -- REQ-7-9 requires the did:guardian:...?versionId=...#key-n form");
});
