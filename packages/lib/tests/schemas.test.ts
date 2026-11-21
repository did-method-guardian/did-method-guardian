// Audit WS-3.2: packages/lib/schemas/** had drifted pre-rewrite (still
// required keySigs/verificationMethods/registrar{did,sig}/sigs, no did or
// proof) while website/static/schemas/** had been hand-fixed to match the
// actual proof model -- and scripts/sync-schemas.py copies lib -> static,
// so the next sync would have silently reverted the live, correct schemas
// back to the stale ones. This test closes that gap two ways: every real
// interop fixture must actually validate against these schemas, and these
// schemas must stay byte-identical to the ones actually served from
// website/static/schemas (the single source of truth going forward,
// copied into packages/lib/schemas directly; see schemas/README.md).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 as Ajv } from "ajv/dist/2020.js";

const here = dirname(fileURLToPath(import.meta.url));
// `here` is dist/tests when run compiled -- repo root is four levels up.
// schemas/ is never compiled (plain JSON, not TS), so it stays a sibling
// of src/ and dist/ at the packages/lib root, two levels up from dist/tests.
const repoRoot = join(here, "..", "..", "..", "..");
const libSchemasRoot = join(here, "..", "..", "schemas");
const staticSchemasRoot = join(repoRoot, "website", "static", "schemas");
const fixturesRoot = join(repoRoot, "interop_tests", "operation_log");

function loadJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function listSchemaFiles(root: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      files.push(...listSchemaFiles(join(root, entry.name)).map((f) => join(entry.name, f)));
    } else if (entry.name.endsWith(".json")) {
      files.push(entry.name);
    }
  }
  return files;
}

test("packages/lib/schemas stays byte-identical to website/static/schemas (the single source of truth)", () => {
  const libFiles = new Set(listSchemaFiles(libSchemasRoot));
  const staticFiles = new Set(listSchemaFiles(staticSchemasRoot));
  // schemas/README.md is lib-specific documentation, not a schema -- the one allowed asymmetry.
  libFiles.delete("README.md");
  assert.deepEqual([...libFiles].sort(), [...staticFiles].sort(), "packages/lib/schemas and website/static/schemas must list the exact same schema files");
  for (const file of libFiles) {
    const libContent = readFileSync(join(libSchemasRoot, file), "utf8");
    const staticContent = readFileSync(join(staticSchemasRoot, file), "utf8");
    assert.equal(libContent, staticContent, `${file} has drifted between packages/lib/schemas and website/static/schemas`);
  }
});

function buildValidator(): Ajv {
  const ajv = new Ajv({ schemas: [], allowUnionTypes: true });
  for (const rel of listSchemaFiles(libSchemasRoot)) {
    if (rel === "README.md") continue;
    const schema = loadJson(join(libSchemasRoot, rel)) as { $id?: string };
    if (schema.$id) ajv.addSchema(schema, schema.$id);
  }
  return ajv;
}

function loadFixtures(subdir: "valid" | "invalid"): { name: string; fixture: { log: { op: { type: string } }[] } }[] {
  const dir = join(fixturesRoot, subdir);
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({ name: f, fixture: loadJson(join(dir, f)) as { log: { op: { type: string } }[] } }));
}

test("every interop fixture's own operations validate against the operation schemas", () => {
  const ajv = buildValidator();
  const validate = ajv.getSchema("https://guardianspec.org/schemas/operation.schema.json");
  assert.ok(validate, "operation.schema.json must be loaded");
  for (const subdir of ["valid", "invalid"] as const) {
    for (const { name, fixture } of loadFixtures(subdir)) {
      for (const entry of fixture.log) {
        if (entry.op.type === "guardian_transfer") continue; // v0.1, superseded, not in the schema union (operation.schema.json's own header comment)
        const ok = validate!(entry.op);
        assert.ok(ok, `${subdir}/${name}, op type ${entry.op.type}: ${ajv.errorsText(validate!.errors)}`);
      }
    }
  }
});
