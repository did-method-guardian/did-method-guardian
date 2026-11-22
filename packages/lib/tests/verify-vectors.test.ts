import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { MIN_KEYS_EXTENSION, verifyLog } from "../src/index.js";
import type { Did, Log } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = path.join(__dirname, "..", "..", "..", "..", "interop_tests", "cleanroom", "vectors-final");

interface VerifyVector {
  kind?: "registrar" | "resolve";
  description: string;
  did: Did;
  log: Log;
  expect: { result: "valid" | "invalid" | "unsupported" };
  targets: string;
}

// The README's documented default for every vector is the toy min-keys
// extension. Production code implements no extensions at all -- that is
// what `verifyLog`'s own bare default is for -- so this suite opts in
// explicitly, the same way a real conformance test harness would.
const IMPLEMENTED = new Set([MIN_KEYS_EXTENSION]);

/**
 * The clean-room conformance vectors (interop_tests/cleanroom/README.md):
 * written independently from the spec text alone, across several rounds
 * of review. `targets` is a label, never asserted -- only `expect.result`
 * is.
 */
for (const file of fs.readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json"))) {
  const vector = JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, file), "utf-8")) as VerifyVector;
  if (vector.kind === "registrar" || vector.kind === "resolve") continue; // this file covers verify vectors only

  test(`verify vector ${file}: ${vector.description}`, async () => {
    const r = await verifyLog(vector.did, vector.log, IMPLEMENTED);
    assert.equal(r.result, vector.expect.result, `${file} [${vector.targets}]: ${r.reason ?? ""}`);
  });
}

test("verifyLog's bare default implements no extensions: a log that marks min-keys critical is unsupported", async () => {
  const vector = JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, "ACK-ext-critical-N0.json"), "utf-8")) as VerifyVector;
  const r = await verifyLog(vector.did, vector.log);
  assert.equal(r.result, "unsupported");
});
