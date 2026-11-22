import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { parseIJson, verifyLog } from "../src/index.js";
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

/**
 * The clean-room conformance vectors (interop_tests/cleanroom/README.md):
 * written independently from the spec text alone, across six rounds of
 * review. `targets` is a label, never asserted -- only `expect.result`
 * is. REQ-5-2 (no fraction/exponent) is checked at parse time
 * (`parseIJson`), the one clause `JSON.parse`'s own result can't
 * preserve -- a vector that fails to parse for that reason is itself
 * the REQ-5-2 "invalid" outcome, never a test-harness error.
 */
for (const file of fs.readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json"))) {
  const text = fs.readFileSync(path.join(VECTORS_DIR, file), "utf-8");
  let vector: VerifyVector;
  let parseFailedWithReq52 = false;
  try {
    vector = parseIJson(text) as VerifyVector;
  } catch (e) {
    vector = JSON.parse(text) as VerifyVector; // only to read expect/kind/targets for the assertion below
    parseFailedWithReq52 = true;
    void e;
  }
  if (vector.kind === "registrar" || vector.kind === "resolve") continue; // this file covers verify vectors only

  test(`verify vector ${file}: ${vector.description}`, async () => {
    if (parseFailedWithReq52) {
      assert.equal(vector.expect.result, "invalid", `${file}: REQ-5-2 (fraction/exponent) failed to parse, but the vector expects ${vector.expect.result}`);
      return;
    }
    const r = await verifyLog(vector.did, vector.log);
    assert.equal(r.result, vector.expect.result, `${file} [${vector.targets}]: ${r.reason ?? ""}`);
  });
}
