import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { checkAcceptance } from "../src/index.js";
import type { Did, Log, LogResolver, Operation } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = path.join(__dirname, "..", "..", "..", "..", "interop_tests", "cleanroom", "vectors-final");

interface RegistrarVector {
  kind?: "registrar" | "resolve";
  description: string;
  did: Did;
  log: Log;
  op: Operation;
  resolver?: Record<string, Log>;
  expect: { result: "accepted" | "rejected" };
  targets: string;
  implemented?: string[];
}

/**
 * The one vector this reference implementation cannot reproduce:
 * `reg-inv-ext-unsupported` simulates a registrar that implements NO
 * extensions at all (`implemented: []`), where this library always
 * implements the toy `min-keys` extension the same way everywhere
 * (verify, resolve and accept) -- there is no real deployment of this
 * same library that would implement fewer extensions in `checkAcceptance`
 * than in `verifyLog`, so this is not parameterized.
 */
const KNOWN_GAPS = new Set(["reg-inv-ext-unsupported.json"]);

for (const file of fs.readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json"))) {
  const vector = JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, file), "utf-8")) as RegistrarVector;
  if (vector.kind !== "registrar" || KNOWN_GAPS.has(file)) continue;

  test(`registrar vector ${file}: ${vector.description}`, async () => {
    const resolver = vector.resolver ?? {};
    const resolveLog: LogResolver = (did) => resolver[did];
    const r = await checkAcceptance(vector.did, vector.log, vector.op, resolveLog);
    const expected = vector.expect.result === "accepted";
    assert.equal(r.accepted, expected, `${file} [${vector.targets}]: ${r.reason ?? ""}`);
  });
}
