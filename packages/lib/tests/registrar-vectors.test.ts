import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { checkAcceptance } from "../src/index.js";
import { MIN_KEYS_EXTENSION } from "../src/testExtensions.js";
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

for (const file of fs.readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json"))) {
  const vector = JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, file), "utf-8")) as RegistrarVector;
  if (vector.kind !== "registrar") continue;

  test(`registrar vector ${file}: ${vector.description}`, async () => {
    const resolver = vector.resolver ?? {};
    const resolveLog: LogResolver = (did) => resolver[did];
    // The README's documented default is the toy extension; a vector
    // sets `implemented` explicitly (e.g. `[]`) to simulate a different
    // registrar's own capability set.
    const implemented = new Set(vector.implemented ?? [MIN_KEYS_EXTENSION]);
    const r = await checkAcceptance(vector.did, vector.log, vector.op, resolveLog, implemented);
    const expected = vector.expect.result === "accepted";
    assert.equal(r.accepted, expected, `${file} [${vector.targets}]: ${r.reason ?? ""}`);
  });
}
