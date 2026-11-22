import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { anchorOf, checkMutuality, checkWardReport, MIN_KEYS_EXTENSION, resolve, verifyLog } from "../src/index.js";
import type { CreateOp, Did, Entry, Log, LogResolver, WardRecord } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = path.join(__dirname, "..", "..", "..", "..", "interop_tests", "cleanroom", "vectors-final");

interface ResolveVector {
  kind?: "registrar" | "resolve";
  description: string;
  did: Did;
  log: Log;
  resolver?: Record<string, Log>;
  expect: { result: "valid" | "invalid" | "unsupported" };
  targets: string;
  expectMutuality?: string[];
  expectWardReports?: [string, string][];
}

// See verify-vectors.test.ts: the README's documented default is the toy
// extension; production code's own bare default implements none.
const IMPLEMENTED = new Set([MIN_KEYS_EXTENSION]);

/** The clean-room conformance vectors' `resolve` kind: REQ-11-1 plus the optional REQ-11-5/REQ-11-6 reports. */
for (const file of fs.readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json"))) {
  const vector = JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, file), "utf-8")) as ResolveVector;
  if (vector.kind !== "resolve") continue;

  test(`resolve vector ${file}: ${vector.description}`, async () => {
    const resolver = vector.resolver ?? {};
    const resolveLog: LogResolver = (did) => resolver[did];

    const r = await resolve(vector.did, vector.log, resolveLog, IMPLEMENTED);
    assert.equal(r.result, vector.expect.result, `${file} [${vector.targets}]: ${r.reason ?? ""}`);
    if (r.result !== "valid") return;

    if (vector.expectMutuality) {
      const wardAnchor = await anchorOf(vector.log[0] as CreateOp);
      const verified = await verifyLog(vector.did, vector.log, IMPLEMENTED);
      const state = verified.state!;
      const entries: Entry[] = [...state.guardians, ...(state.successor ? [state.successor] : [])];
      const got = await Promise.all(entries.map((entry) => checkMutuality(vector.did, wardAnchor, entry, resolveLog, false, IMPLEMENTED)));
      assert.deepEqual(got, vector.expectMutuality, file);
    }

    if (vector.expectWardReports) {
      const verified = await verifyLog(vector.did, vector.log, IMPLEMENTED);
      const state = verified.state!;
      const got = await Promise.all(
        state.wards.map(async (record: WardRecord) => [record.did.split(":").pop(), await checkWardReport(vector.did, record, resolveLog, IMPLEMENTED)]),
      );
      assert.deepEqual(got, vector.expectWardReports, file);
    }
  });
}
