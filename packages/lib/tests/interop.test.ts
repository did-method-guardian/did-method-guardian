import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyLog } from "../src/index.js";
import type { Did, Log, LogResolver } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(__dirname, "..", "..", "..", "..", "interop_tests", "operation_log");

interface Fixture {
  description: string;
  expect: "accept" | "reject";
  reject_req?: string;
  did: Did;
  log: Log;
  resolve: Record<string, Log>;
}

function loadFixtures(kind: "valid" | "invalid"): [string, Fixture][] {
  const dir = path.join(FIXTURES_ROOT, kind);
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => [f, JSON.parse(fs.readFileSync(path.join(dir, f), "utf-8")) as Fixture]);
}

for (const [file, fixture] of loadFixtures("valid")) {
  test(`interop valid/${file}: ${fixture.description}`, async () => {
    const resolveLog: LogResolver = (did) => (did === fixture.did ? fixture.log : fixture.resolve[did]);
    const result = await verifyLog(fixture.did, fixture.log, resolveLog);
    assert.equal(result.valid, true, result.reason);
  });
}

for (const [file, fixture] of loadFixtures("invalid")) {
  test(`interop invalid/${file}: ${fixture.description}`, async () => {
    const resolveLog: LogResolver = (did) => (did === fixture.did ? fixture.log : fixture.resolve[did]);
    const result = await verifyLog(fixture.did, fixture.log, resolveLog);
    assert.equal(result.valid, false);
    if (fixture.reject_req) {
      assert.ok(result.reason?.startsWith(fixture.reject_req), `expected reason to start with ${fixture.reject_req}, got: ${result.reason}`);
    }
  });
}
