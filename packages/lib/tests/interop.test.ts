import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { replay } from "../src/document.js";
import { verifyLog as realVerifyLog } from "../src/verifyLog.js";
import type { KeyResolver } from "../src/operations.js";
import type { Did, LogEntry } from "../src/types.js";

// `here` is dist/tests when run compiled -- repo root is four levels up
// (tests -> dist -> lib -> packages -> repo root).
const here = dirname(fileURLToPath(import.meta.url));
const fixturesRoot = join(here, "..", "..", "..", "..", "interop_tests", "operation_log");

interface Fixture {
  note: string;
  expect: "accept" | "reject";
  known_keys: Record<Did, string>;
  registrar_did: Did;
  log: LogEntry[];
}

function loadFixtures(subdir: "valid" | "invalid"): { name: string; fixture: Fixture }[] {
  const dir = join(fixturesRoot, subdir);
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({ name: f, fixture: JSON.parse(readFileSync(join(dir, f), "utf8")) as Fixture }));
}

/**
 * WS-2.1/3.3 (audit): delegates to the library's own real verifyLog,
 * rather than this test file's own prior hand-rolled walk -- that
 * version never recomputed a single cid, never checked prev linkage at
 * all (it just trusted fixture.log's own array order), and never ran a
 * fork through checkNullification. `fixture.registrar_did` is no longer
 * read here: the real verifyLog derives the expected registrar
 * structurally from each genesis's own domain (WS-4.4), never from a
 * caller-supplied value -- consistent with every fixture already using a
 * registrar_did that IS that domain root (gen-fixtures.ts constructs
 * them that way), and a stronger check than trusting the fixture's own
 * claim about who the registrar is.
 */
async function verifyLog(fixture: Fixture, wardDid: Did): Promise<{ valid: boolean; reason?: string }> {
  const resolve: KeyResolver = (did) => (fixture.known_keys[did] ? [fixture.known_keys[did]] : undefined);
  const result = await realVerifyLog(wardDid, fixture.log, resolve);
  return result.valid ? { valid: true } : { valid: false, reason: result.reason };
}

/** Audit WS-3.3: the ward is derived from the fixture's own genesis.did, never hardcoded -- several fixtures deliberately use a genesis name other than the common case (puppet/puppet2/keyswap/unsigned, each exercising a specific forgery), and a hardcoded ward here silently looked up the wrong identity's state for those. */
function wardDidOf(fixture: Fixture): Did {
  const genesis = fixture.log[0]?.op as { did?: Did } | undefined;
  if (!genesis?.did) throw new Error("fixture's first log entry is not a genesis with a did field");
  return genesis.did;
}

for (const { name, fixture } of loadFixtures("valid")) {
  test(`valid fixture accepted: ${name}`, async () => {
    const result = await verifyLog(fixture, wardDidOf(fixture));
    assert.equal(result.valid, true, `${fixture.note} -- ${result.reason ?? ""}`);
  });

  test(`valid fixture replays to a consistent document: ${name}`, () => {
    const state = replay(wardDidOf(fixture), fixture.log);
    assert.ok(state, "replay must produce a resolved state without throwing");
  });
}

for (const { name, fixture } of loadFixtures("invalid")) {
  test(`invalid fixture rejected: ${name}`, async () => {
    const result = await verifyLog(fixture, wardDidOf(fixture));
    assert.equal(result.valid, false, `expected rejection (${fixture.note}) but verification passed`);
  });
}
