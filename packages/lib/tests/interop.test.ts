import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyCustodialCreate, verifyCustodialRotate, verifyCustodialTombstone, verifyGuardianRelinquish, verifyGuardianTransfer } from "../src/operations.js";
import { DEFAULT_GUARDIAN_POLICY } from "../src/types.js";
import { replay } from "../src/document.js";
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
  log: LogEntry[];
}

function loadFixtures(subdir: "valid" | "invalid"): { name: string; fixture: Fixture }[] {
  const dir = join(fixturesRoot, subdir);
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => ({ name: f, fixture: JSON.parse(readFileSync(join(dir, f), "utf8")) as Fixture }));
}

/** Verifies every operation in a fixture's log in order, stopping at (and reporting) the first failure. */
async function verifyLog(fixture: Fixture, wardDid: Did): Promise<{ valid: boolean; reason?: string }> {
  const resolve: KeyResolver = (did) => (fixture.known_keys[did] ? [fixture.known_keys[did]] : undefined);
  let currentGuardians: Did[] = [];
  let currentOperationalKeys: string[] = [];

  for (const entry of fixture.log) {
    const op = entry.op;
    if (op.type === "custodial_create") {
      const result = await verifyCustodialCreate(op, resolve);
      if (!result.valid) return result;
      currentGuardians = op.incoming;
      currentOperationalKeys = op.operationalKeys;
    } else if (op.type === "custodial_rotate") {
      const result = await verifyCustodialRotate(op, currentOperationalKeys, resolve);
      if (!result.valid) return result;
      currentOperationalKeys = op.operationalKeys;
    } else if (op.type === "guardian_transfer") {
      const result = await verifyGuardianTransfer(op, currentGuardians, resolve);
      if (!result.valid) return result;
      currentGuardians = op.incoming;
    } else if (op.type === "guardian_relinquish") {
      const result = await verifyGuardianRelinquish(op, currentGuardians, DEFAULT_GUARDIAN_POLICY.removal_threshold, resolve);
      if (!result.valid) return result;
      currentGuardians = [];
    } else if (op.type === "custodial_tombstone") {
      const eligible = [wardDid, ...currentGuardians];
      const result = await verifyCustodialTombstone(op, eligible, DEFAULT_GUARDIAN_POLICY.tombstone_threshold, resolve);
      if (!result.valid) return result;
    }
  }
  return { valid: true };
}

for (const { name, fixture } of loadFixtures("valid")) {
  test(`valid fixture accepted: ${name}`, async () => {
    const result = await verifyLog(fixture, "did:guardian:fred:example:com");
    assert.equal(result.valid, true, `${fixture.note} -- ${result.reason ?? ""}`);
  });

  test(`valid fixture replays to a consistent document: ${name}`, () => {
    const state = replay("did:guardian:fred:example:com", fixture.log);
    assert.ok(state, "replay must produce a resolved state without throwing");
  });
}

for (const { name, fixture } of loadFixtures("invalid")) {
  test(`invalid fixture rejected: ${name}`, async () => {
    const result = await verifyLog(fixture, "did:guardian:fred:example:com");
    assert.equal(result.valid, false, `expected rejection (${fixture.note}) but verification passed`);
  });
}
