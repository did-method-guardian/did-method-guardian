import { test } from "node:test";
import assert from "node:assert/strict";
import { meetsThreshold, requiredCount, requiredTransferSigners } from "../src/quorum.js";

test("any: a single signer suffices, regardless of n", () => {
  assert.equal(requiredCount("any", 1), 1);
  assert.equal(requiredCount("any", 5), 1);
});

test("any: vacuously unsatisfiable at n=0, not an error", () => {
  assert.equal(requiredCount("any", 0), Infinity);
  assert.equal(meetsThreshold("any", [], []), false);
});

test("majority: strict floor(n/2)+1 for n=1..6", () => {
  const expected: Record<number, number> = { 1: 1, 2: 2, 3: 2, 4: 3, 5: 3, 6: 4 };
  for (const [n, want] of Object.entries(expected)) {
    assert.equal(requiredCount("majority", Number(n)), want, `n=${n}`);
  }
});

test("majority degenerates to unanimous at n=2", () => {
  assert.equal(requiredCount("majority", 2), requiredCount("unanimous", 2));
});

test("majority is strict: exactly half does not satisfy it at even n", () => {
  const eligible = ["a", "b", "c", "d"];
  assert.equal(meetsThreshold("majority", ["a", "b"], eligible), false, "2 of 4 is not a majority");
  assert.equal(meetsThreshold("majority", ["a", "b", "c"], eligible), true, "3 of 4 is a majority");
});

test("quorum intersection: no two disjoint cohorts can both independently satisfy majority", () => {
  const eligible = ["a", "b", "c", "d"];
  const required = requiredCount("majority", eligible.length);
  const cohortA = ["a", "b"];
  const cohortB = ["c", "d"];
  // Neither disjoint half alone reaches the required count...
  assert.equal(cohortA.length < required, true);
  assert.equal(cohortB.length < required, true);
  // ...and any two *valid* (threshold-meeting) cohorts must overlap, since
  // 2*required > eligible.length for every n > 0.
  assert.equal(2 * required > eligible.length, true);
});

test("unanimous requires every eligible party", () => {
  assert.equal(requiredCount("unanimous", 3), 3);
  assert.equal(meetsThreshold("unanimous", ["a", "b"], ["a", "b", "c"]), false);
  assert.equal(meetsThreshold("unanimous", ["a", "b", "c"], ["a", "b", "c"]), true);
});

test("at_least(n): an absolute count regardless of eligible set size", () => {
  assert.equal(requiredCount({ at_least: 2 }, 10), 2);
  assert.equal(meetsThreshold({ at_least: 2 }, ["a"], ["a", "b", "c"]), false);
  assert.equal(meetsThreshold({ at_least: 2 }, ["a", "b"], ["a", "b", "c"]), true);
});

test("ineligible or duplicate signers are never double-counted", () => {
  const eligible = ["a", "b", "c"];
  assert.equal(meetsThreshold("majority", ["a", "a", "stranger"], eligible), false, "1 valid distinct signer is not a majority of 3");
});

test("requiredTransferSigners: continuing guardians (in current and incoming, not in outgoing) are excluded", () => {
  // current = [troy, jane]; troy steps down, jane continues, caleb joins.
  const signers = requiredTransferSigners(["troy", "jane"], ["troy"], ["jane", "caleb"]);
  assert.deepEqual(new Set(signers), new Set(["troy", "caleb"]), "jane continues and should not need to re-sign");
});

test("requiredTransferSigners: naming someone in both outgoing and incoming still requires their signature", () => {
  // Listing a party in `outgoing` is itself a claim they're being removed,
  // so their consent is still required even if `incoming` re-adds them --
  // this isn't the "jane continues" case, it's "jane is removed and rejoins".
  const signers = requiredTransferSigners(["troy", "jane"], ["troy", "jane"], ["jane", "caleb"]);
  assert.deepEqual(new Set(signers), new Set(["troy", "jane", "caleb"]));
});

test("requiredTransferSigners: genesis case (current and outgoing both empty) requires only incoming", () => {
  const signers = requiredTransferSigners([], [], ["board-a", "board-b"]);
  assert.deepEqual(new Set(signers), new Set(["board-a", "board-b"]));
});
