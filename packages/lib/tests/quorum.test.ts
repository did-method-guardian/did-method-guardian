import { test } from "node:test";
import assert from "node:assert/strict";
import { guardiansCanApprove, requiredApprovals } from "../src/quorum.js";

// REQ-6-6: the table of required guardian approvals under the default
// policy ("majority" for recovery/membership/removal, "majority" for
// deactivation's threshold), matching the spec's own Appendix A table.
const CASES: [n: number, recovery: number, membership: number, deactivation: number][] = [
  [1, 1, 1, 1],
  [2, 2, 2, 2],
  [3, 2, 2, 2],
  [5, 3, 3, 3],
];

for (const [n, recovery, membership, deactivation] of CASES) {
  test(`REQ-6-6: N=${n}, recovery="majority" requires ${recovery}`, () => {
    assert.equal(requiredApprovals("recovery", "majority", n, n), recovery);
  });
  test(`REQ-6-6: N=${n}, membership="majority" requires ${membership}`, () => {
    assert.equal(requiredApprovals("membership", "majority", n, n), membership);
  });
  test(`REQ-6-6: N=${n}, deactivation.threshold="majority" requires ${deactivation}`, () => {
    assert.equal(requiredApprovals("deactivation", "majority", n, n), deactivation);
  });
}

test('REQ-6-6: N=1, removal="majority" (E=0) is not possible -- required exceeds E', () => {
  const required = requiredApprovals("removal", "majority", 1, 0);
  assert.equal(guardiansCanApprove(required, 0), false);
});

test('REQ-6-6: N=3, removal="majority" (E=2) requires 2', () => {
  assert.equal(requiredApprovals("removal", "majority", 3, 2), 2);
});

test('REQ-6-6 step 1: "any" always has a base of 1', () => {
  assert.equal(requiredApprovals("recovery", "any", 5, 5), 1);
});

test('REQ-6-6 step 2: "any" is exempt from the floor of 2 even when N >= 2', () => {
  assert.equal(requiredApprovals("recovery", "any", 5, 5), 1);
});

test("REQ-6-6 step 2: a non-\"any\" setting is raised to at least 2 once N >= 2", () => {
  assert.equal(requiredApprovals("recovery", 1, 2, 2), 2);
});

test("REQ-6-6 step 2: a non-\"any\" setting stays below 2 when N < 2", () => {
  assert.equal(requiredApprovals("recovery", 1, 1, 1), 1);
});

test('REQ-6-6 step 3: membership is raised to at least floor(N/2)+1 even for an integer k smaller than that', () => {
  assert.equal(requiredApprovals("membership", 1, 5, 5), 3); // floor(5/2)+1 = 3, k=1 alone would be 2 (step 2's floor)
});

test('REQ-6-6 step 3: removal is NOT raised by the membership/deactivation floor', () => {
  assert.equal(requiredApprovals("removal", 1, 5, 4), 2); // step 2's floor of 2 only, not step 3's floor of 3
});

test('REQ-6-6: "all" requires every eligible guardian', () => {
  assert.equal(requiredApprovals("removal", "all", 5, 4), 4);
});

test("REQ-6-6: an integer k larger than E is capped at E", () => {
  assert.equal(requiredApprovals("recovery", 10, 3, 3), 3);
});

test("REQ-6-7: guardians can approve only when the required number does not exceed E", () => {
  assert.equal(guardiansCanApprove(3, 3), true);
  assert.equal(guardiansCanApprove(4, 3), false);
});
