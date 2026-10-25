// Example-driven and property-based tests against the formal method spec's
// own requirement IDs (website/content/docs/did-guardian-spec-v0.2.0/), run
// through src/rules.ts -- never through the v0.1 operations.ts functions,
// which this task deliberately leaves untouched (see rules.ts's own header
// comment). Every test name cites the REQ id(s) it covers.

import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { generateKeypair, signPayload } from "../src/crypto.js";
import type { KeyResolver } from "../src/operations.js";
import { meetsThreshold, requiredCount } from "../src/quorum.js";
import {
  checkGenesisShape,
  isValidName,
  liveGuardians,
  OPERATION_RULES,
  withinRecoveryWindow,
  type VerificationContext,
} from "../src/rules.js";
import { DEFAULT_GUARDIAN_POLICY } from "../src/types.js";
import type { Did, GuardianPolicy, ResolvedState } from "../src/types.js";

// --- test fixtures -----------------------------------------------------

function makeState(overrides: Partial<ResolvedState> = {}): ResolvedState {
  return {
    did: "did:guardian:alice:example.com",
    operationalKeys: [],
    verificationMethods: {},
    services: {},
    guardians: [],
    guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY },
    deactivated: false,
    ...overrides,
  };
}

function makeResolver(keys: Record<Did, string>): KeyResolver {
  return (did) => (keys[did] ? [keys[did]] : undefined);
}

function allLive(): (did: Did) => boolean {
  return () => true;
}

async function signMap(payload: unknown, signerKeys: Record<Did, string>, signers: Did[]): Promise<Record<Did, string>> {
  const sigs: Record<Did, string> = {};
  for (const did of signers) sigs[did] = await signPayload(payload, signerKeys[did]);
  return sigs;
}

// --- REQ-7.1: genesis shape ---------------------------------------------

test("REQ-7.1-1: genesis with non-empty incoming is rejected -- establishing a guardian directly at genesis is guardian_add's job now", () => {
  const result = checkGenesisShape({
    incoming: ["did:guardian:board:example.com"],
    prev: null,
    operationalKeys: ["pk"],
    verificationMethods: { "key-1": "pk" },
    services: {},
    creator: "did:guardian:acme.com",
  });
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-7\.1-1/);
});

test("REQ-7.1-2: genesis with non-null prev is rejected", () => {
  const result = checkGenesisShape({
    incoming: [],
    prev: "some-cid",
    operationalKeys: ["pk"],
    verificationMethods: { "key-1": "pk" },
    services: {},
    creator: "did:guardian:acme.com",
  });
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-7\.1-2/);
});

test("REQ-7.1-4: genesis with no creator is rejected", () => {
  const result = checkGenesisShape({
    incoming: [],
    prev: null,
    operationalKeys: ["pk"],
    verificationMethods: { "key-1": "pk" },
    services: {},
  });
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-7\.1-4/);
});

test("REQ-7.1-1/2/3/4: a conformant genesis (empty incoming, null prev, full key material, a creator) is accepted", () => {
  const result = checkGenesisShape({
    incoming: [],
    prev: null,
    operationalKeys: ["pk"],
    verificationMethods: { "key-1": "pk" },
    services: {},
    creator: "did:guardian:acme.com",
  });
  assert.equal(result.valid, true);
});

// --- REQ-2-1: name syntax ------------------------------------------------

test("REQ-2-1: valid names", () => {
  for (const name of ["ali", "alice", "a1-b2", "fred-flintstone"]) {
    assert.equal(isValidName(name), true, name);
  }
});

test("REQ-2-1: names with consecutive hyphens, too short, or non-alphanumeric edges are rejected", () => {
  for (const name of ["al", "a--b", "-alice", "alice-", "alice_jones"]) {
    assert.equal(isValidName(name), false, name);
  }
});

// --- REQ-7.2-1/7.2-2/REQ-5-2: custodial_rotate --------------------------

test("REQ-7.2-1(a): a ward's own single operational key alone satisfies rotation, regardless of recovery_threshold", async () => {
  const ward = await generateKeypair();
  const wardDid = "did:guardian:alice:example.com";
  const state = makeState({ did: wardDid, guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, recovery_threshold: "unanimous" } });
  const partial = { type: "custodial_rotate" as const, operationalKeys: ["new-pk"], verificationMethods: {}, services: {}, prev: "cid0" };
  const sig = await signPayload(partial, ward.privateKey);
  const op = { ...partial, sig };
  const ctx: VerificationContext = { wardDid, state, resolveKey: makeResolver({ [wardDid]: ward.publicKey }), isGuardianLive: allLive() };
  assert.equal(await OPERATION_RULES.custodial_rotate.isSatisfied(op, [], ctx), true);
});

test("REQ-7.2-1(b): a guardian committee meeting recovery_threshold can rotate without the ward's own key", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const g2Did = "did:guardian:g2:example.com";
  const g1 = await generateKeypair();
  const g2 = await generateKeypair();
  const state = makeState({
    did: wardDid,
    guardians: [g1Did, g2Did],
    guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, recovery_threshold: "majority" },
  });
  const partial = { type: "custodial_rotate" as const, operationalKeys: ["new-pk"], verificationMethods: {}, services: {}, prev: "cid0" };
  const sigs = await signMap(partial, { [g1Did]: g1.privateKey }, [g1Did]); // majority of N=2 is 2 -- one alone should NOT suffice
  const op = { ...partial, sigs };
  const ctx: VerificationContext = {
    wardDid,
    state,
    resolveKey: makeResolver({ [g1Did]: g1.publicKey, [g2Did]: g2.publicKey }),
    isGuardianLive: allLive(),
  };
  assert.equal(await OPERATION_RULES.custodial_rotate.isSatisfied(op, [], ctx), false, "one of two guardians should not meet majority");

  const sigsBoth = await signMap(partial, { [g1Did]: g1.privateKey, [g2Did]: g2.privateKey }, [g1Did, g2Did]);
  const opBoth = { ...partial, sigs: sigsBoth };
  assert.equal(await OPERATION_RULES.custodial_rotate.isSatisfied(opBoth, [], ctx), true);
});

test("REQ-4-4: a deactivated guardian's signature no longer counts toward recovery_threshold", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const g2Did = "did:guardian:g2:example.com";
  const g1 = await generateKeypair();
  const g2 = await generateKeypair();
  const state = makeState({
    did: wardDid,
    guardians: [g1Did, g2Did],
    guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, recovery_threshold: "any" },
  });
  const partial = { type: "custodial_rotate" as const, operationalKeys: ["new-pk"], verificationMethods: {}, services: {}, prev: "cid0" };
  const sigs = await signMap(partial, { [g1Did]: g1.privateKey }, [g1Did]);
  const op = { ...partial, sigs };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey, [g2Did]: g2.publicKey });

  const ctxLive: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  assert.equal(await OPERATION_RULES.custodial_rotate.isSatisfied(op, [], ctxLive), true, "g1 live, any-threshold, should satisfy alone");

  const ctxG1Deactivated: VerificationContext = {
    wardDid,
    state,
    resolveKey,
    isGuardianLive: (did) => did !== g1Did,
  };
  assert.equal(
    await OPERATION_RULES.custodial_rotate.isSatisfied(op, [], ctxG1Deactivated),
    false,
    "a stolen or still-valid key for a tombstoned guardian must not satisfy any() by excluding it from the live set entirely",
  );
});

// --- REQ-6-8/6-9: nullification window ----------------------------------

test("REQ-6-9: a rotation accepted less than 72h ago is still within the recovery window", () => {
  const acceptedAt = new Date("2026-01-01T00:00:00Z");
  const now = new Date("2026-01-03T23:00:00Z"); // 71h later
  assert.equal(withinRecoveryWindow(acceptedAt, now), true);
});

test("REQ-6-9: a rotation accepted 72h or more ago is outside the recovery window", () => {
  const acceptedAt = new Date("2026-01-01T00:00:00Z");
  const now = new Date("2026-01-04T00:00:00Z"); // exactly 72h later
  assert.equal(withinRecoveryWindow(acceptedAt, now), false);
});

// --- REQ-7.2-3/4/5, REQ-5-5: guardian_add -------------------------------

test("REQ-7.2-5: zero-to-one guardian_add requires both the incoming guardian's own key and the ward's own operational key", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const ward = await generateKeypair();
  const incomingDid = "did:guardian:board:example.com";
  const incoming = await generateKeypair();
  const state = makeState({ did: wardDid, guardians: [] });
  const partial = { type: "guardian_add" as const, incoming: incomingDid, prev: "cid0" };
  const resolveKey = makeResolver({ [wardDid]: ward.publicKey, [incomingDid]: incoming.publicKey });

  const sigsIncomingOnly = await signMap(partial, { [incomingDid]: incoming.privateKey }, [incomingDid]);
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  assert.equal(
    await OPERATION_RULES.guardian_add.isSatisfied({ ...partial, sigs: sigsIncomingOnly }, [], ctx),
    false,
    "incoming alone, without the ward's own key, must not establish guardianship over an autonomous ward",
  );

  const sigsBoth = await signMap(partial, { [incomingDid]: incoming.privateKey, [wardDid]: ward.privateKey }, [incomingDid, wardDid]);
  assert.equal(await OPERATION_RULES.guardian_add.isSatisfied({ ...partial, sigs: sigsBoth }, [], ctx), true);
});

test("REQ-7.2-4: adding a guardian to a non-empty set needs the incoming party's own key plus enough of the current guardians to meet addition_threshold", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const incomingDid = "did:guardian:newguy:example.com";
  const g1 = await generateKeypair();
  const incoming = await generateKeypair();
  const state = makeState({ did: wardDid, guardians: [g1Did], guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, addition_threshold: "majority" } });
  const partial = { type: "guardian_add" as const, incoming: incomingDid, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey, [incomingDid]: incoming.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };

  const sigsIncomingOnly = await signMap(partial, { [incomingDid]: incoming.privateKey }, [incomingDid]);
  assert.equal(
    await OPERATION_RULES.guardian_add.isSatisfied({ ...partial, sigs: sigsIncomingOnly }, [], ctx),
    false,
    "the v0.1 bug this closes: incoming's own consent alone used to be enough, with no existing-guardian approval at all",
  );

  const sigsBoth = await signMap(partial, { [incomingDid]: incoming.privateKey, [g1Did]: g1.privateKey }, [incomingDid, g1Did]);
  assert.equal(await OPERATION_RULES.guardian_add.isSatisfied({ ...partial, sigs: sigsBoth }, [], ctx), true);

  // Regression: requiredSigners (used for notification/voting-UI purposes,
  // not the actual gate above) must list the REAL existing committee for
  // the non-empty case, never the ward itself -- a real bug this caught:
  // it used to always return [incoming, wardDid] regardless, so the
  // existing guardian whose approval this actually needs was never
  // notified and never offered a sign option.
  const required = await OPERATION_RULES.guardian_add.requiredSigners({ ...partial, sigs: {} }, ctx);
  assert.ok(required.includes(g1Did), "the real existing guardian must be listed as a required signer");
  assert.ok(!required.includes(wardDid), "the ward itself is never a signer for the non-empty guardian_add case");
});

test("REQ-7.2-5: guardian_add's requiredSigners lists the ward itself only for the zero-to-one case", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const incomingDid = "did:guardian:newguy:example.com";
  const state = makeState({ did: wardDid, guardians: [] });
  const ctx: VerificationContext = { wardDid, state, resolveKey: makeResolver({}), isGuardianLive: allLive() };
  const required = await OPERATION_RULES.guardian_add.requiredSigners({ type: "guardian_add", incoming: incomingDid, prev: "cid0", sigs: {} }, ctx);
  assert.deepEqual([...required].sort(), [incomingDid, wardDid].sort());
});

test("REQ-7.2-7(b) regression: guardian_remove's requiredSigners lists the OTHER current guardians, not just outgoing -- the forced path's real signers", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const [g1Did, g2Did] = ["g1", "g2"].map((n) => `did:guardian:${n}:example.com`);
  const state = makeState({ did: wardDid, guardians: [g1Did, g2Did] });
  const ctx: VerificationContext = { wardDid, state, resolveKey: makeResolver({}), isGuardianLive: allLive() };
  const required = await OPERATION_RULES.guardian_remove.requiredSigners({ type: "guardian_remove", outgoing: g1Did, prev: "cid0", sigs: {} }, ctx);
  assert.ok(required.includes(g2Did), "the other current guardian, whose approval the forced path needs, must be listed");
});

test("REQ-7.2-1 regression: custodial_rotate's requiredSigners lists the live guardian committee too, not just the ward", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const state = makeState({ did: wardDid, guardians: [g1Did] });
  const ctx: VerificationContext = { wardDid, state, resolveKey: makeResolver({}), isGuardianLive: allLive() };
  const required = await OPERATION_RULES.custodial_rotate.requiredSigners(
    { type: "custodial_rotate", operationalKeys: [], verificationMethods: {}, services: {}, prev: "cid0" },
    ctx,
  );
  assert.ok(required.includes(g1Did), "the guardian committee, whose approval a recovery rotation can use, must be listed");
});

test("REQ-7.3-1 regression: custodial_tombstone's requiredSigners lists the live guardian committee too, not just the ward", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const state = makeState({ did: wardDid, guardians: [g1Did] });
  const ctx: VerificationContext = { wardDid, state, resolveKey: makeResolver({}), isGuardianLive: allLive() };
  const required = await OPERATION_RULES.custodial_tombstone.requiredSigners({ type: "custodial_tombstone", prev: "cid0", sigs: {} }, ctx);
  assert.ok(required.includes(g1Did), "a guardian able to sign a tombstone under a stricter-than-default threshold must be listed");
});

test("REQ-7.2-3: guardian_add naming an already-current guardian is rejected", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const g1 = await generateKeypair();
  const state = makeState({ did: wardDid, guardians: [g1Did] });
  const partial = { type: "guardian_add" as const, incoming: g1Did, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  const sigs = await signMap(partial, { [g1Did]: g1.privateKey }, [g1Did]);
  assert.equal(await OPERATION_RULES.guardian_add.isSatisfied({ ...partial, sigs }, [], ctx), false);
});

// --- REQ-7.2-6/7, REQ-5-4, REQ-5-7: guardian_remove ----------------------

test("REQ-7.2-7(a): a guardian can always voluntarily remove itself", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const g2Did = "did:guardian:g2:example.com";
  const g1 = await generateKeypair();
  const g2 = await generateKeypair();
  const state = makeState({ did: wardDid, guardians: [g1Did, g2Did] });
  const partial = { type: "guardian_remove" as const, outgoing: g1Did, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey, [g2Did]: g2.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  const sigs = await signMap(partial, { [g1Did]: g1.privateKey }, [g1Did]);
  assert.equal(await OPERATION_RULES.guardian_remove.isSatisfied({ ...partial, sigs }, [], ctx), true);
});

test("REQ-7.2-7(b) regression: at exactly two guardians, forced removal is unreachable -- majority of the FULL set (N=2 -> M=2) can never be met by the one remaining guardian alone", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const g2Did = "did:guardian:g2:example.com";
  const g1 = await generateKeypair();
  const g2 = await generateKeypair();
  const state = makeState({ did: wardDid, guardians: [g1Did, g2Did], guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, removal_threshold: "majority" } });
  // g2 tries to forcibly remove g1 without g1's consent -- this is exactly the N=2 unilateral-takeover bug the user caught.
  const partial = { type: "guardian_remove" as const, outgoing: g1Did, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey, [g2Did]: g2.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  const sigs = await signMap(partial, { [g2Did]: g2.privateKey }, [g2Did]); // only the OTHER guardian signs, not g1
  assert.equal(
    await OPERATION_RULES.guardian_remove.isSatisfied({ ...partial, sigs }, [], ctx),
    false,
    "one of two guardians must never be able to unilaterally eject the other",
  );
});

test("REQ-7.2-7(b): at three guardians, two of the other three meeting majority can forcibly remove the third", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const [g1Did, g2Did, g3Did] = ["g1", "g2", "g3"].map((n) => `did:guardian:${n}:example.com`);
  const [g1, g2, g3] = await Promise.all([generateKeypair(), generateKeypair(), generateKeypair()]);
  const state = makeState({ did: wardDid, guardians: [g1Did, g2Did, g3Did], guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, removal_threshold: "majority" } });
  const partial = { type: "guardian_remove" as const, outgoing: g3Did, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey, [g2Did]: g2.publicKey, [g3Did]: g3.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  const sigs = await signMap(partial, { [g1Did]: g1.privateKey, [g2Did]: g2.privateKey }, [g1Did, g2Did]);
  assert.equal(await OPERATION_RULES.guardian_remove.isSatisfied({ ...partial, sigs }, [], ctx), true);
});

test("REQ-7.2-6: removing the only current guardian is rejected -- guardian_relinquish is the correct operation for full dissolution", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const g1Did = "did:guardian:g1:example.com";
  const g1 = await generateKeypair();
  const state = makeState({ did: wardDid, guardians: [g1Did] });
  const partial = { type: "guardian_remove" as const, outgoing: g1Did, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  const sigs = await signMap(partial, { [g1Did]: g1.privateKey }, [g1Did]);
  assert.equal(await OPERATION_RULES.guardian_remove.isSatisfied({ ...partial, sigs }, [], ctx), false);
});

test("REQ-5-7: guardian_remove is rejected if it would bring the guardian count below min_guardian_count, even if otherwise satisfied", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const [g1Did, g2Did, g3Did] = ["g1", "g2", "g3"].map((n) => `did:guardian:${n}:example.com`);
  const [g1, g2, g3] = await Promise.all([generateKeypair(), generateKeypair(), generateKeypair()]);
  const state = makeState({
    did: wardDid,
    guardians: [g1Did, g2Did, g3Did],
    guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, removal_threshold: "any", min_guardian_count: 3 },
  });
  const partial = { type: "guardian_remove" as const, outgoing: g1Did, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey, [g2Did]: g2.publicKey, [g3Did]: g3.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  const sigs = await signMap(partial, { [g1Did]: g1.privateKey }, [g1Did]); // voluntary, would ordinarily succeed under "any"
  assert.equal(await OPERATION_RULES.guardian_remove.isSatisfied({ ...partial, sigs }, [], ctx), false);
});

// --- REQ-7.2-8, REQ-5-4: guardian_relinquish ------------------------------

test("REQ-7.2-8: guardian_relinquish needs enough current guardians to meet removal_threshold, evaluated against the full set", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const [g1Did, g2Did] = ["g1", "g2"].map((n) => `did:guardian:${n}:example.com`);
  const [g1, g2] = await Promise.all([generateKeypair(), generateKeypair()]);
  const state = makeState({ did: wardDid, guardians: [g1Did, g2Did], guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, removal_threshold: "unanimous" } });
  const partial = { type: "guardian_relinquish" as const, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey, [g2Did]: g2.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };

  const sigsOne = await signMap(partial, { [g1Did]: g1.privateKey }, [g1Did]);
  assert.equal(await OPERATION_RULES.guardian_relinquish.isSatisfied({ ...partial, sigs: sigsOne }, [], ctx), false);

  const sigsBoth = await signMap(partial, { [g1Did]: g1.privateKey, [g2Did]: g2.privateKey }, [g1Did, g2Did]);
  assert.equal(await OPERATION_RULES.guardian_relinquish.isSatisfied({ ...partial, sigs: sigsBoth }, [], ctx), true);
});

// --- REQ-7.2-9/10, REQ-5-6: policy_update ---------------------------------

test("REQ-7.2-10: policy_update is rejected while the current guardian set is empty", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const state = makeState({ did: wardDid, guardians: [] });
  const ctx: VerificationContext = { wardDid, state, resolveKey: makeResolver({}), isGuardianLive: allLive() };
  const op = { type: "policy_update" as const, policy: { ...DEFAULT_GUARDIAN_POLICY }, prev: "cid0", sigs: {} };
  const result = await OPERATION_RULES.policy_update.checkShape(op, ctx);
  assert.equal(result.valid, false);
  assert.match(result.reason!, /REQ-7\.2-10/);
});

test("REQ-5-6: policy_update is evaluated against the CURRENT policy_threshold, never the proposed new one", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const [g1Did, g2Did] = ["g1", "g2"].map((n) => `did:guardian:${n}:example.com`);
  const [g1, g2] = await Promise.all([generateKeypair(), generateKeypair()]);
  const state = makeState({ did: wardDid, guardians: [g1Did, g2Did], guardianPolicy: { ...DEFAULT_GUARDIAN_POLICY, policy_threshold: "any" } });
  const proposed: GuardianPolicy = { ...DEFAULT_GUARDIAN_POLICY, policy_threshold: "unanimous" };
  const partial = { type: "policy_update" as const, policy: proposed, prev: "cid0" };
  const resolveKey = makeResolver({ [g1Did]: g1.publicKey, [g2Did]: g2.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  const sigs = await signMap(partial, { [g1Did]: g1.privateKey }, [g1Did]); // one of two -- satisfies "any" (current), would fail "unanimous" (proposed)
  assert.equal(await OPERATION_RULES.policy_update.isSatisfied({ ...partial, sigs }, [], ctx), true);
});

// --- REQ-7.3-1, REQ-5-3: custodial_tombstone ------------------------------

test("REQ-7.3-1: the ward's own key alone satisfies tombstone under the default any-threshold", async () => {
  const wardDid = "did:guardian:alice:example.com";
  const ward = await generateKeypair();
  const state = makeState({ did: wardDid, guardians: [] });
  const partial = { type: "custodial_tombstone" as const, prev: "cid0" };
  const resolveKey = makeResolver({ [wardDid]: ward.publicKey });
  const ctx: VerificationContext = { wardDid, state, resolveKey, isGuardianLive: allLive() };
  const sigs = await signMap(partial, { [wardDid]: ward.privateKey }, [wardDid]);
  assert.equal(await OPERATION_RULES.custodial_tombstone.isSatisfied({ ...partial, sigs }, [], ctx), true);
});

// --- liveGuardians / REQ-4-4 helper --------------------------------------

test("REQ-4-4: liveGuardians excludes a deactivated guardian from the current set entirely", async () => {
  const state = makeState({ guardians: ["did:guardian:g1:example.com", "did:guardian:g2:example.com"] });
  const live = await liveGuardians(state, (did) => did !== "did:guardian:g1:example.com");
  assert.deepEqual(live, ["did:guardian:g2:example.com"]);
});

// --- REQ-5-1: threshold formula property tests ----------------------------

test("REQ-5-1: majority and unanimous coincide exactly at N=2 (M=2 for both) -- the boundary the two-guardian-deadlock design relies on", () => {
  assert.equal(requiredCount("majority", 2), 2);
  assert.equal(requiredCount("unanimous", 2), 2);
});

test("REQ-5-1: \"any\" over an empty eligible set is unsatisfiable", () => {
  assert.equal(meetsThreshold("any", [], []), false);
  assert.equal(requiredCount("any", 0), Infinity);
});

test("REQ-5-1 (property): majority quorum intersection -- any two signer sets that each independently meet majority over the same eligible set must share at least one member", () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 1, max: 20 }).chain((n) =>
        fc.record({
          n: fc.constant(n),
          setA: fc.subarray(Array.from({ length: n }, (_, i) => i), { minLength: Math.floor(n / 2) + 1 }),
          setB: fc.subarray(Array.from({ length: n }, (_, i) => i), { minLength: Math.floor(n / 2) + 1 }),
        }),
      ),
      ({ n, setA, setB }) => {
        const eligible = Array.from({ length: n }, (_, i) => String(i));
        const strA = setA.map(String);
        const strB = setB.map(String);
        assert.equal(meetsThreshold("majority", strA, eligible), true);
        assert.equal(meetsThreshold("majority", strB, eligible), true);
        const intersects = strA.some((x) => strB.includes(x));
        assert.equal(intersects, true, `setA=${JSON.stringify(strA)} setB=${JSON.stringify(strB)} n=${n} must intersect`);
      },
    ),
  );
});

test("REQ-5-1 (property): requiredCount(\"at_least\", k) never goes negative even for a negative k", () => {
  fc.assert(
    fc.property(fc.integer({ min: -50, max: 50 }), (k) => {
      assert.equal(requiredCount({ at_least: k }, 100) >= 0, true);
    }),
  );
});
