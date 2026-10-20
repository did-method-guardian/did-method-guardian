import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "../src/crypto.js";
import {
  signCustodialCreate,
  verifyCustodialCreate,
  signGuardianTransfer,
  verifyGuardianTransfer,
  signCustodialRotate,
  verifyCustodialRotate,
  cidFor,
} from "../src/operations.js";
import type { KeyResolver } from "../src/operations.js";

function makeResolver(keys: Record<string, string>): KeyResolver {
  return (did) => (keys[did] ? [keys[did]] : undefined);
}

test("genesis with one consenting guardian verifies", async () => {
  const ward = await generateKeypair();
  const guardian = await generateKeypair();
  const resolve = makeResolver({ "did:guardian:board:example:com": guardian.publicKey });

  const op = await signCustodialCreate(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKey],
      verificationMethods: { "key-1": ward.publicKey },
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board:example:com"],
      prev: null,
    },
    { "did:guardian:board:example:com": guardian.privateKey },
  );

  const result = await verifyCustodialCreate(op, resolve);
  assert.equal(result.valid, true, result.reason);
});

test("forged guardian claim fails -- the named party never signed", async () => {
  const ward = await generateKeypair();
  const realGuardian = await generateKeypair();
  const impostorKey = await generateKeypair(); // the attacker's own key, not the named guardian's
  const resolve = makeResolver({ "did:guardian:board:example:com": realGuardian.publicKey });

  // Attacker builds a genesis op naming a real, unwilling party as guardian,
  // but signs with their own key instead of the named guardian's.
  const op = await signCustodialCreate(
    {
      type: "custodial_create",
      name: "puppet",
      operationalKeys: [ward.publicKey],
      verificationMethods: { "key-1": ward.publicKey },
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board:example:com"],
      prev: null,
    },
    { "did:guardian:board:example:com": impostorKey.privateKey }, // forged
  );

  const result = await verifyCustodialCreate(op, resolve);
  assert.equal(result.valid, false, "a forged guardian claim must fail verification");
});

test("guardian_transfer requires both outgoing and incoming signatures", async () => {
  const troy = await generateKeypair();
  const caleb = await generateKeypair();
  const resolve = makeResolver({
    "did:guardian:troy:example:com": troy.publicKey,
    "did:guardian:caleb:example:com": caleb.publicKey,
  });

  const op = await signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:troy:example:com"], incoming: ["did:guardian:caleb:example:com"], prev: "abc123" },
    ["did:guardian:troy:example:com"],
    { "did:guardian:troy:example:com": troy.privateKey, "did:guardian:caleb:example:com": caleb.privateKey },
  );

  const result = await verifyGuardianTransfer(op, ["did:guardian:troy:example:com"], resolve);
  assert.equal(result.valid, true, result.reason);
});

test("one co-guardian cannot unilaterally strip another's standing", async () => {
  const troy = await generateKeypair();
  const jane = await generateKeypair();
  const resolve = makeResolver({
    "did:guardian:troy:example:com": troy.publicKey,
    "did:guardian:jane:example:com": jane.publicKey,
  });

  // Troy alone tries to remove Jane from a two-guardian set -- Jane's own signature is missing.
  const op = await signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:jane:example:com"], incoming: [], prev: "abc123" },
    ["did:guardian:troy:example:com", "did:guardian:jane:example:com"],
    { "did:guardian:jane:example:com": troy.privateKey }, // troy forges jane's slot with his own key
  );

  const result = await verifyGuardianTransfer(op, ["did:guardian:troy:example:com", "did:guardian:jane:example:com"], resolve);
  assert.equal(result.valid, false, "removing jane without her own signature must fail");
});

test("tampering with signed content after signing invalidates the signature", async () => {
  const ward = await generateKeypair();
  const op = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [ward.publicKey], verificationMethods: {}, services: {}, prev: "abc123" },
    ward.privateKey,
  );
  const tampered = { ...op, operationalKeys: ["did:key:attacker"] };
  const result = await verifyCustodialRotate(tampered, [ward.publicKey], () => undefined);
  assert.equal(result.valid, false);
});

test("a guardian who rotated their own keys signs with their new key, verified live -- no lock-out, no re-registration", async () => {
  // Troy was established as a guardian under his old key, then rotated to a
  // new one (an ordinary custodial_rotate on his own identity, unrelated to
  // any ward). He's later named in `outgoing` (stepping down) and signs with
  // his *current* key. Verification always resolves live (spec §4.8) -- a
  // stale resolver still holding his old key must reject the signature
  // (it genuinely doesn't match), while the live, post-rotation resolver
  // accepts it with nothing special required on the ward's side at all.
  const troyOldKey = await generateKeypair();
  const troyNewKey = await generateKeypair();
  const resolveStale = makeResolver({ "did:guardian:troy:example:com": troyOldKey.publicKey });
  const resolveFresh = makeResolver({ "did:guardian:troy:example:com": troyNewKey.publicKey });

  const currentGuardians = ["did:guardian:troy:example:com"];
  const op = await signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:troy:example:com"], incoming: [], prev: "cid0" },
    currentGuardians,
    { "did:guardian:troy:example:com": troyNewKey.privateKey },
  );

  assert.equal((await verifyGuardianTransfer(op, currentGuardians, resolveStale)).valid, false, "signed with the new key, so a resolver still reporting the old one must reject it");
  assert.equal((await verifyGuardianTransfer(op, currentGuardians, resolveFresh)).valid, true, "the live, post-rotation resolver accepts it with no re-registration needed");
});

test("cidFor is deterministic for identical content", async () => {
  const ward = await generateKeypair();
  const op = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [ward.publicKey], verificationMethods: {}, services: {}, prev: "abc123" },
    ward.privateKey,
  );
  assert.equal(await cidFor(op), await cidFor({ ...op }));
});
