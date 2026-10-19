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

test("genesis with one consenting guardian verifies", () => {
  const ward = generateKeypair();
  const guardian = generateKeypair();
  const resolve = makeResolver({ "did:guardian:board:example:com": guardian.publicKeyPem });

  const op = signCustodialCreate(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKeyPem],
      verificationMethods: { "key-1": ward.publicKeyPem },
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board:example:com"],
      prev: null,
    },
    { "did:guardian:board:example:com": guardian.privateKeyPem },
  );

  const result = verifyCustodialCreate(op, resolve);
  assert.equal(result.valid, true, result.reason);
});

test("forged guardian claim fails -- the named party never signed", () => {
  const ward = generateKeypair();
  const realGuardian = generateKeypair();
  const impostorKey = generateKeypair(); // the attacker's own key, not the named guardian's
  const resolve = makeResolver({ "did:guardian:board:example:com": realGuardian.publicKeyPem });

  // Attacker builds a genesis op naming a real, unwilling party as guardian,
  // but signs with their own key instead of the named guardian's.
  const op = signCustodialCreate(
    {
      type: "custodial_create",
      name: "puppet",
      operationalKeys: [ward.publicKeyPem],
      verificationMethods: { "key-1": ward.publicKeyPem },
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board:example:com"],
      prev: null,
    },
    { "did:guardian:board:example:com": impostorKey.privateKeyPem }, // forged
  );

  const result = verifyCustodialCreate(op, resolve);
  assert.equal(result.valid, false, "a forged guardian claim must fail verification");
});

test("guardian_transfer requires both outgoing and incoming signatures", () => {
  const troy = generateKeypair();
  const caleb = generateKeypair();
  const resolve = makeResolver({
    "did:guardian:troy:example:com": troy.publicKeyPem,
    "did:guardian:caleb:example:com": caleb.publicKeyPem,
  });

  const op = signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:troy:example:com"], incoming: ["did:guardian:caleb:example:com"], prev: "abc123" },
    ["did:guardian:troy:example:com"],
    { "did:guardian:troy:example:com": troy.privateKeyPem, "did:guardian:caleb:example:com": caleb.privateKeyPem },
  );

  const result = verifyGuardianTransfer(op, ["did:guardian:troy:example:com"], resolve);
  assert.equal(result.valid, true, result.reason);
});

test("one co-guardian cannot unilaterally strip another's standing", () => {
  const troy = generateKeypair();
  const jane = generateKeypair();
  const resolve = makeResolver({
    "did:guardian:troy:example:com": troy.publicKeyPem,
    "did:guardian:jane:example:com": jane.publicKeyPem,
  });

  // Troy alone tries to remove Jane from a two-guardian set -- Jane's own signature is missing.
  const op = signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:jane:example:com"], incoming: [], prev: "abc123" },
    ["did:guardian:troy:example:com", "did:guardian:jane:example:com"],
    { "did:guardian:jane:example:com": troy.privateKeyPem }, // troy forges jane's slot with his own key
  );

  const result = verifyGuardianTransfer(op, ["did:guardian:troy:example:com", "did:guardian:jane:example:com"], resolve);
  assert.equal(result.valid, false, "removing jane without her own signature must fail");
});

test("tampering with signed content after signing invalidates the signature", () => {
  const ward = generateKeypair();
  const op = signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [ward.publicKeyPem], verificationMethods: {}, services: {}, prev: "abc123" },
    ward.privateKeyPem,
  );
  const tampered = { ...op, operationalKeys: ["did:key:attacker"] };
  const result = verifyCustodialRotate(tampered, [ward.publicKeyPem], () => undefined);
  assert.equal(result.valid, false);
});

test("a guardian who rotated their own keys signs with their new key, verified live -- no lock-out, no re-registration", () => {
  // Troy was established as a guardian under his old key, then rotated to a
  // new one (an ordinary custodial_rotate on his own identity, unrelated to
  // any ward). He's later named in `outgoing` (stepping down) and signs with
  // his *current* key. Verification always resolves live (spec §4.8) -- a
  // stale resolver still holding his old key must reject the signature
  // (it genuinely doesn't match), while the live, post-rotation resolver
  // accepts it with nothing special required on the ward's side at all.
  const troyOldKey = generateKeypair();
  const troyNewKey = generateKeypair();
  const resolveStale = makeResolver({ "did:guardian:troy:example:com": troyOldKey.publicKeyPem });
  const resolveFresh = makeResolver({ "did:guardian:troy:example:com": troyNewKey.publicKeyPem });

  const currentGuardians = ["did:guardian:troy:example:com"];
  const op = signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:troy:example:com"], incoming: [], prev: "cid0" },
    currentGuardians,
    { "did:guardian:troy:example:com": troyNewKey.privateKeyPem },
  );

  assert.equal(verifyGuardianTransfer(op, currentGuardians, resolveStale).valid, false, "signed with the new key, so a resolver still reporting the old one must reject it");
  assert.equal(verifyGuardianTransfer(op, currentGuardians, resolveFresh).valid, true, "the live, post-rotation resolver accepts it with no re-registration needed");
});

test("cidFor is deterministic for identical content", () => {
  const ward = generateKeypair();
  const op = signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [ward.publicKeyPem], verificationMethods: {}, services: {}, prev: "abc123" },
    ward.privateKeyPem,
  );
  assert.equal(cidFor(op), cidFor({ ...op }));
});
