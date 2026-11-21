import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair, signPayload } from "../src/crypto.js";
import {
  signCustodialCreate,
  verifyCustodialCreate,
  signGuardianTransfer,
  verifyGuardianTransfer,
  signCustodialRotate,
  verifyCustodialRotate,
  signRegistrarAttestation,
  verifySignerProof,
  unsecuredDocument,
  createProof,
  cidFor,
} from "../src/operations.js";
import type { KeyResolver } from "../src/operations.js";
import type { CustodialCreateOp, Did } from "../src/types.js";

function makeResolver(keys: Record<string, string>): KeyResolver {
  return (did) => (keys[did] ? [keys[did]] : undefined);
}

const REGISTRAR_DID: Did = "did:guardian:example.com";

test("REQ-7.1-5: a registrar attestation signs over genesis's own content without covering its own not-yet-computed signature value", async () => {
  const ward = await generateKeypair();
  const registrar = await generateKeypair();
  const resolve = makeResolver({ [REGISTRAR_DID]: registrar.publicKey });

  const partial: Omit<CustodialCreateOp, "proof" | "creator"> = {
    type: "custodial_create",
    did: "did:guardian:example.com:alice",
    name: "alice",
    operationalKeys: [ward.publicKey],
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
  };
  const withCreator = { ...partial, creator: REGISTRAR_DID };
  const attestation = await signRegistrarAttestation(withCreator, REGISTRAR_DID, registrar.privateKey);
  const signed = await signCustodialCreate(withCreator, {}, { [ward.publicKey]: ward.privateKey });
  const genesis = { ...signed, proof: [...signed.proof, attestation] };

  const result = await verifyCustodialCreate(genesis, resolve, REGISTRAR_DID);
  assert.equal(result.valid, true, result.reason);
});

test("REQ-7.1-5: a forged registrar attestation (wrong key) is rejected", async () => {
  const ward = await generateKeypair();
  const impostor = await generateKeypair();
  const realRegistrarKey = await generateKeypair();
  const resolve = makeResolver({ [REGISTRAR_DID]: realRegistrarKey.publicKey }); // verifier resolves the REAL key, not the impostor's

  const partial: Omit<CustodialCreateOp, "proof" | "creator"> = {
    type: "custodial_create",
    did: "did:guardian:example.com:alice",
    name: "alice",
    operationalKeys: [ward.publicKey],
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
  };
  const withCreator = { ...partial, creator: REGISTRAR_DID };
  const forgedAttestation = await signRegistrarAttestation(withCreator, REGISTRAR_DID, impostor.privateKey);
  const signed = await signCustodialCreate(withCreator, {}, { [ward.publicKey]: ward.privateKey });
  const genesis = { ...signed, proof: [...signed.proof, forgedAttestation] };

  const result = await verifyCustodialCreate(genesis, resolve, REGISTRAR_DID);
  assert.equal(result.valid, false);
});

/** A valid registrar attestation (REQ-7.1-5) over `partial`, plus a resolver that already knows the registrar's key -- shared by tests below that aren't themselves testing the attestation, so they can still construct an otherwise-valid genesis. `operationalPrivateKeys` satisfies REQ-7.1-8's proof of possession. */
async function attestedGenesis(
  partial: Omit<CustodialCreateOp, "proof" | "creator">,
  incomingKeys: Record<string, string>,
  registrar: { publicKey: string; privateKey: string },
  operationalPrivateKeys: Record<string, string>,
) {
  const withCreator = { ...partial, creator: REGISTRAR_DID };
  const registrarAttestation = await signRegistrarAttestation(withCreator, REGISTRAR_DID, registrar.privateKey);
  const signed = await signCustodialCreate(withCreator, incomingKeys, operationalPrivateKeys);
  return { ...signed, proof: [...signed.proof, registrarAttestation] };
}

test("genesis with one consenting guardian verifies", async () => {
  const ward = await generateKeypair();
  const guardian = await generateKeypair();
  const registrar = await generateKeypair();
  const resolve = makeResolver({ "did:guardian:example.com:board": guardian.publicKey, [REGISTRAR_DID]: registrar.publicKey });

  const op = await attestedGenesis(
    {
      type: "custodial_create",
      did: "did:guardian:example.com:fred",
      name: "fred",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:example.com:board"],
      prev: null,
    },
    { "did:guardian:example.com:board": guardian.privateKey },
    registrar,
    { [ward.publicKey]: ward.privateKey },
  );

  const result = await verifyCustodialCreate(op, resolve, REGISTRAR_DID);
  assert.equal(result.valid, true, result.reason);
});

test("forged guardian claim fails -- the named party never signed", async () => {
  const ward = await generateKeypair();
  const realGuardian = await generateKeypair();
  const impostorKey = await generateKeypair(); // the attacker's own key, not the named guardian's
  const registrar = await generateKeypair();
  const resolve = makeResolver({ "did:guardian:example.com:board": realGuardian.publicKey, [REGISTRAR_DID]: registrar.publicKey });

  // Attacker builds a genesis op naming a real, unwilling party as guardian,
  // but signs with their own key instead of the named guardian's. A real
  // registrar attestation is still attached -- this test is specifically
  // about the forged guardian signature, not REQ-7.1-5.
  const op = await attestedGenesis(
    {
      type: "custodial_create",
      did: "did:guardian:example.com:puppet",
      name: "puppet",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:example.com:board"],
      prev: null,
    },
    { "did:guardian:example.com:board": impostorKey.privateKey }, // forged
    registrar,
    { [ward.publicKey]: ward.privateKey },
  );

  const result = await verifyCustodialCreate(op, resolve, REGISTRAR_DID);
  assert.equal(result.valid, false, "a forged guardian claim must fail verification");
});

test("REQ-7.1-5: genesis with no registrar attestation at all is rejected", async () => {
  const ward = await generateKeypair();
  const resolve = makeResolver({});

  const op = await signCustodialCreate(
    {
      type: "custodial_create",
      did: "did:guardian:example.com:alice",
      name: "alice",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: [],
      prev: null,
      creator: REGISTRAR_DID,
      // no registrar attestation appended to proof -- this is the thing under test
    },
    {},
    { [ward.publicKey]: ward.privateKey }, // valid proof of possession, so this fails for the registrar-attestation reason, not this one
  );

  const result = await verifyCustodialCreate(op, resolve, REGISTRAR_DID);
  assert.equal(result.valid, false, "genesis with no registrar attestation must be rejected");
});

test("audit WS-4.4: a registrarDid that isn't the domain root of genesis.did is rejected, even with a real, valid signature from that DID", async () => {
  const ward = await generateKeypair();
  const evilDid: Did = "did:guardian:evil.example";
  const evilRegistrar = await generateKeypair();
  const resolve = makeResolver({ [evilDid]: evilRegistrar.publicKey });

  const partial: Omit<CustodialCreateOp, "proof" | "creator"> = {
    type: "custodial_create",
    did: "did:guardian:example.com:alice", // the genesis is for example.com
    name: "alice",
    operationalKeys: [ward.publicKey],
    services: {},
    outgoing: [],
    incoming: [],
    prev: null,
  };
  const withCreator = { ...partial, creator: evilDid };
  const genesis = await signCustodialCreate(withCreator, {}, { [ward.publicKey]: ward.privateKey });
  const evilAttestation = await signRegistrarAttestation(withCreator, evilDid, evilRegistrar.privateKey); // a REAL, validly-signed attestation...
  const op = { ...genesis, proof: [...genesis.proof, evilAttestation] };

  const result = await verifyCustodialCreate(op, resolve, evilDid); // ...but evil.example is not example.com's own domain root
  assert.equal(result.valid, false, "a genesis for example.com attested by a different domain's registrar must never pass, regardless of whether that attestation is genuinely validly signed");
});

test("audit WS-1.7: an unexplained extra proof in the genesis proof set is rejected, even when every required proof is also present and valid", async () => {
  const ward = await generateKeypair();
  const registrar = await generateKeypair();
  const evilDid: Did = "did:guardian:evil.example";
  const evil = await generateKeypair();
  const genesisDid: Did = "did:guardian:example.com:alice";
  const resolve = makeResolver({ [REGISTRAR_DID]: registrar.publicKey });

  const op = await attestedGenesis(
    { type: "custodial_create", did: genesisDid, name: "alice", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    registrar,
    { [ward.publicKey]: ward.privateKey },
  );
  const unsecuredDoc = unsecuredDocument(op as any);
  const strayProof = await createProof(unsecuredDoc, `${evilDid}#key-0`, evil.privateKey); // a real signature, but from nobody this genesis names anywhere
  const poisoned = { ...op, proof: [...op.proof, strayProof] };

  const result = await verifyCustodialCreate(poisoned, resolve, REGISTRAR_DID);
  assert.equal(result.valid, false, "a stray proof not tied to any operational key, incoming guardian, or the registrar must be rejected outright, not silently ignored");
});

test("audit WS-1.8: a genesis naming a malformed policy field is rejected, not merged blindly into default state", async () => {
  const ward = await generateKeypair();
  const registrar = await generateKeypair();
  const resolve = makeResolver({ [REGISTRAR_DID]: registrar.publicKey });

  const op = await attestedGenesis(
    {
      type: "custodial_create",
      did: "did:guardian:example.com:alice",
      name: "alice",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: [],
      prev: null,
      policy: { recovery_threshold: "literally_anything" } as any, // REQ-7.1-7's own field is Partial -- malformed even partially
    },
    {},
    registrar,
    { [ward.publicKey]: ward.privateKey },
  );

  const result = await verifyCustodialCreate(op, resolve, REGISTRAR_DID);
  assert.equal(result.valid, false, "a genesis must never be accepted with a policy that would leave the ward unverifiable from its first post-genesis operation onward");
});

const WARD_DID: Did = "did:guardian:fred:example:com";

test("guardian_transfer establishes a guardian from zero (empty outgoing, non-empty incoming) -- requires BOTH the incoming guardian's consent AND the ward's own", async () => {
  const ward = await generateKeypair();
  const board = await generateKeypair();
  const boardDid = "did:guardian:example.com:board";
  const resolve = makeResolver({ [boardDid]: board.publicKey, [WARD_DID]: ward.publicKey });

  const op = await signGuardianTransfer(
    { type: "guardian_transfer", outgoing: [], incoming: [boardDid], prev: "cid0" },
    WARD_DID,
    [], // currently guardian-less
    { [boardDid]: board.privateKey, [WARD_DID]: ward.privateKey },
  );

  const result = await verifyGuardianTransfer(op, WARD_DID, [], resolve);
  assert.equal(result.valid, true, result.reason);
});

test("establishing a guardian from zero without the ward's own consent is rejected -- otherwise anyone could impose guardianship unilaterally", async () => {
  const board = await generateKeypair();
  const boardDid = "did:guardian:example.com:board";
  const resolve = makeResolver({ [boardDid]: board.publicKey }); // no key registered for WARD_DID at all -- stands in for "the ward never signed"

  // Built by hand, not via signGuardianTransfer -- that helper refuses to
  // produce an under-signed operation at all, which is correct for honest
  // callers but means this adversarial case (a guardian signs, the ward
  // doesn't) has to be constructed directly, the same way the other forgery
  // tests above do.
  const unsigned = { type: "guardian_transfer" as const, outgoing: [], incoming: [boardDid], prev: "cid0" };
  const op = { ...unsigned, sigs: { [boardDid]: await signPayload(unsigned, board.privateKey) } };

  const result = await verifyGuardianTransfer(op, WARD_DID, [], resolve);
  assert.equal(result.valid, false, "a willing guardian alone must not be enough to impose guardianship on an autonomous ward");
});

test("guardian_transfer with empty incoming is rejected -- that shape is guardian_relinquish's, not this operation's", async () => {
  const troy = await generateKeypair();
  const resolve = makeResolver({ "did:guardian:troy:example:com": troy.publicKey });

  const op = await signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:troy:example:com"], incoming: [], prev: "cid0" },
    WARD_DID,
    ["did:guardian:troy:example:com"],
    { "did:guardian:troy:example:com": troy.privateKey },
  );

  const result = await verifyGuardianTransfer(op, WARD_DID, ["did:guardian:troy:example:com"], resolve);
  assert.equal(result.valid, false, "full removal with no replacement must go through guardian_relinquish instead");
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
    WARD_DID,
    ["did:guardian:troy:example:com"],
    { "did:guardian:troy:example:com": troy.privateKey, "did:guardian:caleb:example:com": caleb.privateKey },
  );

  const result = await verifyGuardianTransfer(op, WARD_DID, ["did:guardian:troy:example:com"], resolve);
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
    WARD_DID,
    ["did:guardian:troy:example:com", "did:guardian:jane:example:com"],
    { "did:guardian:jane:example:com": troy.privateKey }, // troy forges jane's slot with his own key
  );

  const result = await verifyGuardianTransfer(op, WARD_DID, ["did:guardian:troy:example:com", "did:guardian:jane:example:com"], resolve);
  assert.equal(result.valid, false, "removing jane without her own signature must fail");
});

test("tampering with signed content after signing invalidates the signature", async () => {
  const ward = await generateKeypair();
  const op = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [ward.publicKey], services: {}, prev: "abc123" },
    WARD_DID,
    ward.privateKey,
    { [ward.publicKey]: ward.privateKey },
  );
  const tampered = { ...op, operationalKeys: ["did:key:attacker"] };
  const result = await verifyCustodialRotate(tampered, [ward.publicKey], () => undefined);
  assert.equal(result.valid, false);
});

test("a guardian who rotated their own keys signs with their new key, verified live -- no lock-out, no re-registration", async () => {
  // Troy was established as a guardian under his old key, then rotated to a
  // new one (an ordinary custodial_rotate on his own identity, unrelated to
  // any ward). He's later named in `outgoing` (stepping down, replaced by
  // caleb) and signs with his *current* key. Verification always resolves
  // live (spec §4.8) -- a stale resolver still holding his old key must
  // reject the signature (it genuinely doesn't match), while the live,
  // post-rotation resolver accepts it with nothing special required on the
  // ward's side at all.
  const troyOldKey = await generateKeypair();
  const troyNewKey = await generateKeypair();
  const caleb = await generateKeypair();
  const resolveStale = makeResolver({ "did:guardian:troy:example:com": troyOldKey.publicKey, "did:guardian:caleb:example:com": caleb.publicKey });
  const resolveFresh = makeResolver({ "did:guardian:troy:example:com": troyNewKey.publicKey, "did:guardian:caleb:example:com": caleb.publicKey });

  const currentGuardians = ["did:guardian:troy:example:com"];
  const op = await signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:troy:example:com"], incoming: ["did:guardian:caleb:example:com"], prev: "cid0" },
    WARD_DID,
    currentGuardians,
    { "did:guardian:troy:example:com": troyNewKey.privateKey, "did:guardian:caleb:example:com": caleb.privateKey },
  );

  assert.equal((await verifyGuardianTransfer(op, WARD_DID, currentGuardians, resolveStale)).valid, false, "signed with the new key, so a resolver still reporting the old one must reject it");
  assert.equal((await verifyGuardianTransfer(op, WARD_DID, currentGuardians, resolveFresh)).valid, true, "the live, post-rotation resolver accepts it with no re-registration needed");
});

test("REQ-4-2: verifySignerProof's own asOf parameter resolves a signer's key as of a given time, not whatever the resolver reports as current", async () => {
  // A signature collected asynchronously (registrar API spec §3) can
  // outlive its own signer's later key rotation -- it was genuinely valid
  // when produced, and REQ-4-2 requires it stay verifiable against the key
  // that was actually valid at that moment, not whatever's current by the
  // time a (possibly much later) verification happens. A resolver that's
  // asOf-aware reports differently depending on the timestamp it's asked
  // about; verifySignerProof must pass its own asOf argument through rather
  // than silently ignoring it.
  const signerDid: Did = "did:guardian:example.com:g1";
  const oldKey = await generateKeypair();
  const newKey = await generateKeypair();
  const rotatedAt = new Date("2026-06-01T00:00:00Z");
  const resolve: KeyResolver = (_did, asOf) => {
    if (asOf && asOf.getTime() < rotatedAt.getTime()) return [oldKey.publicKey];
    return [newKey.publicKey];
  };

  const newKeyPair = await generateKeypair();
  const op = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [newKeyPair.publicKey], services: {}, prev: "cid0" },
    signerDid,
    oldKey.privateKey,
    { [newKeyPair.publicKey]: newKeyPair.privateKey }, // not under test here -- this test only checks verifySignerProof's asOf behavior against op.proof
  );
  const signedAt = new Date("2026-05-01T00:00:00Z"); // before rotatedAt
  const unsecuredDoc = unsecuredDocument(op);

  assert.equal(await verifySignerProof(unsecuredDoc, op.proof, signerDid, resolve, signedAt), true, "verified as of when it was actually signed, against the key valid then");
  assert.equal(await verifySignerProof(unsecuredDoc, op.proof, signerDid, resolve), false, "verified with no asOf (i.e. 'now', after rotation) against the signer's current key must fail -- it's genuinely a different key");
});

test("cidFor is deterministic for identical content", async () => {
  const ward = await generateKeypair();
  const op = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [ward.publicKey], services: {}, prev: "abc123" },
    WARD_DID,
    ward.privateKey,
    { [ward.publicKey]: ward.privateKey },
  );
  assert.equal(await cidFor(op), await cidFor({ ...op }));
});
