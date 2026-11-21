// Generates interop_tests/operation_log fixtures using the reference
// implementation itself, so every fixture is a genuinely valid (or
// deliberately, specifically invalid) signed operation log -- not hand-typed
// data that merely looks plausible. Build the lib (tsc) then:
//   node dist/scripts/gen-fixtures.js
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeypair } from "../src/crypto.js";
import {
  signCustodialCreate,
  signCustodialRotate,
  signGuardianAdd,
  signGuardianTransfer,
  signGuardianRelinquish,
  signCustodialTombstone,
  signPolicyUpdate,
  signRegistrarAttestation,
  createProof,
  unsecuredDocument,
  popVerificationMethod,
  cidFor,
} from "../src/operations.js";
import { DEFAULT_GUARDIAN_POLICY } from "../src/types.js";
import type { CustodialCreateOp, Did, LogEntry } from "../src/types.js";

// `here` is dist/scripts when run compiled -- repo root is four levels up
// (scripts -> dist -> lib -> packages -> repo root).
const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "..", "..", "..", "interop_tests", "operation_log");

/**
 * `known_keys` maps every DID referenced as a signer in this fixture's log to
 * its public key (Multikey) -- a test-harness convenience. In a real
 * deployment each signer's key is resolved independently through its own
 * identity (spec §5); a single fixture file bundling them is specifically so
 * this interop suite is checkable in isolation, without standing up real
 * resolvable identities for every guardian referenced. `registrar_did`
 * (v0.4) names which DID's own proof to check genesis's registrar
 * attestation against (verifyCustodialCreate's 3rd argument) -- every
 * fixture carrying a custodial_create needs this, even an "accept" one
 * that's actually a root identity attesting its own genesis (Fix 7).
 */
function write(
  subdir: "valid" | "invalid",
  name: string,
  log: LogEntry[],
  note: string,
  knownKeys: Record<string, string>,
  expect: "accept" | "reject",
  registrarDidForFixture: Did = registrarDid,
) {
  const dir = join(outDir, subdir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${name}.json`), JSON.stringify({ note, expect, known_keys: knownKeys, registrar_did: registrarDidForFixture, log }, null, 2) + "\n");
  console.log(`wrote ${subdir}/${name}.json`);
}

const wardDid: Did = "did:guardian:fred:example:com";
const ward = await generateKeypair();
const boardA = await generateKeypair();
const boardB = await generateKeypair();
const impostor = await generateKeypair();

// One registrar identity, reused across every fixture below -- REQ-7.1-5
// requires every genesis to carry this attestation; `registrarKnownKeys`
// gets merged into every fixture's own `known_keys` so the test harness can
// resolve it, same as any other signer.
const registrarDid: Did = "did:guardian:example:com";
const registrar = await generateKeypair();
const registrarKnownKeys = { [registrarDid]: registrar.publicKey };

/**
 * Attaches a real registrar attestation (REQ-7.1-5) to a genesis op after
 * it's otherwise fully signed -- matches what registrar.ts's acceptGenesis
 * actually does: sign the ward/guardian side first, then append the
 * registrar's own proof to the same `proof` array. `operationalPrivateKeys`
 * satisfies REQ-7.1-8's proof of possession.
 */
async function signGenesis(
  partial: Omit<CustodialCreateOp, "proof" | "creator">,
  incomingKeys: Record<Did, string>,
  operationalPrivateKeys: Record<string, string>,
): Promise<CustodialCreateOp> {
  const withCreator = { ...partial, creator: registrarDid };
  const signed = await signCustodialCreate(withCreator, incomingKeys, operationalPrivateKeys);
  const attestation = await signRegistrarAttestation(withCreator, registrarDid, registrar.privateKey);
  return { ...signed, proof: [...signed.proof, attestation] };
}

// --- valid: genesis with a two-member initial guardian set ---
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: wardDid,
      name: "fred",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
      prev: null,
    },
    { "did:guardian:board-a:example:com": boardA.privateKey, "did:guardian:board-b:example:com": boardB.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  write(
    "valid",
    "genesis_two_guardians",
    [{ cid: await cidFor(genesis), op: genesis }],
    "Genesis establishing a two-member guardian set, both consenting.",
    { "did:guardian:board-a:example:com": boardA.publicKey, "did:guardian:board-b:example:com": boardB.publicKey, ...registrarKnownKeys },
    "accept",
  );
}

// --- valid: genesis -> rotate -> guardian_transfer (board-a steps down, board-c joins) ---
{
  const boardC = await generateKeypair();
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: wardDid,
      name: "fred",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
      prev: null,
    },
    { "did:guardian:board-a:example:com": boardA.privateKey, "did:guardian:board-b:example:com": boardB.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);

  const newWardKey = await generateKeypair();
  const rotate = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [newWardKey.publicKey], services: {}, prev: genesisCid },
    wardDid,
    ward.privateKey,
    { [newWardKey.publicKey]: newWardKey.privateKey },
  );
  const rotateCid = await cidFor(rotate);

  const transfer = await signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:board-a:example:com"], incoming: ["did:guardian:board-b:example:com", "did:guardian:board-c:example:com"], prev: rotateCid },
    wardDid,
    ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
    { "did:guardian:board-a:example:com": boardA.privateKey, "did:guardian:board-c:example:com": boardC.privateKey },
  );

  write(
    "valid",
    "rotate_then_guardian_transfer",
    [
      { cid: genesisCid, op: genesis },
      { cid: rotateCid, op: rotate },
      { cid: await cidFor(transfer), op: transfer },
    ],
    "Genesis, an ordinary operational-key rotation, then board-a steps down and board-c joins -- board-b continues and does not re-sign.",
    {
      "did:guardian:board-a:example:com": boardA.publicKey,
      "did:guardian:board-b:example:com": boardB.publicKey,
      "did:guardian:board-c:example:com": boardC.publicKey,
      ...registrarKnownKeys,
    },
    "accept",
  );
}

// --- valid: guardian_relinquish reaching full autonomy ---
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: wardDid,
      name: "fred",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
      prev: null,
    },
    { "did:guardian:board-a:example:com": boardA.privateKey, "did:guardian:board-b:example:com": boardB.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const relinquish = await signGuardianRelinquish(
    { type: "guardian_relinquish", prev: genesisCid },
    { "did:guardian:board-a:example:com": boardA.privateKey, "did:guardian:board-b:example:com": boardB.privateKey },
    ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
  );
  write(
    "valid",
    "guardian_relinquish_unanimous",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(relinquish), op: relinquish }],
    "Both guardians sign off on full relinquishment -- meets the default majority (here, unanimous since n=2) threshold.",
    { "did:guardian:board-a:example:com": boardA.publicKey, "did:guardian:board-b:example:com": boardB.publicKey, ...registrarKnownKeys },
    "accept",
  );
}

// --- valid: tombstone, any single current key ---
{
  const genesis = await signGenesis(
    { type: "custodial_create", did: wardDid, name: "fred", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const tombstone = await signCustodialTombstone({ type: "custodial_tombstone", prev: genesisCid }, { [wardDid]: ward.privateKey }, [wardDid]);
  write(
    "valid",
    "tombstone_any_single_key",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(tombstone), op: tombstone }],
    "Guardian-less ward tombstoning itself via its own operational key (resolved under its own DID), meeting the default `any` tombstone_threshold.",
    { [wardDid]: ward.publicKey, ...registrarKnownKeys },
    "accept",
  );
}

// --- valid: standalone guardian_add (zero-to-one case, REQ-7.2-5) on an otherwise guardian-less ward -- issue #6 ---
{
  const genesis = await signGenesis(
    { type: "custodial_create", did: wardDid, name: "fred", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const boardDid: Did = "did:guardian:board:example:com";
  const addOp = await signGuardianAdd(
    { type: "guardian_add", incoming: boardDid, prev: genesisCid },
    { [boardDid]: boardA.privateKey, [wardDid]: ward.privateKey }, // REQ-7.2-5: zero-to-one needs both the incoming guardian's key and the ward's
    [boardDid, wardDid],
  );
  write(
    "valid",
    "guardian_add_zero_to_one",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(addOp), op: addOp }],
    "A standalone guardian_add establishing the first guardian for a previously guardian-less ward -- both the incoming guardian's and the ward's signatures are present (REQ-7.2-5).",
    { [wardDid]: ward.publicKey, [boardDid]: boardA.publicKey, ...registrarKnownKeys },
    "accept",
  );
}

// --- valid (Fix 7): the bare-domain root identity attests its own genesis -- no other registrar attestation exists or is needed ---
{
  const rootDid: Did = "did:guardian:example:com"; // the SAME identity as `registrarDid` elsewhere in this file -- here it's attesting ITSELF, not some other ward
  const genesisPartial = { type: "custodial_create" as const, did: rootDid, name: "", operationalKeys: [registrar.publicKey], services: {}, outgoing: [] as [], incoming: [] as Did[], prev: null, creator: rootDid };
  const signed = await signCustodialCreate(genesisPartial, {}, { [registrar.publicKey]: registrar.privateKey });
  write(
    "valid",
    "root_genesis_self_attestation",
    [{ cid: await cidFor(signed), op: signed }],
    "Fix 7: the bare-domain root identity's own genesis carries only its own proof of possession -- no separate registrar attestation exists, because there is no other party on this deployment to vouch for it. verifyCustodialCreate must accept this when op.did === registrarDid.",
    { [rootDid]: registrar.publicKey },
    "accept",
    rootDid,
  );
}

// --- invalid: standalone guardian_add missing the ward's required signature (REQ-7.2-5) ---
{
  const genesis = await signGenesis(
    { type: "custodial_create", did: "did:guardian:puppet2:example:com", name: "puppet2", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const boardDid: Did = "did:guardian:board:example:com";
  const unsigned = { type: "guardian_add" as const, incoming: boardDid, prev: genesisCid };
  const boardProof = await createProof(unsecuredDocument(unsigned as any), `${boardDid}#key-0`, boardA.privateKey);
  const addOp = { ...unsigned, proof: [boardProof] }; // the ward never signs
  write(
    "invalid",
    "guardian_add_missing_ward_signature",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(addOp), op: addOp }],
    "REJECT: establishing a guardian from zero needs both the incoming guardian's and the ward's signature (REQ-7.2-5) -- here only the incoming guardian signed.",
    { "did:guardian:puppet2:example:com": ward.publicKey, [boardDid]: boardA.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: forged guardian claim (genesis names a guardian who never signed) ---
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: "did:guardian:puppet:example:com",
      name: "puppet",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com"],
      prev: null,
    },
    { "did:guardian:board-a:example:com": impostor.privateKey }, // forged: not board-a's real key
    { [ward.publicKey]: ward.privateKey },
  );
  write(
    "invalid",
    "forged_guardian_claim",
    [{ cid: await cidFor(genesis), op: genesis }],
    "REJECT: 'board-a' is named as initial guardian but the proof was produced by a different, impostor key -- must fail verification against board-a's real, resolved public key.",
    { "did:guardian:board-a:example:com": boardA.publicKey, ...registrarKnownKeys }, // the REAL board-a key -- the fixture's proof won't match it
    "reject",
  );
}

// --- invalid: genesis names an incoming guardian at genesis (v0.3, REQ-7.1-1) who never co-signed at all -- no proof entry, not even a forged one ---
// Built directly, not via signGenesis -- that helper (signCustodialCreate)
// refuses to produce an under-signed operation at all, which is correct
// for honest callers but means this adversarial case has to be
// constructed by hand, the same way the other forgery fixtures above do.
{
  const did: Did = "did:guardian:unsigned:example:com";
  const withCreator = {
    type: "custodial_create" as const,
    did,
    name: "unsigned",
    operationalKeys: [ward.publicKey],
    services: {},
    outgoing: [] as [],
    incoming: ["did:guardian:board-a:example:com"] as Did[],
    prev: null,
    creator: registrarDid,
  };
  const registrarAttestation = await signRegistrarAttestation(withCreator, registrarDid, registrar.privateKey);
  const unsecuredDoc = unsecuredDocument(withCreator as any);
  const wardPop = await createProof(unsecuredDoc, popVerificationMethod(ward.publicKey), ward.privateKey);
  const genesis = { ...withCreator, proof: [wardPop, registrarAttestation] }; // board-a never signs at all
  write(
    "invalid",
    "genesis_unsigned_incoming_guardian",
    [{ cid: await cidFor(genesis), op: genesis }],
    "REJECT: 'board-a' is named as an incoming guardian directly at genesis (REQ-7.1-1, v0.3) but carries no proof at all -- establishing a guardian this way still requires that guardian's consent.",
    { "did:guardian:board-a:example:com": boardA.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: guardian_transfer missing the removed guardian's own signature ---
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: wardDid,
      name: "fred",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:troy:example:com", "did:guardian:jane:example:com"],
      prev: null,
    },
    { "did:guardian:troy:example:com": boardA.privateKey, "did:guardian:jane:example:com": boardB.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const transfer = await signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:jane:example:com"], incoming: ["did:guardian:troy:example:com"], prev: genesisCid },
    wardDid,
    ["did:guardian:troy:example:com", "did:guardian:jane:example:com"],
    { "did:guardian:jane:example:com": boardA.privateKey }, // troy forges jane's own removal signature
  );
  write(
    "invalid",
    "unilateral_coguardian_removal",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(transfer), op: transfer }],
    "REJECT: troy attempts to remove jane from a two-guardian set, but the proof claimed as jane's was produced with troy's own key, not jane's.",
    { "did:guardian:troy:example:com": boardA.publicKey, "did:guardian:jane:example:com": boardB.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: quorum not met (majority required, only one of three signs) ---
{
  const boardC = await generateKeypair();
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: wardDid,
      name: "fred",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com", "did:guardian:board-c:example:com"],
      prev: null,
    },
    {
      "did:guardian:board-a:example:com": boardA.privateKey,
      "did:guardian:board-b:example:com": boardB.privateKey,
      "did:guardian:board-c:example:com": boardC.privateKey,
    },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  // Only board-a signs the relinquish; default removal/relinquish bar is
  // majority (2 of 3) -- this must NOT be accepted.
  const relinquish = await signGuardianRelinquish(
    { type: "guardian_relinquish", prev: genesisCid },
    { "did:guardian:board-a:example:com": boardA.privateKey },
    ["did:guardian:board-a:example:com"],
  );
  write(
    "invalid",
    "relinquish_quorum_not_met",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(relinquish), op: relinquish }],
    "REJECT: three guardians exist, default removal/relinquish threshold is majority (2 of 3), but only board-a signed.",
    {
      "did:guardian:board-a:example:com": boardA.publicKey,
      "did:guardian:board-b:example:com": boardB.publicKey,
      "did:guardian:board-c:example:com": boardC.publicKey,
      ...registrarKnownKeys,
    },
    "reject",
  );
}

// --- invalid: genesis with no registrar attestation at all (REQ-7.1-5) ---
{
  const genesis = await signCustodialCreate(
    {
      type: "custodial_create",
      did: wardDid,
      name: "fred",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: [],
      prev: null,
      creator: registrarDid,
      // no registrar attestation appended to proof -- the thing under test
    },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  write(
    "invalid",
    "genesis_missing_registrar_attestation",
    [{ cid: await cidFor(genesis), op: genesis }],
    "REJECT: genesis carries no registrar attestation at all -- REQ-7.1-5 requires one on every genesis, not only when a registrar happens to include it.",
    { ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid (Fix 1): an operational key's proof of possession is signed by a DIFFERENT key than the one actually listed in operationalKeys ---
// Before this fix, a separate verificationMethods map meant nothing cross-checked
// the DID Document's presented key against the key that actually proved
// possession -- an attacker could present a victim's key in the document
// while only ever controlling a different one. The new model has no
// separate map to desync, but the underlying proof-of-possession check
// itself still has to actually look at `operationalKeys`, not just at
// whether SOME valid proof happens to be attached.
{
  const impostorOperationalKey = impostor.publicKey; // the key an attacker actually controls
  const victimKeyClaimedInDocument = ward.publicKey; // the key an attacker wants the document to show instead
  const partial = { type: "custodial_create" as const, did: "did:guardian:keyswap:example:com", name: "keyswap", operationalKeys: [victimKeyClaimedInDocument], services: {}, outgoing: [] as [], incoming: [] as Did[], prev: null, creator: registrarDid };
  const unsecuredDoc = unsecuredDocument(partial as any);
  // The attacker can only produce a PoP proof for the key they actually
  // hold (impostorOperationalKey), never for victimKeyClaimedInDocument --
  // but its verificationMethod claims the SAME did:key: self-reference
  // scheme either way, so this exercises whether verification actually
  // walks `operationalKeys` and demands a matching proof for EACH one,
  // rather than accepting any one valid-looking PoP proof as sufficient.
  const wrongKeyPop = await createProof(unsecuredDoc, popVerificationMethod(impostorOperationalKey), impostor.privateKey);
  const attestation = await signRegistrarAttestation(partial, registrarDid, registrar.privateKey);
  const genesis = { ...partial, proof: [wrongKeyPop, attestation] };
  write(
    "invalid",
    "genesis_pop_key_mismatch",
    [{ cid: await cidFor(genesis), op: genesis }],
    "Fix 1 (PoP bypass): operationalKeys names a key the attacker does not hold; the only proof of possession attached is for a DIFFERENT key the attacker actually controls. Must reject -- a valid proof for the wrong key is not proof of possession of the right one.",
    { ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid (Fix 6): a policy version newer than this verifier understands must block EVERY operation it governs, not just the specific field it doesn't recognize ---
{
  const genesis = await signGenesis(
    { type: "custodial_create", did: wardDid, name: "fred", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: ["did:guardian:board-a:example:com"], prev: null },
    { "did:guardian:board-a:example:com": boardA.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const futurePolicy = { ...DEFAULT_GUARDIAN_POLICY, version: DEFAULT_GUARDIAN_POLICY.version + 1 };
  const policyUpdate = await signPolicyUpdate({ type: "policy_update", policy: futurePolicy, prev: genesisCid }, { "did:guardian:board-a:example:com": boardA.privateKey }, ["did:guardian:board-a:example:com"]);
  const policyCid = await cidFor(policyUpdate);
  const boardDid: Did = "did:guardian:board-b:example:com";
  // This guardian_add is otherwise completely well-formed (both the ward
  // and the sole existing guardian consent, easily meeting addition_threshold)
  // -- it must still be rejected, because the policy now in effect carries
  // a version this verifier doesn't understand, and some other field in it
  // (hypothetically) could be more restrictive than what's actually checked.
  const addOp = await signGuardianAdd({ type: "guardian_add", incoming: boardDid, prev: policyCid }, { [boardDid]: boardB.privateKey, "did:guardian:board-a:example:com": boardA.privateKey }, [boardDid, "did:guardian:board-a:example:com"]);
  write(
    "invalid",
    "policy_version_gate_blocks_governed_op",
    [{ cid: genesisCid, op: genesis }, { cid: policyCid, op: policyUpdate }, { cid: await cidFor(addOp), op: addOp }],
    "Fix 6: policy_update bumps GuardianPolicy.version beyond what this verifier supports; the guardian_add that follows is otherwise fully and validly signed but must still be rejected, since this verifier can't trust ANY threshold read off a policy version it doesn't recognize.",
    { "did:guardian:board-a:example:com": boardA.publicKey, [boardDid]: boardB.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

console.log("done.");
