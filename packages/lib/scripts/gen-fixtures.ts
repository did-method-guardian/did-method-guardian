// Generates interop_tests/operation_log fixtures using the reference
// implementation itself, so every fixture is a genuinely valid (or
// deliberately, specifically invalid) signed operation log -- not hand-typed
// data that merely looks plausible. Build the lib (tsc) then:
//   node dist/scripts/gen-fixtures.js
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeypair, signPayload } from "../src/crypto.js";
import { signCustodialCreate, signCustodialRotate, signGuardianAdd, signGuardianTransfer, signGuardianRelinquish, signCustodialTombstone, signRegistrarAttestation, corePayload, cidFor } from "../src/operations.js";
import type { CustodialCreateOp, Did, LogEntry } from "../src/types.js";

// `here` is dist/scripts when run compiled -- repo root is four levels up
// (scripts -> dist -> lib -> packages -> repo root).
const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "..", "..", "..", "interop_tests", "operation_log");

/**
 * `known_keys` maps every DID referenced as a signer in this fixture's log to
 * its public key -- a test-harness convenience. In a real deployment each
 * signer's key is resolved independently through its own identity (spec §5);
 * a single fixture file bundling them is specifically so this interop suite
 * is checkable in isolation, without standing up real resolvable identities
 * for every guardian referenced.
 */
function write(
  subdir: "valid" | "invalid",
  name: string,
  log: LogEntry[],
  note: string,
  knownKeys: Record<string, string>,
  expect: "accept" | "reject",
) {
  const dir = join(outDir, subdir);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${name}.json`), JSON.stringify({ note, expect, known_keys: knownKeys, log }, null, 2) + "\n");
  console.log(`wrote ${subdir}/${name}.json`);
}

const wardDid = "did:guardian:fred:example:com";
const ward = await generateKeypair();
const boardA = await generateKeypair();
const boardB = await generateKeypair();
const impostor = await generateKeypair();

// One registrar identity, reused across every fixture below -- REQ-7.1-5
// now requires every genesis to carry this attestation; `registrarKnownKeys`
// gets merged into every fixture's own `known_keys` so the test harness can
// resolve it, same as any other signer.
const registrarDid = "did:guardian:example:com";
const registrar = await generateKeypair();
const registrarKnownKeys = { [registrarDid]: registrar.publicKey };

/** Attaches `creator` (REQ-7.1-4) and a real registrar attestation (REQ-7.1-5) to a genesis op before it's signed -- every fixture below builds its genesis this way now, matching what registerWard actually produces. `operationalPrivateKeys` satisfies REQ-7.1-8's proof of possession. */
async function signGenesis(
  partial: Omit<CustodialCreateOp, "sigs" | "creator" | "registrar" | "keySigs">,
  incomingKeys: Record<Did, string>,
  operationalPrivateKeys: Record<string, string>,
): Promise<CustodialCreateOp> {
  const withCreator = { ...partial, creator: registrarDid };
  const attestation = await signRegistrarAttestation(withCreator, registrarDid, registrar.privateKey);
  return signCustodialCreate({ ...withCreator, registrar: attestation }, incomingKeys, operationalPrivateKeys);
}

// --- valid: genesis with a two-member initial guardian set ---
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKey],
      verificationMethods: { "key-1": ward.publicKey },
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
      name: "fred",
      operationalKeys: [ward.publicKey],
      verificationMethods: { "key-1": ward.publicKey },
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
    { type: "custodial_rotate", operationalKeys: [newWardKey.publicKey], verificationMethods: { "key-1": newWardKey.publicKey }, services: {}, prev: genesisCid },
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
      name: "fred",
      operationalKeys: [ward.publicKey],
      verificationMethods: { "key-1": ward.publicKey },
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
    { type: "custodial_create", name: "fred", operationalKeys: [ward.publicKey], verificationMethods: {}, services: {}, outgoing: [], incoming: [], prev: null },
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
    { type: "custodial_create", name: "fred", operationalKeys: [ward.publicKey], verificationMethods: {}, services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const boardDid = "did:guardian:board:example:com";
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

// --- invalid: standalone guardian_add missing the ward's required signature (REQ-7.2-5) ---
{
  const genesis = await signGenesis(
    { type: "custodial_create", name: "puppet2", operationalKeys: [ward.publicKey], verificationMethods: {}, services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const boardDid = "did:guardian:board:example:com";
  const unsigned = { type: "guardian_add" as const, incoming: boardDid, prev: genesisCid };
  const addOp = { ...unsigned, sigs: { [boardDid]: await signPayload(unsigned, boardA.privateKey) } }; // the ward never signs
  write(
    "invalid",
    "guardian_add_missing_ward_signature",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(addOp), op: addOp }],
    "REJECT: establishing a guardian from zero needs both the incoming guardian's and the ward's signature (REQ-7.2-5) -- here only the incoming guardian signed.",
    { [wardDid]: ward.publicKey, [boardDid]: boardA.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: forged guardian claim (genesis names a guardian who never signed) ---
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      name: "puppet",
      operationalKeys: [ward.publicKey],
      verificationMethods: {},
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
    "REJECT: 'board-a' is named as initial guardian but the signature was produced by a different, impostor key -- must fail verification against board-a's real, resolved public key.",
    { "did:guardian:board-a:example:com": boardA.publicKey, ...registrarKnownKeys }, // the REAL board-a key -- the fixture's signature won't match it
    "reject",
  );
}

// --- invalid: genesis names an incoming guardian at genesis (v0.3, REQ-7.1-1) who never co-signed at all -- no sig entry, not even a forged one ---
// Built directly, not via signGenesis -- that helper (signCustodialCreate)
// refuses to produce an under-signed operation at all, which is correct
// for honest callers but means this adversarial case has to be
// constructed by hand, the same way the other forgery fixtures above do.
{
  const withCreator = {
    type: "custodial_create" as const,
    name: "unsigned",
    operationalKeys: [ward.publicKey],
    verificationMethods: {},
    services: {},
    outgoing: [] as [],
    incoming: ["did:guardian:board-a:example:com"],
    prev: null,
    creator: registrarDid,
  };
  const registrarAttestation = await signRegistrarAttestation(withCreator, registrarDid, registrar.privateKey);
  const payload = corePayload(withCreator as any);
  const keySigs = { [ward.publicKey]: await signPayload(payload, ward.privateKey) };
  const genesis = { ...withCreator, registrar: registrarAttestation, keySigs, sigs: {} }; // board-a never signs at all
  write(
    "invalid",
    "genesis_unsigned_incoming_guardian",
    [{ cid: await cidFor(genesis), op: genesis }],
    "REJECT: 'board-a' is named as an incoming guardian directly at genesis (REQ-7.1-1, v0.3) but carries no signature at all -- establishing a guardian this way still requires that guardian's consent.",
    { "did:guardian:board-a:example:com": boardA.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: guardian_transfer missing the removed guardian's own signature ---
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKey],
      verificationMethods: {},
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
    "REJECT: troy attempts to remove jane from a two-guardian set, but the signature claimed as jane's was produced with troy's own key, not jane's.",
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
      name: "fred",
      operationalKeys: [ward.publicKey],
      verificationMethods: {},
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
      name: "fred",
      operationalKeys: [ward.publicKey],
      verificationMethods: { "key-1": ward.publicKey },
      services: {},
      outgoing: [],
      incoming: [],
      prev: null,
      creator: registrarDid,
      // no `registrar` field -- the thing under test
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

console.log("done.");
