// Generates interop_tests/operation_log fixtures using the reference
// implementation itself, so every fixture is a genuinely valid (or
// deliberately, specifically invalid) signed operation log -- not hand-typed
// data that merely looks plausible. Build the lib (tsc) then:
//   node dist/scripts/gen-fixtures.js
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeypair } from "../src/crypto.js";
import { signCustodialCreate, signCustodialRotate, signGuardianTransfer, signGuardianRelinquish, signCustodialTombstone, cidFor } from "../src/operations.js";
import type { LogEntry } from "../src/types.js";

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
const ward = generateKeypair();
const boardA = generateKeypair();
const boardB = generateKeypair();
const impostor = generateKeypair();

// --- valid: genesis with a two-member initial guardian set ---
{
  const genesis = signCustodialCreate(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKeyPem],
      verificationMethods: { "key-1": ward.publicKeyPem },
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
      prev: null,
    },
    { "did:guardian:board-a:example:com": boardA.privateKeyPem, "did:guardian:board-b:example:com": boardB.privateKeyPem },
  );
  write(
    "valid",
    "genesis_two_guardians",
    [{ cid: cidFor(genesis), op: genesis }],
    "Genesis establishing a two-member guardian set, both consenting.",
    { "did:guardian:board-a:example:com": boardA.publicKeyPem, "did:guardian:board-b:example:com": boardB.publicKeyPem },
    "accept",
  );
}

// --- valid: genesis -> rotate -> guardian_transfer (board-a steps down, board-c joins) ---
{
  const boardC = generateKeypair();
  const genesis = signCustodialCreate(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKeyPem],
      verificationMethods: { "key-1": ward.publicKeyPem },
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
      prev: null,
    },
    { "did:guardian:board-a:example:com": boardA.privateKeyPem, "did:guardian:board-b:example:com": boardB.privateKeyPem },
  );
  const genesisCid = cidFor(genesis);

  const newWardKey = generateKeypair();
  const rotate = signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [newWardKey.publicKeyPem], verificationMethods: { "key-1": newWardKey.publicKeyPem }, services: {}, prev: genesisCid },
    ward.privateKeyPem,
  );
  const rotateCid = cidFor(rotate);

  const transfer = signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:board-a:example:com"], incoming: ["did:guardian:board-b:example:com", "did:guardian:board-c:example:com"], prev: rotateCid },
    ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
    { "did:guardian:board-a:example:com": boardA.privateKeyPem, "did:guardian:board-c:example:com": boardC.privateKeyPem },
  );

  write(
    "valid",
    "rotate_then_guardian_transfer",
    [
      { cid: genesisCid, op: genesis },
      { cid: rotateCid, op: rotate },
      { cid: cidFor(transfer), op: transfer },
    ],
    "Genesis, an ordinary operational-key rotation, then board-a steps down and board-c joins -- board-b continues and does not re-sign.",
    {
      "did:guardian:board-a:example:com": boardA.publicKeyPem,
      "did:guardian:board-b:example:com": boardB.publicKeyPem,
      "did:guardian:board-c:example:com": boardC.publicKeyPem,
    },
    "accept",
  );
}

// --- valid: guardian_relinquish reaching full autonomy ---
{
  const genesis = signCustodialCreate(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKeyPem],
      verificationMethods: { "key-1": ward.publicKeyPem },
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
      prev: null,
    },
    { "did:guardian:board-a:example:com": boardA.privateKeyPem, "did:guardian:board-b:example:com": boardB.privateKeyPem },
  );
  const genesisCid = cidFor(genesis);
  const relinquish = signGuardianRelinquish(
    { type: "guardian_relinquish", prev: genesisCid },
    { "did:guardian:board-a:example:com": boardA.privateKeyPem, "did:guardian:board-b:example:com": boardB.privateKeyPem },
    ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com"],
  );
  write(
    "valid",
    "guardian_relinquish_unanimous",
    [{ cid: genesisCid, op: genesis }, { cid: cidFor(relinquish), op: relinquish }],
    "Both guardians sign off on full relinquishment -- meets the default majority (here, unanimous since n=2) threshold.",
    { "did:guardian:board-a:example:com": boardA.publicKeyPem, "did:guardian:board-b:example:com": boardB.publicKeyPem },
    "accept",
  );
}

// --- valid: tombstone, any single current key ---
{
  const genesis = signCustodialCreate(
    { type: "custodial_create", name: "fred", operationalKeys: [ward.publicKeyPem], verificationMethods: {}, services: {}, outgoing: [], incoming: [], prev: null },
    {},
  );
  const genesisCid = cidFor(genesis);
  const tombstone = signCustodialTombstone({ type: "custodial_tombstone", prev: genesisCid }, { [wardDid]: ward.privateKeyPem }, [wardDid]);
  write(
    "valid",
    "tombstone_any_single_key",
    [{ cid: genesisCid, op: genesis }, { cid: cidFor(tombstone), op: tombstone }],
    "Guardian-less ward tombstoning itself via its own operational key (resolved under its own DID), meeting the default `any` tombstone_threshold.",
    { [wardDid]: ward.publicKeyPem },
    "accept",
  );
}

// --- invalid: forged guardian claim (genesis names a guardian who never signed) ---
{
  const genesis = signCustodialCreate(
    {
      type: "custodial_create",
      name: "puppet",
      operationalKeys: [ward.publicKeyPem],
      verificationMethods: {},
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com"],
      prev: null,
    },
    { "did:guardian:board-a:example:com": impostor.privateKeyPem }, // forged: not board-a's real key
  );
  write(
    "invalid",
    "forged_guardian_claim",
    [{ cid: cidFor(genesis), op: genesis }],
    "REJECT: 'board-a' is named as initial guardian but the signature was produced by a different, impostor key -- must fail verification against board-a's real, resolved public key.",
    { "did:guardian:board-a:example:com": boardA.publicKeyPem }, // the REAL board-a key -- the fixture's signature won't match it
    "reject",
  );
}

// --- invalid: guardian_transfer missing the removed guardian's own signature ---
{
  const genesis = signCustodialCreate(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKeyPem],
      verificationMethods: {},
      services: {},
      outgoing: [],
      incoming: ["did:guardian:troy:example:com", "did:guardian:jane:example:com"],
      prev: null,
    },
    { "did:guardian:troy:example:com": boardA.privateKeyPem, "did:guardian:jane:example:com": boardB.privateKeyPem },
  );
  const genesisCid = cidFor(genesis);
  const transfer = signGuardianTransfer(
    { type: "guardian_transfer", outgoing: ["did:guardian:jane:example:com"], incoming: [], prev: genesisCid },
    ["did:guardian:troy:example:com", "did:guardian:jane:example:com"],
    { "did:guardian:jane:example:com": boardA.privateKeyPem }, // troy forges jane's own removal signature
  );
  write(
    "invalid",
    "unilateral_coguardian_removal",
    [{ cid: genesisCid, op: genesis }, { cid: cidFor(transfer), op: transfer }],
    "REJECT: troy attempts to remove jane from a two-guardian set, but the signature claimed as jane's was produced with troy's own key, not jane's.",
    { "did:guardian:troy:example:com": boardA.publicKeyPem, "did:guardian:jane:example:com": boardB.publicKeyPem },
    "reject",
  );
}

// --- invalid: quorum not met (majority required, only one of three signs) ---
{
  const boardC = generateKeypair();
  const genesis = signCustodialCreate(
    {
      type: "custodial_create",
      name: "fred",
      operationalKeys: [ward.publicKeyPem],
      verificationMethods: {},
      services: {},
      outgoing: [],
      incoming: ["did:guardian:board-a:example:com", "did:guardian:board-b:example:com", "did:guardian:board-c:example:com"],
      prev: null,
    },
    {
      "did:guardian:board-a:example:com": boardA.privateKeyPem,
      "did:guardian:board-b:example:com": boardB.privateKeyPem,
      "did:guardian:board-c:example:com": boardC.privateKeyPem,
    },
  );
  const genesisCid = cidFor(genesis);
  // Only board-a signs the relinquish; default removal/relinquish bar is
  // majority (2 of 3) -- this must NOT be accepted.
  const relinquish = signGuardianRelinquish(
    { type: "guardian_relinquish", prev: genesisCid },
    { "did:guardian:board-a:example:com": boardA.privateKeyPem },
    ["did:guardian:board-a:example:com"],
  );
  write(
    "invalid",
    "relinquish_quorum_not_met",
    [{ cid: genesisCid, op: genesis }, { cid: cidFor(relinquish), op: relinquish }],
    "REJECT: three guardians exist, default removal/relinquish threshold is majority (2 of 3), but only board-a signed.",
    {
      "did:guardian:board-a:example:com": boardA.publicKeyPem,
      "did:guardian:board-b:example:com": boardB.publicKeyPem,
      "did:guardian:board-c:example:com": boardC.publicKeyPem,
    },
    "reject",
  );
}

console.log("done.");
