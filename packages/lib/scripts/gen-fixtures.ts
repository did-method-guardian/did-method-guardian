// Generates interop_tests/operation_log fixtures using the reference
// implementation itself, so every fixture is a genuinely valid (or
// deliberately, specifically invalid) signed operation log -- not hand-typed
// data that merely looks plausible. Build the lib (tsc) then:
//   node dist/scripts/gen-fixtures.js
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeypair, fromMultibaseBase58btc, toMultibaseBase58btc, canonicalize, sha256Bytes, signRawBytes } from "../src/crypto.js";
import {
  signCustodialCreate,
  signCustodialRotate,
  signCustodialRotateByGuardians,
  signGuardianAdd,
  signGuardianRemove,
  signGuardianRelinquish,
  signCustodialTombstone,
  signPolicyUpdate,
  signRegistrarAttestation,
  signReceipt,
  createProof,
  unsecuredDocument,
  popVerificationMethod,
  cidFor,
} from "../src/operations.js";
import { DEFAULT_GUARDIAN_POLICY } from "../src/types.js";
import type { CustodialCreateOp, CustodialRotateOp, Did, LogEntry } from "../src/types.js";

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

const wardDid: Did = "did:guardian:example.com:fred";
const ward = await generateKeypair();
const boardA = await generateKeypair();
const boardB = await generateKeypair();
const impostor = await generateKeypair();

// One registrar identity, reused across every fixture below -- REQ-7.1-5
// requires every genesis to carry this attestation; `registrarKnownKeys`
// gets merged into every fixture's own `known_keys` so the test harness can
// resolve it, same as any other signer.
const registrarDid: Did = "did:guardian:example.com";
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
      incoming: ["did:guardian:example.com:board-a", "did:guardian:example.com:board-b"],
      prev: null,
    },
    { "did:guardian:example.com:board-a": boardA.privateKey, "did:guardian:example.com:board-b": boardB.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  write(
    "valid",
    "genesis_two_guardians",
    [{ cid: await cidFor(genesis), op: genesis }],
    "Genesis establishing a two-member guardian set, both consenting.",
    { "did:guardian:example.com:board-a": boardA.publicKey, "did:guardian:example.com:board-b": boardB.publicKey, ...registrarKnownKeys },
    "accept",
  );
}

// --- valid: genesis -> rotate -> guardian_remove (board-a steps down) -> guardian_add (board-c joins) ---
// WS-3.3/3.6 (audit): replaces the old guardian_transfer-based version of
// this fixture -- guardian_transfer is v0.1, superseded, kept only for
// replaying ALREADY-accepted history (document.ts's own comment), never
// produced for a new operation. board-a's own departure and board-c's own
// arrival are now two separate, real v0.2 operations instead.
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
      incoming: ["did:guardian:example.com:board-a", "did:guardian:example.com:board-b"],
      prev: null,
    },
    { "did:guardian:example.com:board-a": boardA.privateKey, "did:guardian:example.com:board-b": boardB.privateKey },
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

  // REQ-7.2-7(a): board-a steps down voluntarily -- only its own signature is needed.
  const removeBoardA = await signGuardianRemove(
    { type: "guardian_remove", outgoing: "did:guardian:example.com:board-a", prev: rotateCid },
    { "did:guardian:example.com:board-a": boardA.privateKey },
    ["did:guardian:example.com:board-a"],
  );
  const removeCid = await cidFor(removeBoardA);

  // REQ-7.2-4: board-c joins a non-empty guardian set -- needs its own
  // signature plus enough of the CURRENT committee (now just board-b,
  // whose majority is itself) to meet addition_threshold.
  const addBoardC = await signGuardianAdd(
    { type: "guardian_add", incoming: "did:guardian:example.com:board-c", prev: removeCid },
    { "did:guardian:example.com:board-c": boardC.privateKey, "did:guardian:example.com:board-b": boardB.privateKey },
    ["did:guardian:example.com:board-c", "did:guardian:example.com:board-b"],
  );

  write(
    "valid",
    "rotate_then_guardian_add_remove",
    [
      { cid: genesisCid, op: genesis },
      { cid: rotateCid, op: rotate },
      { cid: removeCid, op: removeBoardA },
      { cid: await cidFor(addBoardC), op: addBoardC },
    ],
    "Genesis, an ordinary operational-key rotation, then board-a steps down (voluntary guardian_remove) and board-c joins (guardian_add, needing board-b's own continuing approval) -- board-b itself is never removed or re-added.",
    {
      "did:guardian:example.com:board-a": boardA.publicKey,
      "did:guardian:example.com:board-b": boardB.publicKey,
      "did:guardian:example.com:board-c": boardC.publicKey,
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
      incoming: ["did:guardian:example.com:board-a", "did:guardian:example.com:board-b"],
      prev: null,
    },
    { "did:guardian:example.com:board-a": boardA.privateKey, "did:guardian:example.com:board-b": boardB.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const relinquish = await signGuardianRelinquish(
    { type: "guardian_relinquish", prev: genesisCid },
    { "did:guardian:example.com:board-a": boardA.privateKey, "did:guardian:example.com:board-b": boardB.privateKey },
    ["did:guardian:example.com:board-a", "did:guardian:example.com:board-b"],
  );
  write(
    "valid",
    "guardian_relinquish_unanimous",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(relinquish), op: relinquish }],
    "Both guardians sign off on full relinquishment -- meets the default majority (here, unanimous since n=2) threshold.",
    { "did:guardian:example.com:board-a": boardA.publicKey, "did:guardian:example.com:board-b": boardB.publicKey, ...registrarKnownKeys },
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
  const boardDid: Did = "did:guardian:example.com:board";
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
  const rootDid: Did = "did:guardian:example.com"; // the SAME identity as `registrarDid` elsewhere in this file -- here it's attesting ITSELF, not some other ward
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
    { type: "custodial_create", did: "did:guardian:example.com:puppet2", name: "puppet2", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const boardDid: Did = "did:guardian:example.com:board";
  const unsigned = { type: "guardian_add" as const, incoming: boardDid, prev: genesisCid };
  const boardProof = await createProof(unsecuredDocument(unsigned as any), `${boardDid}#key-0`, boardA.privateKey);
  const addOp = { ...unsigned, proof: [boardProof] }; // the ward never signs
  write(
    "invalid",
    "guardian_add_missing_ward_signature",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(addOp), op: addOp }],
    "REJECT: establishing a guardian from zero needs both the incoming guardian's and the ward's signature (REQ-7.2-5) -- here only the incoming guardian signed.",
    { "did:guardian:example.com:puppet2": ward.publicKey, [boardDid]: boardA.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: forged guardian claim (genesis names a guardian who never signed) ---
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: "did:guardian:example.com:puppet",
      name: "puppet",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:example.com:board-a"],
      prev: null,
    },
    { "did:guardian:example.com:board-a": impostor.privateKey }, // forged: not board-a's real key
    { [ward.publicKey]: ward.privateKey },
  );
  write(
    "invalid",
    "forged_guardian_claim",
    [{ cid: await cidFor(genesis), op: genesis }],
    "REJECT: 'board-a' is named as initial guardian but the proof was produced by a different, impostor key -- must fail verification against board-a's real, resolved public key.",
    { "did:guardian:example.com:board-a": boardA.publicKey, ...registrarKnownKeys }, // the REAL board-a key -- the fixture's proof won't match it
    "reject",
  );
}

// --- invalid: genesis names an incoming guardian at genesis (v0.3, REQ-7.1-1) who never co-signed at all -- no proof entry, not even a forged one ---
// Built directly, not via signGenesis -- that helper (signCustodialCreate)
// refuses to produce an under-signed operation at all, which is correct
// for honest callers but means this adversarial case has to be
// constructed by hand, the same way the other forgery fixtures above do.
{
  const did: Did = "did:guardian:example.com:unsigned";
  const withCreator = {
    type: "custodial_create" as const,
    did,
    name: "unsigned",
    operationalKeys: [ward.publicKey],
    services: {},
    outgoing: [] as [],
    incoming: ["did:guardian:example.com:board-a"] as Did[],
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
    { "did:guardian:example.com:board-a": boardA.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: guardian_remove forging the removed co-guardian's own signature ---
// WS-3.3/3.6 (audit): replaces the old guardian_transfer-based version --
// same narrative (troy forges a signature claimed as jane's own), via
// guardian_remove instead.
{
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: wardDid,
      name: "fred",
      operationalKeys: [ward.publicKey],
      services: {},
      outgoing: [],
      incoming: ["did:guardian:example.com:troy", "did:guardian:example.com:jane"],
      prev: null,
    },
    { "did:guardian:example.com:troy": boardA.privateKey, "did:guardian:example.com:jane": boardB.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const unsigned = { type: "guardian_remove" as const, outgoing: "did:guardian:example.com:jane", prev: genesisCid };
  const forgedProof = await createProof(unsecuredDocument(unsigned as any), "did:guardian:example.com:jane#key-0", boardA.privateKey); // troy's key, claimed as jane's own
  const removeOp = { ...unsigned, proof: [forgedProof] };
  write(
    "invalid",
    "unilateral_coguardian_removal",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(removeOp), op: removeOp }],
    "REJECT: troy attempts to remove jane from a two-guardian set, but the proof claimed as jane's own voluntary removal (REQ-7.2-7a) was produced with troy's key, not jane's -- and troy alone can never meet the forced-removal path either (REQ-7.2-7b is unreachable at exactly two guardians).",
    { "did:guardian:example.com:troy": boardA.publicKey, "did:guardian:example.com:jane": boardB.publicKey, ...registrarKnownKeys },
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
      incoming: ["did:guardian:example.com:board-a", "did:guardian:example.com:board-b", "did:guardian:example.com:board-c"],
      prev: null,
    },
    {
      "did:guardian:example.com:board-a": boardA.privateKey,
      "did:guardian:example.com:board-b": boardB.privateKey,
      "did:guardian:example.com:board-c": boardC.privateKey,
    },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  // Only board-a signs the relinquish; default removal/relinquish bar is
  // majority (2 of 3) -- this must NOT be accepted.
  const relinquish = await signGuardianRelinquish(
    { type: "guardian_relinquish", prev: genesisCid },
    { "did:guardian:example.com:board-a": boardA.privateKey },
    ["did:guardian:example.com:board-a"],
  );
  write(
    "invalid",
    "relinquish_quorum_not_met",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(relinquish), op: relinquish }],
    "REJECT: three guardians exist, default removal/relinquish threshold is majority (2 of 3), but only board-a signed.",
    {
      "did:guardian:example.com:board-a": boardA.publicKey,
      "did:guardian:example.com:board-b": boardB.publicKey,
      "did:guardian:example.com:board-c": boardC.publicKey,
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
  const partial = { type: "custodial_create" as const, did: "did:guardian:example.com:keyswap", name: "keyswap", operationalKeys: [victimKeyClaimedInDocument], services: {}, outgoing: [] as [], incoming: [] as Did[], prev: null, creator: registrarDid };
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
    { type: "custodial_create", did: wardDid, name: "fred", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: ["did:guardian:example.com:board-a"], prev: null },
    { "did:guardian:example.com:board-a": boardA.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const futurePolicy = { ...DEFAULT_GUARDIAN_POLICY, version: DEFAULT_GUARDIAN_POLICY.version + 1 };
  const policyUpdate = await signPolicyUpdate({ type: "policy_update", policy: futurePolicy, prev: genesisCid }, { "did:guardian:example.com:board-a": boardA.privateKey }, ["did:guardian:example.com:board-a"]);
  const policyCid = await cidFor(policyUpdate);
  const boardDid: Did = "did:guardian:example.com:board-b";
  // This guardian_add is otherwise completely well-formed (both the ward
  // and the sole existing guardian consent, easily meeting addition_threshold)
  // -- it must still be rejected, because the policy now in effect carries
  // a version this verifier doesn't understand, and some other field in it
  // (hypothetically) could be more restrictive than what's actually checked.
  const addOp = await signGuardianAdd({ type: "guardian_add", incoming: boardDid, prev: policyCid }, { [boardDid]: boardB.privateKey, "did:guardian:example.com:board-a": boardA.privateKey }, [boardDid, "did:guardian:example.com:board-a"]);
  write(
    "invalid",
    "policy_version_gate_blocks_governed_op",
    [{ cid: genesisCid, op: genesis }, { cid: policyCid, op: policyUpdate }, { cid: await cidFor(addOp), op: addOp }],
    "Fix 6: policy_update bumps GuardianPolicy.version beyond what this verifier supports; the guardian_add that follows is otherwise fully and validly signed but must still be rejected, since this verifier can't trust ANY threshold read off a policy version it doesn't recognize.",
    { "did:guardian:example.com:board-a": boardA.publicKey, [boardDid]: boardB.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// WS-3.4 (audit): fixtures below fill in the audit's own named gaps in
// negative-case coverage. A few of the audit's original 15 are covered
// already (unknown/invalid policy version is exactly what
// policy_version_gate_blocks_governed_op.json already tests) or don't
// translate into a verifyLog-checkable fixture at all ("replayed
// superseded recovery" is an acceptance-time/storage invariant --
// registrar.ts's own submitOperation rejects a cid that already exists
// anywhere in ITS stored log, WS-1.5 -- never a property of a log
// verifyLog is handed complete and already-accepted; already covered by
// a server-level regression test, not duplicated here).

const P256_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

/** The mathematically-equivalent high-S counterpart of a genuine low-S signature -- same technique as crypto.test.ts's own malleability test, applied to a real proofValue here instead of the old base64url scheme. */
function toHighS(proofValueMultibase: string): string {
  const bytes = fromMultibaseBase58btc(proofValueMultibase);
  const r = bytes.slice(0, 32);
  let s = 0n;
  for (const b of bytes.slice(32, 64)) s = (s << 8n) | BigInt(b);
  const highS = P256_N - s;
  const highSBytes = new Uint8Array(32);
  let v = highS;
  for (let i = 31; i >= 0; i--) {
    highSBytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(highSBytes, 32);
  return toMultibaseBase58btc(out);
}

/** Signs a hand-built proofConfig directly -- for the two fixtures below that need a genuinely valid signature over content createProof itself would never construct (a cryptosuite/created it doesn't support). */
async function signRawProofConfig(unsecuredDoc: unknown, proofConfig: { type: "DataIntegrityProof"; cryptosuite: string; verificationMethod: string; proofPurpose: string; created: string }, privateKey: string) {
  const proofConfigHash = await sha256Bytes(new TextEncoder().encode(canonicalize(proofConfig)));
  const documentHash = await sha256Bytes(new TextEncoder().encode(canonicalize(unsecuredDoc)));
  const signingInput = new Uint8Array(proofConfigHash.length + documentHash.length);
  signingInput.set(proofConfigHash, 0);
  signingInput.set(documentHash, proofConfigHash.length);
  const proofValue = await signRawBytes(signingInput, privateKey);
  return { ...proofConfig, proofValue };
}

// --- invalid: the ward's own signature over a rotation is the mathematically-equivalent high-S counterpart of a valid one (Fix 3 malleability) ---
{
  const highSDid: Did = "did:guardian:example.com:highs";
  const genesis = await signGenesis(
    { type: "custodial_create", did: highSDid, name: "highs", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const newKey = await generateKeypair();
  const rotate = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [newKey.publicKey], services: {}, prev: genesisCid },
    highSDid,
    ward.privateKey,
    { [newKey.publicKey]: newKey.privateKey },
  );
  const tamperedProof = rotate.proof.map((p) => (p.verificationMethod === `${highSDid}#key-0` ? { ...p, proofValue: toHighS(p.proofValue) } : p));
  const tamperedRotate = { ...rotate, proof: tamperedProof };
  write(
    "invalid",
    "high_s_signature_malleability",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(tamperedRotate), op: tamperedRotate }],
    "REJECT: the ward's own signature over the rotation is the mathematically-equivalent high-S counterpart of a valid signature -- ECDSA malleability must not produce a second valid form (Fix 3).",
    { [highSDid]: ward.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: genesis attested by a registrar from a different domain than genesis.did's own (WS-4.4) ---
{
  const evilRegistrarDid: Did = "did:guardian:evil.example";
  const evilRegistrar = await generateKeypair();
  const partial = { type: "custodial_create" as const, did: "did:guardian:example.com:foreign", name: "foreign", operationalKeys: [ward.publicKey], services: {}, outgoing: [] as [], incoming: [] as Did[], prev: null, creator: evilRegistrarDid };
  const signed = await signCustodialCreate(partial, {}, { [ward.publicKey]: ward.privateKey });
  const evilAttestation = await signRegistrarAttestation(partial, evilRegistrarDid, evilRegistrar.privateKey);
  const genesis = { ...signed, proof: [...signed.proof, evilAttestation] };
  write(
    "invalid",
    "foreign_domain_genesis_attestation",
    [{ cid: await cidFor(genesis), op: genesis }],
    "REJECT: genesis for example.com:foreign is attested by did:guardian:evil.example#key-0 -- a real, validly-signed attestation, but not from example.com's own domain root (WS-4.4/REQ-7.1-5).",
    { [evilRegistrarDid]: evilRegistrar.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: genesis naming itself as its own guardian (REQ-7.1-9) ---
{
  const selfGuardianDid: Did = "did:guardian:example.com:selfguardian";
  const partial = { type: "custodial_create" as const, did: selfGuardianDid, name: "selfguardian", operationalKeys: [ward.publicKey], services: {}, outgoing: [] as [], incoming: [selfGuardianDid], prev: null };
  const genesis = await signGenesis(partial, { [selfGuardianDid]: ward.privateKey }, { [ward.publicKey]: ward.privateKey });
  write(
    "invalid",
    "genesis_self_guardian",
    [{ cid: await cidFor(genesis), op: genesis }],
    "REJECT: a genesis can't name itself as its own guardian (REQ-7.1-9), even though it co-signs successfully.",
    { [selfGuardianDid]: ward.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: genesis naming the same guardian twice in incoming ---
{
  const dupGuardianDid: Did = "did:guardian:example.com:dupguardian";
  const partial = { type: "custodial_create" as const, did: "did:guardian:example.com:dupward", name: "dupward", operationalKeys: [ward.publicKey], services: {}, outgoing: [] as [], incoming: [dupGuardianDid, dupGuardianDid], prev: null };
  const genesis = await signGenesis(partial, { [dupGuardianDid]: boardA.privateKey }, { [ward.publicKey]: ward.privateKey });
  write(
    "invalid",
    "genesis_duplicate_incoming_guardian",
    [{ cid: await cidFor(genesis), op: genesis }],
    "REJECT: genesis names the same guardian twice in incoming -- malformed, even though the single real signature would trivially satisfy both entries.",
    { [dupGuardianDid]: boardA.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: an operation appears after this identity's own tombstone (REQ-6-5) ---
{
  const postTombstoneDid: Did = "did:guardian:example.com:posttombstone";
  const genesis = await signGenesis(
    { type: "custodial_create", did: postTombstoneDid, name: "posttombstone", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const tombstone = await signCustodialTombstone({ type: "custodial_tombstone", prev: genesisCid }, { [postTombstoneDid]: ward.privateKey }, [postTombstoneDid]);
  const tombstoneCid = await cidFor(tombstone);
  const newKey = await generateKeypair();
  const rotateAfter = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [newKey.publicKey], services: {}, prev: tombstoneCid },
    postTombstoneDid,
    ward.privateKey,
    { [newKey.publicKey]: newKey.privateKey },
  );
  write(
    "invalid",
    "operation_after_tombstone",
    [{ cid: genesisCid, op: genesis }, { cid: tombstoneCid, op: tombstone }, { cid: await cidFor(rotateAfter), op: rotateAfter }],
    "REJECT: a custodial_rotate appears after this identity's own tombstone -- REQ-6-5 requires every subsequent operation to be rejected once deactivated.",
    { [postTombstoneDid]: ward.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: nullification naming a prev whose successor was accepted more than 72h ago (REQ-6-9) ---
{
  const nullWinGuardianDid: Did = "did:guardian:example.com:nullwinguardian";
  const nullWinGuardian = await generateKeypair();
  const nullWinDid: Did = "did:guardian:example.com:nullwinward";
  const genesis = await signGenesis(
    { type: "custodial_create", did: nullWinDid, name: "nullwinward", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [nullWinGuardianDid], prev: null },
    { [nullWinGuardianDid]: nullWinGuardian.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const oldKey = await generateKeypair();
  const wardRotate = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [oldKey.publicKey], services: {}, prev: genesisCid },
    nullWinDid,
    ward.privateKey,
    { [oldKey.publicKey]: oldKey.privateKey },
  );
  const staleReceiptAt = new Date(Date.now() - 73 * 60 * 60 * 1000).toISOString(); // 73h ago -- outside the 72h window
  const staleReceipt = await signReceipt(unsecuredDocument(wardRotate as any), registrarDid, registrar.privateKey, staleReceiptAt);
  const wardRotateWithReceipt = { ...wardRotate, proof: [...wardRotate.proof, staleReceipt] };
  const wardRotateCid = await cidFor(wardRotateWithReceipt);

  const recoveryKey = await generateKeypair();
  const nullifyingRotate = await signCustodialRotateByGuardians(
    { type: "custodial_rotate", operationalKeys: [recoveryKey.publicKey], services: {}, prev: genesisCid },
    { [nullWinGuardianDid]: nullWinGuardian.privateKey },
    [nullWinGuardianDid],
    { [recoveryKey.publicKey]: recoveryKey.privateKey },
  );
  write(
    "invalid",
    "nullification_outside_window",
    [{ cid: genesisCid, op: genesis }, { cid: wardRotateCid, op: wardRotateWithReceipt }, { cid: await cidFor(nullifyingRotate), op: nullifyingRotate }],
    "REJECT: the guardian-signed nullifying rotation names genesis as prev, but the rotation it would nullify was accepted (per its own registrar receipt) 73 hours ago -- outside REQ-6-9's 72h window.",
    { [nullWinGuardianDid]: nullWinGuardian.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: a guardian-signed nullifying rotation installing a key with no proof of possession (REQ-7.2-12) ---
{
  const noPopGuardianDid: Did = "did:guardian:example.com:nopopguardian";
  const noPopGuardian = await generateKeypair();
  const noPopDid: Did = "did:guardian:example.com:nopopward";
  const genesis = await signGenesis(
    { type: "custodial_create", did: noPopDid, name: "nopopward", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [noPopGuardianDid], prev: null },
    { [noPopGuardianDid]: noPopGuardian.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const oldKey = await generateKeypair();
  const wardRotate = await signCustodialRotate(
    { type: "custodial_rotate", operationalKeys: [oldKey.publicKey], services: {}, prev: genesisCid },
    noPopDid,
    ward.privateKey,
    { [oldKey.publicKey]: oldKey.privateKey },
  );
  const freshReceipt = await signReceipt(unsecuredDocument(wardRotate as any), registrarDid, registrar.privateKey, new Date().toISOString());
  const wardRotateWithReceipt = { ...wardRotate, proof: [...wardRotate.proof, freshReceipt] };
  const wardRotateCid = await cidFor(wardRotateWithReceipt);

  const recoveryKey = await generateKeypair();
  const partial = { type: "custodial_rotate" as const, operationalKeys: [recoveryKey.publicKey], services: {}, prev: genesisCid };
  const guardianProof = await createProof(unsecuredDocument(partial as any), `${noPopGuardianDid}#key-0`, noPopGuardian.privateKey);
  const nullifyingRotate = { ...partial, proof: [guardianProof] }; // no PoP proof for recoveryKey at all
  write(
    "invalid",
    "nullification_without_pop",
    [{ cid: genesisCid, op: genesis }, { cid: wardRotateCid, op: wardRotateWithReceipt }, { cid: await cidFor(nullifyingRotate), op: nullifyingRotate }],
    "REJECT: the guardian-signed nullifying rotation installs a new key with no proof of possession for it at all -- REQ-7.2-12 is still required for a nullification, same as any other rotation.",
    { [noPopGuardianDid]: noPopGuardian.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// WS-3.4 (audit): "zero threshold" deliberately NOT added as its own
// fixture -- any value low enough to be an interesting "zero threshold"
// case (at_least <= 0) is already rejected by threshold.schema.json's
// own `minimum: 1` at the structural level, so it could never be
// schema-valid (this suite's own established convention, enforced by
// schemas.test.ts: every fixture, invalid ones included, must still be
// schema-conformant -- invalidity has to come from a semantic check, not
// malformed shape). WS-1.3's actual behavior here (every threshold kind
// unsatisfiable over an empty eligible set, n=0) is already covered
// directly in quorum.test.ts.

// --- invalid: genesis carrying an unexplained extra proof, from neither a declared key, an incoming guardian, nor the registrar (WS-1.7) ---
{
  const strayProofDid: Did = "did:guardian:example.com:strayproof";
  const strayDid: Did = "did:guardian:evil.example";
  const stray = await generateKeypair();
  const genesis = await signGenesis(
    { type: "custodial_create", did: strayProofDid, name: "strayproof", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const strayProof = await createProof(unsecuredDocument(genesis as any), `${strayDid}#key-0`, stray.privateKey);
  const poisoned = { ...genesis, proof: [...genesis.proof, strayProof] };
  write(
    "invalid",
    "genesis_unexplained_extra_proof",
    [{ cid: await cidFor(poisoned), op: poisoned }],
    "REJECT: genesis carries a real, validly-signed extra proof from a DID that's neither a declared operational key, an incoming guardian, nor the registrar (WS-1.7) -- an unexplained proof must never be silently accepted.",
    { [strayProofDid]: ward.publicKey, [strayDid]: stray.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: a proof with a proofPurpose this implementation doesn't use, even though its signature is genuinely valid over that exact content (WS-1.9) ---
// WS-3.4 (audit): "wrong cryptosuite" specifically has no fixture of its
// own -- data-integrity-proof.schema.json already constrains cryptosuite
// to the literal constant "ecdsa-jcs-2019" (schema-enforced, same
// reasoning as the dropped zero-threshold fixture above), so a wrong-
// cryptosuite proof could never be schema-valid in the first place.
// proofPurpose has no such schema constant (just `{"type": "string"}`),
// so it's the one of the pair that actually needs its own fixture here.
{
  const badPurposeDid: Did = "did:guardian:example.com:badpurpose";
  const genesis = await signGenesis(
    { type: "custodial_create", did: badPurposeDid, name: "badpurpose", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const newKey = await generateKeypair();
  const partial = { type: "custodial_rotate" as const, operationalKeys: [newKey.publicKey], services: {}, prev: genesisCid };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const popProof = await createProof(unsecuredDoc, popVerificationMethod(newKey.publicKey), newKey.privateKey);
  const forgedWardProof = await signRawProofConfig(
    unsecuredDoc,
    { type: "DataIntegrityProof", cryptosuite: "ecdsa-jcs-2019", verificationMethod: `${badPurposeDid}#key-0`, proofPurpose: "capabilityInvocation", created: new Date().toISOString() },
    ward.privateKey,
  );
  const rotate = { ...partial, proof: [popProof, forgedWardProof] } as unknown as CustodialRotateOp;
  write(
    "invalid",
    "proof_wrong_proof_purpose",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(rotate), op: rotate }],
    "REJECT: the ward's own proof over the rotation carries proofPurpose capabilityInvocation, not this implementation's one current value (assertionMethod) -- a genuinely valid signature over that exact content, which validateProofShape (WS-1.9) must still refuse.",
    { [badPurposeDid]: ward.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- invalid: a proof with a malformed (non-ISO-8601) created value, even though its signature is genuinely valid over that exact content (WS-1.9) ---
{
  const badCreatedDid: Did = "did:guardian:example.com:badcreated";
  const genesis = await signGenesis(
    { type: "custodial_create", did: badCreatedDid, name: "badcreated", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: [], prev: null },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  const newKey = await generateKeypair();
  const partial = { type: "custodial_rotate" as const, operationalKeys: [newKey.publicKey], services: {}, prev: genesisCid };
  const unsecuredDoc = unsecuredDocument(partial as any);
  const popProof = await createProof(unsecuredDoc, popVerificationMethod(newKey.publicKey), newKey.privateKey);
  const forgedWardProof = await signRawProofConfig(
    unsecuredDoc,
    { type: "DataIntegrityProof", cryptosuite: "ecdsa-jcs-2019", verificationMethod: `${badCreatedDid}#key-0`, proofPurpose: "assertionMethod", created: "not-a-real-timestamp" },
    ward.privateKey,
  );
  const rotate = { ...partial, proof: [popProof, forgedWardProof] } as unknown as CustodialRotateOp;
  write(
    "invalid",
    "proof_malformed_created",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(rotate), op: rotate }],
    "REJECT: the ward's own proof over the rotation carries created: \"not-a-real-timestamp\" -- a genuinely valid signature over that exact content, which validateProofShape (WS-1.9) must still refuse.",
    { [badCreatedDid]: ward.publicKey, ...registrarKnownKeys },
    "reject",
  );
}

// --- valid: a genesis whose services map has integer-like keys -- exercises RFC 8785 key ordering (WS-3.1), not just the common alphabetic case ---
{
  const intKeysDid: Did = "did:guardian:example.com:intkeys";
  const genesis = await signGenesis(
    {
      type: "custodial_create",
      did: intKeysDid,
      name: "intkeys",
      operationalKeys: [ward.publicKey],
      services: { "10": { type: "GuardianRegistrarService", endpoint: "https://example.com/ten" }, "2": { type: "GuardianRegistrarService", endpoint: "https://example.com/two" } },
      outgoing: [],
      incoming: [],
      prev: null,
    },
    {},
    { [ward.publicKey]: ward.privateKey },
  );
  write(
    "valid",
    "genesis_integer_like_service_keys",
    [{ cid: await cidFor(genesis), op: genesis }],
    "ACCEPT: genesis's services map has integer-like keys (\"2\", \"10\") -- any implementation whose JCS canonicalization sorts object keys by native numeric enumeration instead of RFC 8785's lexicographic UTF-16 order (WS-3.1) computes a DIFFERENT cid/signing input for this exact content and must fail to verify it.",
    { [intKeysDid]: ward.publicKey, ...registrarKnownKeys },
    "accept",
  );
}

// --- valid: forced guardian_remove meeting removal_threshold against the full live set (REQ-7.2-7b) ---
{
  const boardC = await generateKeypair();
  const forcedDid: Did = "did:guardian:example.com:forcedremoval";
  const guardians: [Did, Did, Did] = ["did:guardian:example.com:board-a", "did:guardian:example.com:board-b", "did:guardian:example.com:board-c"];
  const genesis = await signGenesis(
    { type: "custodial_create", did: forcedDid, name: "forcedremoval", operationalKeys: [ward.publicKey], services: {}, outgoing: [], incoming: guardians, prev: null },
    { [guardians[0]]: boardA.privateKey, [guardians[1]]: boardB.privateKey, [guardians[2]]: boardC.privateKey },
    { [ward.publicKey]: ward.privateKey },
  );
  const genesisCid = await cidFor(genesis);
  // board-a and board-b (majority of the full 3-member set) force out board-c, who never signs.
  const removeOp = await signGuardianRemove(
    { type: "guardian_remove", outgoing: guardians[2], prev: genesisCid },
    { [guardians[0]]: boardA.privateKey, [guardians[1]]: boardB.privateKey },
    [guardians[0], guardians[1]],
  );
  write(
    "valid",
    "guardian_remove_forced_majority",
    [{ cid: genesisCid, op: genesis }, { cid: await cidFor(removeOp), op: removeOp }],
    "ACCEPT: board-a and board-b, a majority of the full three-member guardian set, forcibly remove board-c (REQ-7.2-7b) -- board-c itself never signs.",
    { [guardians[0]]: boardA.publicKey, [guardians[1]]: boardB.publicKey, [guardians[2]]: boardC.publicKey, ...registrarKnownKeys },
    "accept",
  );
}

console.log("done.");
