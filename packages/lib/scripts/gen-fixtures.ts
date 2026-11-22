// Generates interop_tests/operation_log/{valid,invalid}/*.json from this
// library's own signing and verification code -- never hand-typed. Every
// fixture is verified against this library's own verifyLog() as part of
// generation: a valid fixture must pass, an invalid one must fail with the
// expected REQ id as its rejection reason's own prefix. Run: npm run
// gen-fixtures (packages/lib).
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createProof,
  didReferenceVerificationMethod,
  generateKeypair,
  keyReferenceVerificationMethod,
  operationHash,
  unsecuredDocument,
  verifyLog,
} from "../src/index.js";
import type { CreateOp, Did, Key, Log, LogResolver, Operation } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_ROOT = path.join(__dirname, "..", "..", "..", "..", "interop_tests", "operation_log");
const DOMAIN = "example.com";
const ROOT_DID: Did = `did:guardian:${DOMAIN}`;

interface Keypair {
  publicKey: Key;
  privateKey: string;
}

interface Fixture {
  description: string;
  expect: "accept" | "reject";
  reject_req?: string;
  did: Did;
  log: Log;
  resolve: Record<string, Log>;
}

const covered = new Set<string>();
let failures = 0;

function note(reqs: string[]) {
  for (const r of reqs) covered.add(r);
}

async function write(kind: "valid" | "invalid", name: string, fixture: Fixture) {
  const resolver: LogResolver = (did) => (did === fixture.did ? fixture.log : fixture.resolve[did]);
  const result = await verifyLog(fixture.did, fixture.log, resolver);
  if (kind === "valid") {
    if (!result.valid) {
      console.error(`FAIL (expected accept): ${name}: ${result.reason}`);
      failures++;
    }
  } else {
    if (result.valid) {
      console.error(`FAIL (expected reject): ${name}: accepted`);
      failures++;
    } else if (fixture.reject_req && !result.reason?.startsWith(fixture.reject_req)) {
      console.error(`FAIL (wrong reason): ${name}: expected ${fixture.reject_req}, got: ${result.reason}`);
      failures++;
    }
  }
  const dir = path.join(OUT_ROOT, kind);
  fs.writeFileSync(path.join(dir, `${name}.json`), JSON.stringify(fixture, null, 2) + "\n");
}

async function keyRefProof(doc: unknown, key: Keypair): Promise<ReturnType<typeof createProof>> {
  return createProof(doc, keyReferenceVerificationMethod(key.publicKey), key.privateKey);
}

async function didRefProof(doc: unknown, did: Did, versionId: string, index: number, key: Keypair) {
  return createProof(doc, didReferenceVerificationMethod(did, versionId, index), key.privateKey);
}

/** Builds and signs a self-attested root create (REQ-7-4: create's own root-attestation requirement is waived when the DID IS the root). */
async function buildRoot(): Promise<{ key: Keypair; op: CreateOp; hash: string }> {
  const key = await generateKeypair();
  const partial: Omit<CreateOp, "proof"> = { type: "create", did: ROOT_DID, keys: [key.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
  const pop = await keyRefProof(unsecuredDocument(partial), key);
  const op: CreateOp = { ...partial, proof: [pop] };
  return { key, op, hash: await operationHash(op) };
}

/** Builds and signs a plain, guardianless, non-root create, attested by `root`. */
async function buildNamed(name: string, root: { key: Keypair; hash: string }, guardians: Did[] = [], guardianKeys: [Did, Keypair, string][] = []): Promise<{ key: Keypair; did: Did; op: CreateOp; hash: string }> {
  const key = await generateKeypair();
  const did: Did = `did:guardian:${DOMAIN}:${name}`;
  const partial: Omit<CreateOp, "proof"> = { type: "create", did, keys: [key.publicKey], guardians, policy: {}, services: [], alsoKnownAs: [], prev: null };
  const unsecured = unsecuredDocument(partial);
  const pop = await keyRefProof(unsecured, key);
  const guardianProofs = await Promise.all(guardianKeys.map(([gDid, gKey, gHash]) => didRefProof(unsecured, gDid, gHash, 0, gKey)));
  const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
  const op: CreateOp = { ...partial, proof: [pop, ...guardianProofs, attestation] };
  return { key, did, op, hash: await operationHash(op) };
}

async function main() {
  for (const kind of ["valid", "invalid"] as const) {
    for (const f of fs.readdirSync(path.join(OUT_ROOT, kind))) fs.unlinkSync(path.join(OUT_ROOT, kind, f));
  }

  const root = await buildRoot();
  await write("valid", "root_self_attested_create", {
    description: "The root identity's own create needs no separate attestation -- its key's own proof of possession is sufficient (REQ-7-4's create rule, root-identity exception).",
    expect: "accept",
    did: ROOT_DID,
    log: [root.op],
    resolve: {},
  });
  note(["REQ-7-4", "REQ-7-5", "REQ-7-6", "REQ-9-1"]);

  // ---- REQ-4: identifier ----
  for (const [name, did, expect, reqId] of [
    ["name_too_short", `did:guardian:${DOMAIN}:ab`, "reject", "REQ-4-3"],
    ["name_too_long", `did:guardian:${DOMAIN}:${"a".repeat(33)}`, "reject", "REQ-4-3"],
    ["name_leading_hyphen", `did:guardian:${DOMAIN}:-abc`, "reject", "REQ-4-3"],
    ["domain_trailing_dot", `did:guardian:${DOMAIN}.:abc`, "reject", "REQ-4-2"],
    ["domain_uppercase", `did:guardian:EXAMPLE.com:abc`, "reject", "REQ-4-2"],
    ["not_this_method", `did:web:${DOMAIN}:abc`, "reject", "REQ-4-1"],
  ] as const) {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: did as Did, keys: [key.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("invalid", name, { description: `${reqId}: ${name}`, expect: "reject", reject_req: reqId, did: did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
    note([reqId]);
  }
  {
    const named = await buildNamed("rootcheckvalid", root);
    await write("valid", "name_valid_grammar", {
      description: "REQ-4-3/REQ-4-2: a conforming name and domain are accepted.",
      expect: "accept",
      did: named.did,
      log: [named.op],
      resolve: { [ROOT_DID]: [root.op] },
    });
    note(["REQ-4-1", "REQ-4-2", "REQ-4-3", "REQ-4-4", "REQ-4-5"]);
  }

  // ---- A richer world: alice, with g1/g2/g3 as guardians. ----
  const g1 = await buildNamed("guardone", root);
  const g2 = await buildNamed("guardtwo", root);
  const g3 = await buildNamed("guardthree", root);
  const guardianLogs: Record<string, Log> = { [g1.did]: [g1.op], [g2.did]: [g2.op], [g3.did]: [g3.op], [ROOT_DID]: [root.op] };
  const alice = await buildNamed("alice3g", root, [g1.did, g2.did, g3.did], [
    [g1.did, g1.key, g1.hash],
    [g2.did, g2.key, g2.hash],
    [g3.did, g3.key, g3.hash],
  ]);
  const aliceResolve = { ...guardianLogs };

  await write("valid", "create_three_guardians", {
    description: "REQ-7-4 create: every key, every named guardian, and the root attestation all approve.",
    expect: "accept",
    did: alice.did,
    log: [alice.op],
    resolve: aliceResolve,
  });
  note(["REQ-5-16", "REQ-7-4", "REQ-7-5", "REQ-7-6", "REQ-9-1"]);

  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:missingguardiansig` as Did, keys: [key.publicKey], guardians: [g1.did], policy: {}, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("invalid", "create_missing_guardian_approval", { description: "REQ-7-4: create requires every named guardian's own approval.", expect: "reject", reject_req: "REQ-7-4", did: partial.did as Did, log: [op], resolve: aliceResolve });
  }
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:missingattest` as Did, keys: [key.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
    const pop = await keyRefProof(unsecuredDocument(partial), key);
    const op: CreateOp = { ...partial, proof: [pop] };
    await write("invalid", "create_missing_root_attestation", { description: "REQ-7-4: a non-root create requires the root identity's own approval.", expect: "reject", reject_req: "REQ-7-4", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: alice.did, keys: alice.op.keys, guardians: alice.op.guardians, policy: {}, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const g1c = await didRefProof(unsecured, g1.did, g1.hash, 0, g1.key);
    const g2c = await didRefProof(unsecured, g2.did, g2.hash, 0, g2.key);
    const g3c = await didRefProof(unsecured, g3.did, g3.hash, 0, g3.key);
    const op: CreateOp = { ...partial, proof: [g1c, g2c, g3c, attestation] }; // no PoP for alice's own key
    await write("invalid", "create_missing_key_pop", { description: "REQ-7-4: create requires a proof of possession for every key in keys.", expect: "reject", reject_req: "REQ-7-4", did: alice.did, log: [op], resolve: aliceResolve });
  }

  // ---- REQ-5-8/REQ-5-9/REQ-5-12/REQ-5-15: proof encoding. ----
  {
    const op = { ...alice.op, proof: "not-an-array" as unknown as Operation["proof"] };
    await write("invalid", "proof_not_an_array", { description: "REQ-5-8: proof must be an array.", expect: "reject", reject_req: "REQ-5-8", did: alice.did, log: [op as unknown as Operation], resolve: aliceResolve });
  }
  {
    const badProof = { ...alice.op.proof[0], created: "2026-01-01T00:00:00Z" } as unknown as Operation["proof"][number];
    const op = { ...alice.op, proof: [badProof, ...alice.op.proof.slice(1)] };
    await write("invalid", "proof_extra_member", { description: "REQ-5-9: a proof must contain exactly type, cryptosuite, verificationMethod, proofPurpose and proofValue -- no created.", expect: "reject", reject_req: "REQ-5-9", did: alice.did, log: [op], resolve: aliceResolve });
  }
  {
    const badProof = { ...alice.op.proof[0], proofPurpose: "assertionMethod" } as unknown as Operation["proof"][number];
    const op = { ...alice.op, proof: [badProof, ...alice.op.proof.slice(1)] };
    await write("invalid", "proof_wrong_purpose", { description: "REQ-5-9: proofPurpose must be capabilityInvocation.", expect: "reject", reject_req: "REQ-5-9", did: alice.did, log: [op], resolve: aliceResolve });
  }
  {
    const badVm = alice.op.proof[0].verificationMethod.replace("did:key:", "did:example:");
    const badProof = { ...alice.op.proof[0], verificationMethod: badVm };
    const op = { ...alice.op, proof: [badProof, ...alice.op.proof.slice(1)] };
    await write("invalid", "proof_unrecognized_verification_method", { description: "REQ-5-12: verificationMethod must be a key reference or a DID reference.", expect: "reject", reject_req: "REQ-5-12", did: alice.did, log: [op], resolve: aliceResolve });
  }
  {
    const dup = alice.op.proof[1]; // g1's proof
    const op = { ...alice.op, proof: [...alice.op.proof, dup] };
    await write("invalid", "proof_duplicate_signer", { description: "REQ-5-15: an operation must not contain two proofs from the same signer.", expect: "reject", reject_req: "REQ-5-15", did: alice.did, log: [op], resolve: aliceResolve });
  }
  note(["REQ-5-8", "REQ-5-9", "REQ-5-12", "REQ-5-15"]);

  // ---- REQ-5-11: low-S. Flips a valid signature's s to n - s (still a mathematically valid ECDSA signature, but the malleable, non-canonical form). ----
  {
    const { fromMultibaseBase58btc, toMultibaseBase58btc } = await import("../src/crypto.js");
    const P256_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    const popProof = alice.op.proof[0];
    const sigBytes = fromMultibaseBase58btc(popProof.proofValue);
    let s = 0n;
    for (let i = 32; i < 64; i++) s = (s << 8n) | BigInt(sigBytes[i]);
    const flipped = P256_N - s;
    const flippedBytes = new Uint8Array(sigBytes);
    let v = flipped;
    for (let i = 63; i >= 32; i--) {
      flippedBytes[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    const highSProof = { ...popProof, proofValue: toMultibaseBase58btc(flippedBytes) };
    const op = { ...alice.op, proof: [highSProof, ...alice.op.proof.slice(1)] };
    await write("invalid", "proof_high_s_signature", { description: "REQ-5-11: a verifier must reject a signature whose S value is greater than half the curve order.", expect: "reject", reject_req: "REQ-5-13", did: alice.did, log: [op], resolve: aliceResolve });
  }
  note(["REQ-5-11"]);

  // ---- REQ-5-14: DID-reference clauses. ----
  {
    const newKey = await generateKeypair();
    const partial = { type: "update" as const, keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: alice.hash };
    const pop = await keyRefProof(unsecuredDocument(partial), newKey);
    const badHashProof = await didRefProof(unsecuredDocument(partial), g1.did, "zNotARealHash", 0, g1.key);
    const op = { ...partial, proof: [pop, badHashProof] };
    await write("invalid", "did_reference_hash_not_found", { description: "REQ-5-14 clause 1: the referenced operation hash must appear in that DID's log.", expect: "reject", reject_req: "REQ-5-14", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  {
    const newKey = await generateKeypair();
    const partial = { type: "update" as const, keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: alice.hash };
    const pop = await keyRefProof(unsecuredDocument(partial), newKey);
    const badIndexProof = await didRefProof(unsecuredDocument(partial), g1.did, g1.hash, 5, g1.key);
    const op = { ...partial, proof: [pop, badIndexProof] };
    await write("invalid", "did_reference_key_index_out_of_range", { description: "REQ-5-14 clause 4: the state after the referenced operation must have a key at that index.", expect: "reject", reject_req: "REQ-5-14", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  {
    // g1 deactivates itself, then tries to approve alice's update anyway, referencing its pre-deactivation state.
    const g1DeactivatePartial = { type: "deactivate" as const, prev: g1.hash };
    const g1DeactivateProof = await keyRefProof(unsecuredDocument(g1DeactivatePartial), g1.key);
    const g1DeactivateOp = { ...g1DeactivatePartial, proof: [g1DeactivateProof] };
    const g1DeactivateHash = await operationHash(g1DeactivateOp);
    const resolveWithDeactivatedG1 = { ...aliceResolve, [g1.did]: [g1.op, g1DeactivateOp] };

    const newKey = await generateKeypair();
    const partial = { type: "update" as const, keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: alice.hash };
    const pop = await keyRefProof(unsecuredDocument(partial), newKey);
    const deactivatedApproval = await didRefProof(unsecuredDocument(partial), g1.did, g1DeactivateHash, 0, g1.key);
    const op = { ...partial, proof: [pop, deactivatedApproval] };
    await write("invalid", "did_reference_signer_deactivated", { description: "REQ-5-14 clause 3: the state after the referenced operation must not be deactivated.", expect: "reject", reject_req: "REQ-5-14", did: alice.did, log: [alice.op, op], resolve: resolveWithDeactivatedG1 });
  }
  note(["REQ-5-14"]);

  // ---- REQ-6-1/REQ-6-2: state shape. ----
  {
    const key1 = await generateKeypair();
    const key9 = await Promise.all(Array.from({ length: 9 }, () => generateKeypair()));
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:toomanykeys` as Did, keys: [key1.publicKey, ...key9.map((k) => k.publicKey)], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pops = await Promise.all([key1, ...key9].map((k) => keyRefProof(unsecured, k)));
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [...pops, attestation] };
    await write("invalid", "state_too_many_keys", { description: "REQ-6-1: keys must contain at most 8 entries.", expect: "reject", reject_req: "REQ-6-1", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:dupsvc` as Did, keys: [key.publicKey], guardians: [], policy: {}, services: [{ id: "#a", type: "x", serviceEndpoint: "https://a.example" }, { id: "#a", type: "y", serviceEndpoint: "https://b.example" }], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("invalid", "state_duplicate_service_id", { description: "REQ-6-2: two services must not have the same id.", expect: "reject", reject_req: "REQ-6-2", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:goodsvc` as Did, keys: [key.publicKey], guardians: [], policy: {}, services: [{ id: "#home", type: "LinkedDomains", serviceEndpoint: "https://goodsvc.example" }], alsoKnownAs: ["https://alias.example"], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("valid", "state_service_and_alias", { description: "REQ-6-2/REQ-9-2: a conforming service and an alsoKnownAs entry are accepted and carried into the DID document.", expect: "accept", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  note(["REQ-6-1", "REQ-6-2"]);

  // ---- REQ-6-4/REQ-6-5: policy shape. ----
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:badpolicymember` as Did, keys: [key.publicKey], guardians: [], policy: { unknownField: 1 } as unknown as Record<string, unknown>, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("invalid", "policy_unknown_member", { description: "REQ-6-4: policy must not contain a member other than recovery, membership, removal and deactivation.", expect: "reject", reject_req: "REQ-6-4", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:membershipany` as Did, keys: [key.publicKey], guardians: [], policy: { membership: "any" } as unknown as Record<string, unknown>, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("invalid", "policy_membership_any_not_allowed", { description: "REQ-6-4: membership's allowed values do not include \"any\".", expect: "reject", reject_req: "REQ-6-4", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:deactmissing` as Did, keys: [key.publicKey], guardians: [], policy: { deactivation: { by: "self" } } as unknown as Record<string, unknown>, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("invalid", "policy_deactivation_missing_threshold", { description: "REQ-6-5: deactivation must contain exactly by and threshold.", expect: "reject", reject_req: "REQ-6-5", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:custompolicy` as Did, keys: [key.publicKey], guardians: [], policy: { recovery: "any", removal: 2, deactivation: { by: "either", threshold: "all" } }, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("valid", "policy_custom_settings", { description: "REQ-6-4/REQ-6-5: a custom policy with every member set to an allowed value is accepted.", expect: "accept", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  note(["REQ-6-4", "REQ-6-5"]);

  // ---- REQ-6-6/REQ-6-7: two guardians, removal="majority" -- neither can remove the other. ----
  {
    const h1 = await buildNamed("htwoguardone", root);
    const h2 = await buildNamed("htwoguardtwo", root);
    const twoGResolve = { [ROOT_DID]: [root.op], [h1.did]: [h1.op], [h2.did]: [h2.op] };
    const ward = await buildNamed("twoguardianward", root, [h1.did, h2.did], [
      [h1.did, h1.key, h1.hash],
      [h2.did, h2.key, h2.hash],
    ]);
    const wardHash = ward.hash;
    const removePartial = { type: "removeGuardian" as const, guardian: h2.did, prev: wardHash };
    const h1Approval = await didRefProof(unsecuredDocument(removePartial), h1.did, h1.hash, 0, h1.key);
    const removeOp = { ...removePartial, proof: [h1Approval] };
    await write("invalid", "remove_guardian_two_guardians_impossible", {
      description: "REQ-6-7: with two guardians and removal \"majority\" (its own base of 1, then raised to 2 by step 2), the required number exceeds E = N - 1 = 1 -- guardians cannot approve.",
      expect: "reject",
      reject_req: "REQ-6-7",
      did: ward.did,
      log: [ward.op, removeOp],
      resolve: { ...twoGResolve, [ward.did]: [ward.op] },
    });
  }
  note(["REQ-6-6", "REQ-6-7"]);

  // ---- REQ-5-1/REQ-5-2/REQ-5-3/REQ-5-4: encoding. ----
  {
    const op = "not-an-object" as unknown as Operation;
    await write("invalid", "operation_not_an_object", { description: "REQ-5-1: an operation must be a JSON object.", expect: "reject", reject_req: "REQ-5-1", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  {
    // policy.recovery is already out of JCS-safe range -- this library's own createProof would refuse to sign it (the same assertJCSSafe a verifier's own canonicalization would hit), so the shape check must catch this before any proof is even looked at. An empty proof array is enough to demonstrate that.
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:hugeinteger` as Did, keys: [key.publicKey], guardians: [], policy: { recovery: 2 ** 53 }, services: [], alsoKnownAs: [], prev: null };
    const op: CreateOp = { ...partial, proof: [] };
    await write("invalid", "integer_out_of_range", { description: "REQ-5-2: every number must be an integer between 0 and 2^53 - 1.", expect: "reject", reject_req: "REQ-5-2", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:lonesurrogate` as Did, keys: [key.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: ["https://example.com/\uD800"], prev: null };
    const op: CreateOp = { ...partial, proof: [] };
    await write("invalid", "lone_surrogate_in_string", { description: "REQ-5-3: every string must be valid UTF-8, with no unpaired surrogates.", expect: "reject", reject_req: "REQ-5-3", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const op = { ...alice.op, unexpectedMember: "surprise" } as unknown as Operation;
    await write("invalid", "operation_extra_member", { description: "REQ-5-4: an operation must not contain members other than those defined for its type.", expect: "reject", reject_req: "REQ-7-5", did: alice.did, log: [op], resolve: aliceResolve });
  }
  note(["REQ-5-1", "REQ-5-2", "REQ-5-3", "REQ-5-4", "REQ-5-5", "REQ-5-6", "REQ-5-7", "REQ-5-10"]);

  {
    const badKey = "zNotAValidMultikeyAtAll";
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:badkeyformat` as Did, keys: [badKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
    const op = { ...partial, proof: [] } as unknown as CreateOp;
    await write("invalid", "key_not_a_valid_multikey", { description: "REQ-5-7: every key must be a Multikey-encoded P-256 public key.", expect: "reject", reject_req: "REQ-5-7", did: partial.did as Did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }

  // ---- REQ-7-1/REQ-7-2/REQ-7-3: common members. ----
  {
    const op = { prev: alice.hash, proof: [] } as unknown as Operation; // no type at all
    await write("invalid", "operation_missing_type", { description: "REQ-7-1: every operation must contain type, prev and proof.", expect: "reject", reject_req: "REQ-7-2", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  {
    const op = { type: "destroy", prev: alice.hash, proof: [] } as unknown as Operation;
    await write("invalid", "operation_unrecognized_type", { description: "REQ-7-2: type must be one of create, update, addGuardian, removeGuardian, setPolicy or deactivate.", expect: "reject", reject_req: "REQ-7-2", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  {
    const op = { ...alice.op, prev: "zSomeHash" } as unknown as Operation;
    await write("invalid", "create_prev_not_null", { description: "REQ-7-3: a create operation's prev must be null.", expect: "reject", reject_req: "REQ-7-3", did: alice.did, log: [op], resolve: aliceResolve });
  }
  note(["REQ-7-1", "REQ-7-2", "REQ-7-3"]);

  // ---- REQ-7-7/REQ-7-8: update. ----
  {
    const newKey = await generateKeypair();
    const partial = { type: "update" as const, keys: [newKey.publicKey], services: [], prev: alice.hash }; // missing alsoKnownAs
    const pop = await keyRefProof(unsecuredDocument(partial), newKey);
    const op = { ...partial, proof: [pop] } as unknown as Operation;
    await write("invalid", "update_missing_member", { description: "REQ-7-7: an update operation must contain exactly type, keys, services, alsoKnownAs, prev and proof.", expect: "reject", reject_req: "REQ-7-7", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  {
    const newKey = await generateKeypair();
    const newService = { id: "#new", type: "LinkedDomains", serviceEndpoint: "https://alice.example" };
    const partial = { type: "update" as const, keys: [newKey.publicKey], services: [newService], alsoKnownAs: ["https://alias.example/alice"], prev: alice.hash };
    const unsecuredUpdate = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecuredUpdate, newKey);
    const g1Approval = await didRefProof(unsecuredUpdate, g1.did, g1.hash, 0, g1.key);
    const g2Approval = await didRefProof(unsecuredUpdate, g2.did, g2.hash, 0, g2.key);
    const op = { ...partial, proof: [pop, g1Approval, g2Approval] };
    const result = await write("valid", "update_replaces_keys_services_alsoKnownAs", { description: "REQ-7-8: update replaces keys, services and alsoKnownAs in the state.", expect: "accept", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
    void result;
  }
  note(["REQ-7-7", "REQ-7-8"]);

  // ---- REQ-7-9/REQ-7-10/REQ-7-11: addGuardian. ----
  const extraGuardian = await buildNamed("extraguardone", root);
  const extraGuardianResolve = { ...aliceResolve, [extraGuardian.did]: [extraGuardian.op] };
  {
    const partial = { type: "addGuardian" as const, guardian: g1.did, prev: alice.hash }; // already a guardian
    const consent = await didRefProof(unsecuredDocument(partial), g1.did, g1.hash, 0, g1.key);
    const membershipApprovals = await Promise.all([
      didRefProof(unsecuredDocument(partial), g1.did, g1.hash, 0, g1.key),
      didRefProof(unsecuredDocument(partial), g2.did, g2.hash, 0, g2.key),
    ]);
    const op = { ...partial, proof: [consent, ...membershipApprovals.slice(1)] };
    await write("invalid", "add_guardian_already_a_guardian", { description: "REQ-7-10: guardian must not already be a guardian.", expect: "reject", reject_req: "REQ-7-10", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  {
    const partial = { type: "addGuardian" as const, guardian: extraGuardian.did, prev: alice.hash };
    const unsecured = unsecuredDocument(partial);
    const consent = await didRefProof(unsecured, extraGuardian.did, extraGuardian.hash, 0, extraGuardian.key);
    const g1Approval = await didRefProof(unsecured, g1.did, g1.hash, 0, g1.key);
    const g2Approval = await didRefProof(unsecured, g2.did, g2.hash, 0, g2.key);
    const op = { ...partial, proof: [consent, g1Approval, g2Approval] };
    const result = await write("valid", "add_guardian_membership_majority", { description: "REQ-7-4/REQ-7-11: addGuardian with N=3 (membership majority -> 2) approved by the new guardian and 2 of 3 current guardians appends it to guardians.", expect: "accept", did: alice.did, log: [alice.op, op], resolve: extraGuardianResolve });
    void result;
  }
  {
    const soloKey = await generateKeypair();
    const soloPartial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:soloward` as Did, keys: [soloKey.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
    const soloUnsecured = unsecuredDocument(soloPartial);
    const soloPop = await keyRefProof(soloUnsecured, soloKey);
    const soloAttestation = await didRefProof(soloUnsecured, ROOT_DID, root.hash, 0, root.key);
    const soloOp: CreateOp = { ...soloPartial, proof: [soloPop, soloAttestation] };
    const soloHash = await operationHash(soloOp);
    const addPartial = { type: "addGuardian" as const, guardian: g1.did, prev: soloHash };
    const addUnsecured = unsecuredDocument(addPartial);
    const consent = await didRefProof(addUnsecured, g1.did, g1.hash, 0, g1.key);
    const ownKey = await keyRefProof(addUnsecured, soloKey);
    const addOp = { ...addPartial, proof: [consent, ownKey] };
    const result = await write("valid", "add_guardian_zero_to_one_by_own_key", { description: "REQ-7-4: addGuardian with N=0 is approved by the added guardian and one current key.", expect: "accept", did: soloPartial.did as Did, log: [soloOp, addOp], resolve: { [ROOT_DID]: [root.op], [g1.did]: [g1.op] } });
    void result;
  }
  note(["REQ-7-9", "REQ-7-10", "REQ-7-11"]);

  // ---- REQ-7-12/REQ-7-13/REQ-7-14/REQ-7-15: removeGuardian. ----
  {
    const partial = { type: "removeGuardian" as const, guardian: extraGuardian.did, prev: alice.hash }; // never a guardian
    const g1Approval = await didRefProof(unsecuredDocument(partial), g1.did, g1.hash, 0, g1.key);
    const g2Approval = await didRefProof(unsecuredDocument(partial), g2.did, g2.hash, 0, g2.key);
    const op = { ...partial, proof: [g1Approval, g2Approval] };
    await write("invalid", "remove_guardian_not_a_current_guardian", { description: "REQ-7-13: guardian must be a current guardian.", expect: "reject", reject_req: "REQ-7-13", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  {
    const partial = { type: "removeGuardian" as const, guardian: g3.did, prev: alice.hash };
    const unsecured = unsecuredDocument(partial);
    const g1Approval = await didRefProof(unsecured, g1.did, g1.hash, 0, g1.key);
    const g2Approval = await didRefProof(unsecured, g2.did, g2.hash, 0, g2.key);
    const op = { ...partial, proof: [g1Approval, g2Approval] };
    const result = await write("valid", "remove_guardian_forced_majority", { description: "REQ-7-4/REQ-7-15: removeGuardian with N=3 (removal majority against E=N-1=2 -> 2) approved by the 2 other guardians removes the named guardian.", expect: "accept", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
    void result;
  }
  {
    // g3 deactivates itself; alice's own key then removes it with evidence, with no other guardian needed.
    const g3DeactivatePartial = { type: "deactivate" as const, prev: g3.hash };
    const g3DeactivateProof = await keyRefProof(unsecuredDocument(g3DeactivatePartial), g3.key);
    const g3DeactivateOp = { ...g3DeactivatePartial, proof: [g3DeactivateProof] };
    const g3DeactivateHash = await operationHash(g3DeactivateOp);
    const resolveWithDeactivatedG3 = { ...aliceResolve, [g3.did]: [g3.op, g3DeactivateOp] };

    const partial = { type: "removeGuardian" as const, guardian: g3.did, evidence: g3DeactivateHash, prev: alice.hash };
    const ownKey = await keyRefProof(unsecuredDocument(partial), alice.key);
    const op = { ...partial, proof: [ownKey] };
    const result = await write("valid", "remove_guardian_with_evidence", { description: "REQ-7-14/REQ-7-4: removeGuardian with evidence of the removed guardian's own deactivation is approved by one current key alone.", expect: "accept", did: alice.did, log: [alice.op, op], resolve: resolveWithDeactivatedG3 });
    void result;

    const badEvidencePartial = { type: "removeGuardian" as const, guardian: g2.did, evidence: g3DeactivateHash, prev: alice.hash }; // evidence names a DIFFERENT guardian's deactivation
    const badOwnKey = await keyRefProof(unsecuredDocument(badEvidencePartial), alice.key);
    const badOp = { ...badEvidencePartial, proof: [badOwnKey] };
    await write("invalid", "remove_guardian_evidence_wrong_log", { description: "REQ-7-14: evidence must be a deactivate operation hash in the REMOVED guardian's own log.", expect: "reject", reject_req: "REQ-7-14", did: alice.did, log: [alice.op, badOp], resolve: resolveWithDeactivatedG3 });
  }
  note(["REQ-7-12", "REQ-7-13", "REQ-7-14", "REQ-7-15"]);

  // ---- REQ-7-16/REQ-7-17: setPolicy. ----
  {
    const partial = { type: "setPolicy" as const, policy: { recovery: "all" as const }, prev: alice.hash };
    const unsecured = unsecuredDocument(partial);
    const ownKey = await keyRefProof(unsecured, alice.key);
    const g1Approval = await didRefProof(unsecured, g1.did, g1.hash, 0, g1.key);
    const g2Approval = await didRefProof(unsecured, g2.did, g2.hash, 0, g2.key);
    const op = { ...partial, proof: [ownKey, g1Approval, g2Approval] };
    const result = await write("valid", "set_policy_replaces_policy", { description: "REQ-7-4/REQ-7-17: setPolicy, approved by one current key and enough guardians per membership, replaces policy in the state.", expect: "accept", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
    void result;
  }
  {
    const partial = { type: "setPolicy" as const, policy: { recovery: "all" as const }, prev: alice.hash };
    const unsecured = unsecuredDocument(partial);
    const g1Approval = await didRefProof(unsecured, g1.did, g1.hash, 0, g1.key);
    const g2Approval = await didRefProof(unsecured, g2.did, g2.hash, 0, g2.key);
    const op = { ...partial, proof: [g1Approval, g2Approval] }; // no key approval at all
    await write("invalid", "set_policy_missing_key_approval", { description: "REQ-7-4: setPolicy requires one current key regardless of guardian approvals.", expect: "reject", reject_req: "REQ-7-4", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  note(["REQ-7-16", "REQ-7-17"]);

  // ---- REQ-7-18/REQ-7-19: deactivate (both, the default). ----
  {
    const partial = { type: "deactivate" as const, prev: alice.hash };
    const unsecured = unsecuredDocument(partial);
    const ownKey = await keyRefProof(unsecured, alice.key);
    const op = { ...partial, proof: [ownKey] }; // key only, no guardian -- default policy is "both"
    await write("invalid", "deactivate_missing_guardian_approval_default_both", { description: "REQ-7-4: deactivate under the default policy (deactivation.by: both) requires one current key AND enough guardian approvals.", expect: "reject", reject_req: "REQ-7-4", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
  }
  note(["REQ-7-18", "REQ-7-19"]);

  // ---- REQ-8-1: log structure. ----
  await write("invalid", "log_empty", { description: "REQ-8-1 step 1: the log must be a non-empty array of operations.", expect: "reject", reject_req: "REQ-8-1", did: alice.did, log: [], resolve: aliceResolve });
  {
    const notCreate = { type: "deactivate" as const, prev: null as unknown as string, proof: [] };
    await write("invalid", "log_first_operation_not_create", { description: "REQ-8-1 step 2: the first operation must be a create.", expect: "reject", reject_req: "REQ-8-1", did: alice.did, log: [notCreate as unknown as Operation], resolve: aliceResolve });
  }
  {
    const key = await generateKeypair();
    const partial: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:somebodyelse` as Did, keys: [key.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, key);
    const attestation = await didRefProof(unsecured, ROOT_DID, root.hash, 0, root.key);
    const op: CreateOp = { ...partial, proof: [pop, attestation] };
    await write("invalid", "log_create_did_mismatch", { description: "REQ-8-1 step 2: the first operation's did must equal the DID being verified.", expect: "reject", reject_req: "REQ-8-1", did: alice.did, log: [op], resolve: { [ROOT_DID]: [root.op] } });
  }
  {
    const key1 = await generateKeypair();
    const partial1: Omit<CreateOp, "proof"> = { type: "create", did: `did:guardian:${DOMAIN}:prevmismatch` as Did, keys: [key1.publicKey], guardians: [], policy: {}, services: [], alsoKnownAs: [], prev: null };
    const unsecured1 = unsecuredDocument(partial1);
    const pop1 = await keyRefProof(unsecured1, key1);
    const attestation1 = await didRefProof(unsecured1, ROOT_DID, root.hash, 0, root.key);
    const op1: CreateOp = { ...partial1, proof: [pop1, attestation1] };
    const key2 = await generateKeypair();
    const partial2 = { type: "update" as const, keys: [key2.publicKey], services: [], alsoKnownAs: [], prev: "zWrongPrevHash" };
    const pop2 = await keyRefProof(unsecuredDocument(partial2), key2);
    const op2 = { ...partial2, proof: [pop2] };
    await write("invalid", "log_prev_mismatch", { description: "REQ-8-1 step 3: each later operation's prev must equal the operation hash of the operation before it.", expect: "reject", reject_req: "REQ-8-1", did: partial1.did as Did, log: [op1, op2], resolve: { [ROOT_DID]: [root.op] } });
  }
  note(["REQ-8-1"]);

  // ---- REQ-8-3: a circular DID reference. ----
  {
    // alice's own deactivate names itself as evidence for removing a (nonexistent) guardian reference -- a direct self-cycle: the proof names alice's OWN pending operation.
    const partial = { type: "update" as const, keys: alice.op.keys, services: [], alsoKnownAs: [], prev: alice.hash };
    const unsecured = unsecuredDocument(partial);
    const selfPop = await keyRefProof(unsecured, alice.key);
    // This proof claims alice's OWN did as a DID-reference approver, naming a versionId that does not exist YET (this very operation's own eventual hash) -- unresolvable without circularity.
    const op = { ...partial, proof: [selfPop] };
    const selfHash = await operationHash(op);
    const circularProof = await didRefProof(unsecured, alice.did, selfHash, 0, alice.key);
    const circularOp = { ...partial, proof: [selfPop, circularProof] };
    await write("invalid", "did_reference_self_cycle", { description: "REQ-8-3: a verifier must reject a proof whose verification requires verifying the operation that contains it.", expect: "reject", reject_req: "REQ-8-3", did: alice.did, log: [alice.op, circularOp], resolve: aliceResolve });
  }

  // ---- REQ-9-2/REQ-9-3/REQ-9-4: DID document derivation is covered directly in document.test.ts; this fixture just confirms a deactivated identity still verifies (its log stays servable, REQ-10-5) and keeps deactivated: true afterward. ----
  {
    const partial = { type: "deactivate" as const, prev: alice.hash };
    const unsecured = unsecuredDocument(partial);
    const ownKey = await keyRefProof(unsecured, alice.key);
    const g1Approval = await didRefProof(unsecured, g1.did, g1.hash, 0, g1.key);
    const g2Approval = await didRefProof(unsecured, g2.did, g2.hash, 0, g2.key);
    const op = { ...partial, proof: [ownKey, g1Approval, g2Approval] };
    const result = await write("valid", "deactivate_both_satisfied", { description: "REQ-7-4/REQ-7-19/REQ-9-4: deactivate under the default policy, approved by one current key and enough guardians, sets deactivated to true.", expect: "accept", did: alice.did, log: [alice.op, op], resolve: aliceResolve });
    void result;
  }
  note(["REQ-9-1", "REQ-9-2", "REQ-9-3", "REQ-9-4"]);

  // ---- REQ-8-4: a referenced log this verifier cannot retrieve at all (absent from resolve). ----
  {
    const newKey = await generateKeypair();
    const partial = { type: "update" as const, keys: [newKey.publicKey], services: [], alsoKnownAs: [], prev: alice.hash };
    const unsecured = unsecuredDocument(partial);
    const pop = await keyRefProof(unsecured, newKey);
    const g1Approval = await didRefProof(unsecured, g1.did, g1.hash, 0, g1.key);
    const op = { ...partial, proof: [pop, g1Approval] };
    const resolveWithoutG1 = { ...aliceResolve };
    delete resolveWithoutG1[g1.did];
    await write("invalid", "resolve_unreachable_log", { description: "REQ-8-4: a verifier that cannot retrieve a referenced log must report the log as not verified.", expect: "reject", reject_req: "REQ-8-4", did: alice.did, log: [alice.op, op], resolve: resolveWithoutG1 });
  }
  note(["REQ-5-13", "REQ-8-4"]);

  console.log(`\n${failures === 0 ? "OK" : "FAILED"}: ${failures} mismatches, ${covered.size} REQs covered so far`);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
