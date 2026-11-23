// F-8, F-9, F-10, F-11 (audit r3, MEDIUM lib findings).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  resolve,
  verifyAttestation,
  checkAcceptance,
  createProof,
  createAttestation,
  generateKeypair,
  operationHash,
  multikeyToSpki,
  toMultibaseBase58btc,
  DEFAULT_POLICY,
} from "../src/index.js";
import type { CreateOp, Did, Log, LogResolver } from "../src/index.js";

// --- F-8: a malformed root log must not throw, only report invalid --------

test("F-8: verifyAttestation reports invalid (not a thrown exception) when the root log has a malformed entry", async () => {
  const rootDid = "did:guardian:f8-root.example" as Did;
  const did = "did:guardian:f8-root.example:alice" as Did;
  const brokenRootLog = [{ type: "create", did: rootDid, prev: null, broken: 0.5 }] as unknown as Log;
  const resolveLog: LogResolver = async (d) => (d === rootDid ? brokenRootLog : undefined);

  const key = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did,
    keys: [key.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const proof = await createProof(createBase, key.publicKey, key.privateKey);
  const attestation = await createAttestation(createBase, rootDid, "zSomeVersionThatWontBeFound", 0, key.privateKey);
  const createOp: CreateOp = { ...createBase, proof: [proof], attestation };

  await assert.doesNotReject(async () => {
    const result = await verifyAttestation(createOp, resolveLog);
    assert.equal(result, "invalid");
  });
});

test("F-8: resolve() with versionId reports invalid (not a thrown exception) on a malformed log", async () => {
  const did = "did:guardian:f8-resolve.example" as Did;
  const brokenLog = [{ type: "create", did, prev: null, broken: 0.5 }] as unknown as Log;
  const resolveLog: LogResolver = async () => undefined;

  await assert.doesNotReject(async () => {
    const result = await resolve(did, brokenLog, resolveLog, new Set(), "zSomeHash");
    assert.equal(result.result, "invalid");
  });
});

// --- F-9: an out-of-range x coordinate must be rejected --------------------

test("F-9: multikeyToSpki rejects a compressed point whose x coordinate is >= the field prime p", () => {
  // Build a syntactically-canonical Multikey (80 24 prefix, 35 bytes)
  // whose embedded x coordinate is deliberately p (the field prime) --
  // never a valid coordinate, since every element of the field is < p.
  const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
  const xBytes = new Uint8Array(32);
  let v = P256_P;
  for (let i = 31; i >= 0; i--) {
    xBytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  const compressed = new Uint8Array(33);
  compressed[0] = 0x02;
  compressed.set(xBytes, 1);
  const multicodecBytes = new Uint8Array(35);
  multicodecBytes[0] = 0x80;
  multicodecBytes[1] = 0x24;
  multicodecBytes.set(compressed, 2);
  const bogusKey = toMultibaseBase58btc(multicodecBytes);

  assert.throws(() => multikeyToSpki(bogusKey as never), /x coordinate/);
});

// --- F-10: attestation versionId must be a hash -----------------------------

test("F-10: a create's attestation.verificationMethod with a non-hash versionId is rejected at shape-check time", async () => {
  const rootDid = "did:guardian:f10-root.example" as Did;
  const did = "did:guardian:f10-root.example:alice" as Did;
  const key = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did,
    keys: [key.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const proof = await createProof(createBase, key.publicKey, key.privateKey);
  // A syntactically-plausible but non-hash versionId -- not a valid
  // multibase base58btc sha2-256 multihash at all.
  const bogusAttestation = await createAttestation(createBase, rootDid, "not-a-real-hash", 0, key.privateKey);
  const createOp: CreateOp = { ...createBase, proof: [proof], attestation: bogusAttestation };

  const resolveLog: LogResolver = async () => undefined;
  const result = await checkAcceptance(did, [], createOp, resolveLog);
  assert.equal(result.accepted, false);
});

// --- F-11: acceptance must reject when the root log can't be fetched, and must verify the signature ---

test("F-11: checkAcceptance rejects a create whose attestation names a root that cannot be resolved (instead of silently skipping the check)", async () => {
  const rootDid = "did:guardian:f11-root.example" as Did;
  const did = "did:guardian:f11-root.example:alice" as Did;
  const key = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did,
    keys: [key.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const proof = await createProof(createBase, key.publicKey, key.privateKey);
  const attestation = await createAttestation(createBase, rootDid, await operationHash({ type: "create", did: rootDid, keys: [], guardians: [], successor: null, policy: DEFAULT_POLICY, services: [], alsoKnownAs: [], prev: null, proof: [] }), 0, key.privateKey);
  const createOp: CreateOp = { ...createBase, proof: [proof], attestation };

  const resolveLog: LogResolver = async () => undefined; // the root can never be fetched
  const result = await checkAcceptance(did, [], createOp, resolveLog);
  assert.equal(result.accepted, false, "an unreachable root log must reject, not silently pass the currency check");
});

test("F-11: checkAcceptance rejects a create whose attestation signature does not actually verify, even though versionId names the current root version", async () => {
  const rootKey = await generateKeypair();
  const rootCreateBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did: "did:guardian:f11b-root.example" as Did,
    keys: [rootKey.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const rootProof = await createProof(rootCreateBase, rootKey.publicKey, rootKey.privateKey);
  const rootCreateOp: CreateOp = { ...rootCreateBase, proof: [rootProof] };
  const rootDid = rootCreateOp.did;
  const rootLog: Log = [rootCreateOp];
  const currentRootVersion = await operationHash(rootCreateOp);

  const did = "did:guardian:f11b-root.example:alice" as Did;
  const wardKey = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did,
    keys: [wardKey.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const proof = await createProof(createBase, wardKey.publicKey, wardKey.privateKey);
  // Signed with the WRONG key (the ward's own, not the root's) --
  // verificationMethod still correctly names the root's current
  // version and key-0, but the signature itself is not genuine.
  const forgedAttestation = await createAttestation(createBase, rootDid, currentRootVersion, 0, wardKey.privateKey);
  const createOp: CreateOp = { ...createBase, proof: [proof], attestation: forgedAttestation };

  const resolveLog: LogResolver = async (d) => (d === rootDid ? rootLog : undefined);
  const result = await checkAcceptance(did, [], createOp, resolveLog);
  assert.equal(result.accepted, false, "a forged attestation signature must be rejected even when versionId/key-index are correct");
});
