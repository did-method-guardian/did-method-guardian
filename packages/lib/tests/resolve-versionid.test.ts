// REQ-9-5: resolving with a versionId derives the document from the
// state right after that operation, not the log's own current end.
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "../src/resolve.js";
import { createProof, DEFAULT_POLICY, generateKeypair, operationHash } from "../src/index.js";
import type { CreateOp, Did, Log, Service, UpdateOp } from "../src/index.js";

// A bare-domain (root) identity's own create needs no attestation
// (REQ-7-7), which keeps this test self-contained -- it isn't testing
// attestation, so there's no need to also build a root log for one.
const DID = "did:guardian:example.com" as Did;

async function buildLog(): Promise<{ log: Log; createHash: string; updateHash: string; key1: string; key2: string }> {
  const key1 = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did: DID,
    keys: [key1.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const createProof1 = await createProof(createBase, key1.publicKey, key1.privateKey);
  const createOp: CreateOp = { ...createBase, proof: [createProof1] };
  const createHash = await operationHash(createOp);

  const key2 = await generateKeypair();
  const service: Service = { id: "#agent", type: "AgentCard", serviceEndpoint: "https://example.com/agent" };
  const updateBase: Omit<UpdateOp, "proof"> = {
    type: "update",
    keys: [key2.publicKey],
    services: [service],
    alsoKnownAs: [],
    prev: createHash,
  };
  const newKeyProof = await createProof(updateBase, key2.publicKey, key2.privateKey);
  const oldKeyProof = await createProof(updateBase, key1.publicKey, key1.privateKey);
  const updateOp: UpdateOp = { ...updateBase, proof: [newKeyProof, oldKeyProof].sort((a, b) => (a.verificationMethod < b.verificationMethod ? -1 : 1)) };
  const updateHash = await operationHash(updateOp);

  return { log: [createOp, updateOp], createHash, updateHash, key1: key1.publicKey, key2: key2.publicKey };
}

test("resolve with versionId=the create's own hash yields the document as of the create alone, even though the log has a later update", async () => {
  const { log, createHash, key1 } = await buildLog();
  const result = await resolve(DID, log, async () => undefined, new Set(), createHash);
  assert.equal(result.result, "valid");
  assert.equal(result.document!.verificationMethod![0].publicKeyMultibase, key1);
  assert.deepEqual(result.document!.service, []); // the update's own service isn't in the create-only state
  assert.equal(result.metadata!.versionId, createHash);
});

test("resolve with versionId=the log's own current (last) hash matches an ordinary resolve with no versionId at all", async () => {
  const { log, updateHash, key2 } = await buildLog();
  const withVersionId = await resolve(DID, log, async () => undefined, new Set(), updateHash);
  const withoutVersionId = await resolve(DID, log, async () => undefined);
  assert.equal(withVersionId.result, "valid");
  assert.deepEqual(withVersionId.document, withoutVersionId.document);
  assert.equal(withVersionId.document!.verificationMethod![0].publicKeyMultibase, key2);
});

test("resolve with a versionId naming a hash that isn't in the log at all is invalid, not a crash", async () => {
  const { log } = await buildLog();
  const result = await resolve(DID, log, async () => undefined, new Set(), "zNotARealOperationHash");
  assert.equal(result.result, "invalid");
  assert.match(result.reason ?? "", /REQ-9-5/);
});
