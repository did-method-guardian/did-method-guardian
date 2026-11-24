// Small integration test against the real, live guardianspec.org registrar
// (the same one the published driver itself resolves against), plus a pure
// unit test for the one thing that actually matters about this driver: it
// never hands the Universal Resolver a document from a log that doesn't
// genuinely verify, even if the registrar that served it says otherwise.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createProof, generateKeypair, type Did, type Log, type LogResolver } from "@did-guardian/lib";
import { resolveDid } from "../src/resolveDriver.js";

test("resolveDriver: resolves the live guardianspec.org root identity", async () => {
  const { status, body } = await resolveDid("did:guardian:guardianspec.org");
  assert.equal(status, 200);
  assert.equal(body.didResolutionMetadata.error, undefined);
  assert.ok(body.didDocument, "a DID document is returned");
  assert.equal((body.didDocument as { id: string }).id, "did:guardian:guardianspec.org");
});

test("resolveDriver: resolves a freshly-registered test identity on guardianspec.org", async () => {
  const name = `uniresolvertest${Date.now().toString(36)}`;
  const registered = await fetch("https://guardianspec.org/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name }),
  });
  assert.equal(registered.status, 201);
  const { did } = (await registered.json()) as { did: string };

  const { status, body } = await resolveDid(did);
  assert.equal(status, 200);
  assert.equal((body.didDocument as { id: string }).id, did);
});

test("resolveDriver: a log whose create was tampered with after signing is refused, not just relayed", async () => {
  const did = "did:guardian:tampertest.example" as Did;
  const keypair = await generateKeypair();
  const createOp = { type: "create" as const, did, keys: [keypair.publicKey], guardians: [], successor: null, policy: {}, services: [], alsoKnownAs: [], prev: null };
  const proof = await createProof(createOp, keypair.publicKey, keypair.privateKey);

  // The log a lying or compromised registrar might serve: the signed
  // create, but with a different key swapped in after the proof was
  // produced -- the proof no longer secures this document, so a genuine
  // re-verification (not just "did it answer the request") must refuse it.
  const attacker = await generateKeypair();
  const tamperedLog = [{ ...createOp, keys: [attacker.publicKey], proof: [proof] }] as unknown as Log;

  const fetchTamperedLog: LogResolver = async () => tamperedLog;
  const { status, body } = await resolveDid(did, fetchTamperedLog);
  assert.notEqual(status, 200, "a tampered log must never resolve successfully");
  assert.equal(body.didDocument, null);
  assert.ok(body.didResolutionMetadata.error, "an error code must be reported");
});
