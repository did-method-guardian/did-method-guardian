// REQ-5-17 (r7d, audit r4) regression: relaySign's own prev-vs-head
// check, factored out as matchesClaimedLog so it's testable without a
// live cross-registrar fetch (relaySign.ts only ever calls it with an
// already-fetched remote log).
import { test } from "node:test";
import assert from "node:assert/strict";
import { createProof, generateKeypair, operationHash, type Did, type Log } from "@did-guardian/lib";
import { matchesClaimedLog } from "../src/relaySign.js";

// A bare-domain root identity's own create needs no attestation
// (REQ-7-7 only requires one for a non-root identity), which keeps
// this fixture a genuinely *valid* log without a second signer.
async function rootLog(domain: string): Promise<{ did: Did; log: Log; head: string }> {
  const did = `did:guardian:${domain}` as Did;
  const keypair = await generateKeypair();
  const createOp = { type: "create" as const, did, keys: [keypair.publicKey], guardians: [], successor: null, policy: {}, services: [], alsoKnownAs: [], prev: null };
  const proof = await createProof(createOp, keypair.publicKey, keypair.privateKey);
  const log = [{ ...createOp, proof: [proof] }] as unknown as Log;
  return { did, log, head: await operationHash(log[0]) };
}

test("matchesClaimedLog: a create is exempt regardless of the log", async () => {
  const did = "did:guardian:guardianspec.org:relaytest1" as Did;
  assert.equal(await matchesClaimedLog(did, undefined, { type: "create", prev: null }), true);
});

test("matchesClaimedLog: an update whose prev matches the claimed DID's own current head matches", async () => {
  const { did, log, head } = await rootLog("relaytest2.test");
  assert.equal(await matchesClaimedLog(did, log, { type: "update", prev: head }), true);
});

test("matchesClaimedLog: an update whose prev is some OTHER identity's head (the relay-sign confused-deputy class) is refused", async () => {
  const mine = await rootLog("relaytest3.test");
  const other = await rootLog("relaytest-other.test");
  assert.equal(await matchesClaimedLog(mine.did, mine.log, { type: "update", prev: other.head }), false);
});

test("matchesClaimedLog: a log that couldn't be fetched at all is refused, not treated as exempt", async () => {
  const did = "did:guardian:guardianspec.org:relaytest4" as Did;
  assert.equal(await matchesClaimedLog(did, undefined, { type: "update", prev: "anything" }), false);
  assert.equal(await matchesClaimedLog(did, null, { type: "update", prev: "anything" }), false);
});
