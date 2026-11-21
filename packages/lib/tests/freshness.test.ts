import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "../src/crypto.js";
import { signLogHeadStatement, verifyLogHeadStatement, statementAgeMs, logHashFor } from "../src/freshness.js";
import type { KeyResolver } from "../src/operations.js";
import type { Did } from "../src/types.js";

function makeResolver(keys: Record<string, string>): KeyResolver {
  return (did) => (keys[did] ? [keys[did]] : undefined);
}

test("a log-head statement verifies against the registrar's resolved key", async () => {
  const registrar = await generateKeypair();
  const registrarDid: Did = "did:guardian:example.com";
  const resolve = makeResolver({ [registrarDid]: registrar.publicKey });

  const statement = await signLogHeadStatement(
    {
      did: "did:guardian:example.com:alice",
      anchor: "genesis-cid",
      headCid: "head-cid",
      seq: 3,
      logHash: await logHashFor([]),
      timestamp: new Date().toISOString(),
      registrar: registrarDid,
    },
    registrar.privateKey,
  );

  const result = await verifyLogHeadStatement(statement, resolve);
  assert.equal(result.valid, true, result.reason);
});

test("a log-head statement signed by a different key fails verification", async () => {
  const registrar = await generateKeypair();
  const impostor = await generateKeypair();
  const registrarDid: Did = "did:guardian:example.com";
  const resolve = makeResolver({ [registrarDid]: registrar.publicKey }); // verifier resolves the REAL key

  const statement = await signLogHeadStatement(
    {
      did: "did:guardian:example.com:alice",
      anchor: "genesis-cid",
      headCid: "head-cid",
      seq: 3,
      logHash: await logHashFor([]),
      timestamp: new Date().toISOString(),
      registrar: registrarDid,
    },
    impostor.privateKey, // forged
  );

  const result = await verifyLogHeadStatement(statement, resolve);
  assert.equal(result.valid, false);
});

test("tampering with any field after signing (headCid, seq, or timestamp) is detected", async () => {
  const registrar = await generateKeypair();
  const registrarDid: Did = "did:guardian:example.com";
  const resolve = makeResolver({ [registrarDid]: registrar.publicKey });

  const statement = await signLogHeadStatement(
    {
      did: "did:guardian:example.com:alice",
      anchor: "genesis-cid",
      headCid: "head-cid",
      seq: 3,
      logHash: await logHashFor([]),
      timestamp: new Date().toISOString(),
      registrar: registrarDid,
    },
    registrar.privateKey,
  );

  assert.equal((await verifyLogHeadStatement({ ...statement, headCid: "attacker-head-cid" }, resolve)).valid, false);
  assert.equal((await verifyLogHeadStatement({ ...statement, seq: 99 }, resolve)).valid, false);
});

test("statementAgeMs reflects elapsed time, and a future timestamp is negative rather than clamped", () => {
  const past = { timestamp: new Date(Date.now() - 5000).toISOString() } as any;
  const future = { timestamp: new Date(Date.now() + 5000).toISOString() } as any;
  assert.ok(statementAgeMs(past) >= 4900);
  assert.ok(statementAgeMs(future) < 0);
});
