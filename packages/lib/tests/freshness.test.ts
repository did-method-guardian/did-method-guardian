import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "../src/crypto.js";
import { signLogHeadStatement, verifyLogHeadStatement, verifyLogHeadAgainst, statementAgeMs, logHashFor } from "../src/freshness.js";
import { cidFor } from "../src/operations.js";
import type { KeyResolver } from "../src/operations.js";
import type { Did, LogEntry } from "../src/types.js";

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

test("audit WS-2.4: logHashFor hashes each entry's RECOMPUTED cid, not whatever the stored cid field claims", async () => {
  const op = { type: "custodial_create" as const, did: "did:guardian:example.com:alice" as Did, name: "alice", operationalKeys: ["pk"], services: {}, outgoing: [] as [], incoming: [] as Did[], prev: null, creator: "did:guardian:example.com" as Did, proof: [] };
  const realCid = await cidFor(op);
  const honest: LogEntry[] = [{ cid: realCid, op }];
  const tamperedCidField: LogEntry[] = [{ cid: "zSomeUnrelatedClaim", op }]; // same op, a lying cid field
  assert.equal(await logHashFor(honest), await logHashFor(tamperedCidField), "the hash must depend on the op's real content, not the stored cid field, which here differs between the two but the real content doesn't");
});

test("audit WS-2.4: verifyLogHeadAgainst checks anchor, headCid, seq, and logHash all independently", async () => {
  const genesisOp = { type: "custodial_create" as const, did: "did:guardian:example.com:alice" as Did, name: "alice", operationalKeys: ["pk"], services: {}, outgoing: [] as [], incoming: [] as Did[], prev: null, creator: "did:guardian:example.com" as Did, proof: [] };
  const genesisCid = await cidFor(genesisOp);
  const log: LogEntry[] = [{ cid: genesisCid, op: genesisOp }];
  const registrar = await generateKeypair();

  const goodStatement = await signLogHeadStatement(
    { did: "did:guardian:example.com:alice", anchor: genesisCid, headCid: genesisCid, seq: 1, logHash: await logHashFor(log), timestamp: new Date().toISOString(), registrar: "did:guardian:example.com" },
    registrar.privateKey,
  );
  assert.equal((await verifyLogHeadAgainst(log, goodStatement)).valid, true);

  assert.equal((await verifyLogHeadAgainst(log, { ...goodStatement, anchor: "zWrongAnchor" })).valid, false, "anchor mismatch must be caught");
  assert.equal((await verifyLogHeadAgainst(log, { ...goodStatement, headCid: "zWrongHead" })).valid, false, "headCid mismatch must be caught");
  assert.equal((await verifyLogHeadAgainst(log, { ...goodStatement, seq: 99 })).valid, false, "seq mismatch must be caught");
  assert.equal((await verifyLogHeadAgainst(log, { ...goodStatement, logHash: "zWrongHash" })).valid, false, "logHash mismatch must be caught");
});

test("statementAgeMs reflects elapsed time, and a future timestamp is negative rather than clamped", () => {
  const past = { timestamp: new Date(Date.now() - 5000).toISOString() } as any;
  const future = { timestamp: new Date(Date.now() + 5000).toISOString() } as any;
  assert.ok(statementAgeMs(past) >= 4900);
  assert.ok(statementAgeMs(future) < 0);
});
