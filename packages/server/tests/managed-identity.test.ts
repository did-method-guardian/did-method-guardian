// D3 (spec r7/r7b): registerManagedIdentity is the one path where a
// single request legitimately produces proofs for two identities (the
// consenting guardian and the brand-new ward it creates) -- per
// thoward-59's own review, that needs a direct test before any deploy,
// against a fake D1, the same convention registrar-session-scope.test.ts
// already uses for submitOperation itself.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { anchorOf, createProof, generateKeypair, keyOfVerificationMethod, operationHash, verifyLog, verifyProofSignature, type AcceptWardOp, type CreateOp, type Operation } from "@did-guardian/lib";
import { registerManagedIdentity, isGuardianHeldHere } from "../src/profile.js";
import { submitOperation } from "../src/registrar.js";
import { authenticatedViaAccessToken } from "../src/signing.js";
import { encryptSecret } from "../src/secretBox.js";
import { RegistrarError } from "../src/registrarError.js";
import type { Env } from "../src/env.js";

interface LogRow {
  did: string;
  seq: number;
  prev: string;
  operation: string;
  created_at: string;
}

interface HeldKeyRow {
  did: string;
  public_key: string;
  private_key_enc: string;
  login_secret_hash: string | null;
  created_at: string;
  must_change_password: number;
}

/**
 * A minimal, stateful fake D1 covering exactly the tables
 * registerManagedIdentity's own call graph touches: logs, held_keys,
 * names, pins -- including its own root-identity bootstrap
 * (ensureRootIdentity, reached through submitOperation on the new
 * ward's own create), since this fake makes no attempt to special-case
 * that away. Each instance is a fresh registrar with nothing in it --
 * callers seed a guardian into it directly before exercising the
 * function under test.
 */
function fakeEnv(): Env {
  const logs: LogRow[] = [];
  const heldKeys = new Map<string, HeldKeyRow>();
  const names = new Map<string, { domain: string; name: string; did: string; created_at: string }>();
  const pins = new Map<string, { did: string; anchor: string; version: string }>();

  const db = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          return {
            async run() {
              if (/INSERT INTO logs/.test(sql)) {
                const [did, seq, prev, operation, created_at] = args as [string, number, string, string, string];
                if (logs.some((r) => r.did === did && r.prev === prev)) throw new Error("UNIQUE constraint failed: logs.did, logs.prev");
                logs.push({ did, seq, prev, operation, created_at });
                return { success: true, meta: { rows_written: 1 } };
              }
              if (/INSERT INTO held_keys/.test(sql)) {
                const [did, public_key, private_key_enc, login_secret_hash, created_at] = args as [string, string, string, string | null, string];
                heldKeys.set(did, { did, public_key, private_key_enc, login_secret_hash, created_at, must_change_password: 0 });
                return { success: true, meta: { rows_written: 1 } };
              }
              if (/INSERT INTO names/.test(sql)) {
                const [domain, name, did, created_at] = args as [string, string, string, string];
                const key = `${domain}\u0000${name}`;
                if (names.has(key)) throw new Error("UNIQUE constraint failed: names.domain, names.name");
                names.set(key, { domain, name, did, created_at });
                return { success: true, meta: { rows_written: 1 } };
              }
              if (/INSERT INTO pins/.test(sql)) {
                const [did, anchor, version] = args as [string, string, string];
                pins.set(did, { did, anchor, version });
                return { success: true, meta: { rows_written: 1 } };
              }
              if (/DELETE FROM names WHERE domain = \? AND name = \?/.test(sql)) {
                const [domain, name] = args as [string, string];
                names.delete(`${domain}\u0000${name}`);
                return { success: true, meta: { rows_written: 1 } };
              }
              return { success: true, meta: { rows_written: 0 } };
            },
            async first() {
              if (/SELECT \* FROM held_keys WHERE did = \?/.test(sql)) return heldKeys.get(args[0] as string) ?? null;
              if (/SELECT \* FROM names WHERE domain = \? AND name = \?/.test(sql)) {
                const [domain, name] = args as [string, string];
                return names.get(`${domain}\u0000${name}`) ?? null;
              }
              if (/SELECT \* FROM pins WHERE did = \?/.test(sql)) return pins.get(args[0] as string) ?? null;
              return null;
            },
            async all() {
              if (/SELECT operation FROM logs WHERE did = \?/.test(sql)) {
                const [did] = args as [string];
                return {
                  results: logs
                    .filter((r) => r.did === did)
                    .sort((a, b) => a.seq - b.seq)
                    .map((r) => ({ operation: r.operation })),
                };
              }
              return { results: [] };
            },
          };
        },
      };
    },
  };

  return {
    DB: db,
    REGISTRAR_DOMAIN: "example.com",
    KEY_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
  } as unknown as Env;
}

/** Fetches and parses a DID's full log directly from the fake DB, bypassing getLog (which needs a real Env type, not this test's structurally-compatible stand-in). */
async function readLog(env: Env, did: string): Promise<Operation[]> {
  const rows = await env.DB.prepare("SELECT operation FROM logs WHERE did = ?").bind(did).all<{ operation: string }>();
  return rows.results.map((r) => JSON.parse(r.operation) as Operation);
}

/**
 * Seeds a held, self-created identity -- through submitOperation
 * itself (same as registerIdentity's own real path), not a direct DB
 * insert, so this create picks up a genuine REQ-10-9 attestation
 * (bootstrapping this fake registrar's own root identity along the
 * way, the same as it would for any first create). The held key's own
 * row is inserted directly afterward, with a REAL encrypted private
 * key (signAs's own decryptSecret call needs that to be real).
 */
async function seedHeldIdentity(env: Env, did: string): Promise<{ publicKey: string; privateKey: string }> {
  const keypair = await generateKeypair();
  const createBase = {
    type: "create" as const,
    did,
    keys: [keypair.publicKey],
    guardians: [],
    successor: null,
    policy: {},
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const proof = await createProof(createBase, keypair.publicKey, keypair.privateKey);
  await submitOperation(env, did as `did:guardian:${string}`, { ...createBase, proof: [proof] });
  const encrypted = await encryptSecret(keypair.privateKey, (env as unknown as { KEY_ENCRYPTION_KEY: string }).KEY_ENCRYPTION_KEY);
  await env.DB.prepare("INSERT INTO held_keys (did, public_key, private_key_enc, login_secret_hash, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(did, keypair.publicKey, encrypted, null, new Date().toISOString())
    .run();
  return keypair;
}

test("registerManagedIdentity: the guardian's log gains exactly one acceptWard, and the new identity's create names it with two valid co-signatures", async () => {
  const env = fakeEnv();
  const guardianDid = "did:guardian:example.com:priya";
  await seedHeldIdentity(env, guardianDid);
  assert.equal(await isGuardianHeldHere(env, guardianDid), true);

  const result = await registerManagedIdentity(env, "bot7", authenticatedViaAccessToken(guardianDid), {});
  assert.equal(result.did, "did:guardian:example.com:bot7");
  assert.ok(result.loginSecret);

  const guardianLog = await readLog(env, guardianDid);
  assert.equal(guardianLog.length, 2, "create + exactly one acceptWard, no more");
  assert.equal(guardianLog[1].type, "acceptWard");
  assert.equal((guardianLog[1] as AcceptWardOp).ward.did, result.did);

  const wardLog = await readLog(env, result.did);
  assert.equal(wardLog.length, 1);
  const wardCreate = wardLog[0] as CreateOp;
  assert.equal(wardCreate.guardians.length, 1);
  assert.equal(wardCreate.guardians[0].did, guardianDid);
  assert.equal(wardCreate.proof.length, 2, "the ward's own new key, and the guardian's held key");
  assert.ok(wardCreate.attestation, "submitOperation's own REQ-10-9 step still added the root's attestation, same as any other create");

  // Full §8 verification, including the attestation it just asserted exists.
  const verified = await verifyLog(result.did as `did:guardian:${string}`, wardLog);
  assert.equal(verified.result, "valid", verified.reason);

  for (const proof of wardCreate.proof) {
    const key = keyOfVerificationMethod(proof.verificationMethod)!;
    assert.ok(await verifyProofSignature(wardCreate, proof, key), `proof from ${key} verifies`);
  }
  const guardianKeyUsed = wardCreate.guardians[0].keys[0];
  assert.ok(
    wardCreate.proof.some((p) => keyOfVerificationMethod(p.verificationMethod) === guardianKeyUsed),
    "one of the two proofs is genuinely from the guardian's own current key, not just two copies of the ward's",
  );
});

test("isGuardianHeldHere: false for an identity this registrar never held a key for, and registerManagedIdentity fails closed rather than silently producing a guardian proof for it", async () => {
  const env = fakeEnv();
  const unknownGuardian = "did:guardian:elsewhere.example:priya";
  assert.equal(await isGuardianHeldHere(env, unknownGuardian), false);

  await assert.rejects(
    () => registerManagedIdentity(env, "bot7", authenticatedViaAccessToken(unknownGuardian), {}),
    (e: unknown) => e instanceof RegistrarError && /no such guardian identity/.test(e.message),
  );
  // Nothing was written anywhere -- no guardian proof, no half-created ward.
  assert.equal((await readLog(env, "did:guardian:example.com:bot7")).length, 0);
});

test("isGuardianHeldHere: false, and a clean failure, for a guardian that genuinely exists but isn't held by THIS registrar (the federated case index.ts falls back on)", async () => {
  const env = fakeEnv();
  // A guardian whose own log this registrar happens to serve (so
  // getLog finds it) but with no held_keys row -- e.g. a ward this
  // registrar hosts that took custody of its own key. signAs must
  // still refuse to sign as it.
  const guardianDid = "did:guardian:example.com:selfcustodied" as const;
  const keypair = await generateKeypair();
  const createBase = { type: "create" as const, did: guardianDid, keys: [keypair.publicKey], guardians: [], successor: null, policy: {}, services: [], alsoKnownAs: [], prev: null };
  const proof = await createProof(createBase, keypair.publicKey, keypair.privateKey);
  await submitOperation(env, guardianDid, { ...createBase, proof: [proof] });
  // Deliberately no held_keys row inserted -- this identity's own key
  // was never registrar-held to begin with (took custody at birth).

  assert.equal(await isGuardianHeldHere(env, guardianDid), false);
  await assert.rejects(
    () => registerManagedIdentity(env, "bot7", authenticatedViaAccessToken(guardianDid), {}),
    (e: unknown) => e instanceof RegistrarError && /does not hold a key/.test(e.message),
  );
  assert.equal((await readLog(env, guardianDid)).length, 1, "no acceptWard was added -- failed before producing any guardian proof");
});

test("registerManagedIdentity: a name collision after the guardian's own acceptWard already succeeded releases the stale ward record, so a retry of the same name does not get stuck", async () => {
  const env = fakeEnv();
  const guardianDid = "did:guardian:example.com:priya";
  const wardDid = "did:guardian:example.com:bot7";
  await seedHeldIdentity(env, guardianDid);

  // Occupy the name "bot7" out from under the retry, the same way a
  // genuine REQ-10-12 collision would -- directly in the fake names
  // table, bypassing registerManagedIdentity so THIS first attempt
  // fails at the create step specifically, after its own acceptWard
  // has already landed on the guardian's log.
  await env.DB.prepare("INSERT INTO names (domain, name, did, created_at) VALUES (?, ?, ?, ?)")
    .bind("example.com", "bot7", "did:guardian:example.com:someone-else", new Date().toISOString())
    .run();

  await assert.rejects(() => registerManagedIdentity(env, "bot7", authenticatedViaAccessToken(guardianDid), {}), /REQ-10-12/);

  const afterFirst = await verifyLog(guardianDid as `did:guardian:${string}`, await readLog(env, guardianDid));
  assert.equal(afterFirst.state!.wards.length, 1, "the first attempt's own acceptWard did land, even though the create it was for never could");
  assert.equal(afterFirst.state!.wards[0].did, wardDid);

  // The name frees up (the operator picks a different name for the
  // identity that was actually occupying it, say) -- a retry of the
  // SAME name "bot7" must now succeed, not get stuck behind the stale
  // acceptWard the first attempt left on the guardian's own log.
  await env.DB.prepare("DELETE FROM names WHERE domain = ? AND name = ?").bind("example.com", "bot7").run();

  const retryResult = await registerManagedIdentity(env, "bot7", authenticatedViaAccessToken(guardianDid), {});
  assert.equal(retryResult.did, wardDid);

  const afterRetry = await verifyLog(guardianDid as `did:guardian:${string}`, await readLog(env, guardianDid));
  assert.equal(afterRetry.result, "valid", afterRetry.reason);
  assert.equal(afterRetry.state!.wards.filter((w) => w.did === wardDid).length, 1, "exactly one live ward record for this DID after the retry -- the stale one was released, not left duplicated");

  const wardLog = await readLog(env, wardDid);
  assert.equal(wardLog.length, 1, "the retry's own create landed");
  assert.equal((wardLog[0] as CreateOp).guardians[0].did, guardianDid);
});

test("registerManagedIdentity: a guardian that genuinely guards an existing identity at that DID never has that guardianship released -- the attempt fails on the name collision instead, and the guardian's own wards record is untouched", async () => {
  const env = fakeEnv();
  const guardianDid = "did:guardian:example.com:priya";
  const wardDid = "did:guardian:example.com:bot7";
  const guardianKeypair = await seedHeldIdentity(env, guardianDid);

  // bot7 is a REAL, already-created identity -- not a stale, never-
  // created record left behind by a failed attempt. It doesn't need
  // to be held by this registrar; only its own log needs to be real.
  const wardKeypair = await generateKeypair();
  const wardCreateBase = {
    type: "create" as const,
    did: wardDid,
    keys: [wardKeypair.publicKey],
    guardians: [],
    successor: null,
    policy: {},
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const wardProof = await createProof(wardCreateBase, wardKeypair.publicKey, wardKeypair.privateKey);
  await submitOperation(env, wardDid, { ...wardCreateBase, proof: [wardProof] });
  const wardAnchor = await anchorOf(wardCreateBase as unknown as CreateOp);

  // The guardian genuinely accepts this real ward -- an ordinary,
  // correct acceptWard, anchor and all, matching how guardian.ts's own
  // addFirstGuardian builds one.
  const acceptBase = { type: "acceptWard" as const, ward: { did: wardDid, anchor: wardAnchor }, prev: await operationHash((await readLog(env, guardianDid)).at(-1)!) };
  const acceptProof = await createProof(acceptBase, guardianKeypair.publicKey, guardianKeypair.privateKey);
  await submitOperation(env, guardianDid, { ...acceptBase, proof: [acceptProof] });

  const beforeAttempt = await verifyLog(guardianDid as `did:guardian:${string}`, await readLog(env, guardianDid));
  assert.equal(beforeAttempt.state!.wards.length, 1);
  assert.deepEqual(beforeAttempt.state!.wards[0], { did: wardDid, anchor: wardAnchor });
  const guardianLogLengthBefore = (await readLog(env, guardianDid)).length;

  await assert.rejects(() => registerManagedIdentity(env, "bot7", authenticatedViaAccessToken(guardianDid), {}), (e: unknown) => e instanceof RegistrarError && /already exists/.test(e.message));

  const afterAttempt = await verifyLog(guardianDid as `did:guardian:${string}`, await readLog(env, guardianDid));
  assert.equal((await readLog(env, guardianDid)).length, guardianLogLengthBefore, "no releaseWard (or anything else) was ever added to the guardian's own log");
  assert.equal(afterAttempt.state!.wards.length, 1, "the real guardianship still stands, untouched");
  assert.deepEqual(afterAttempt.state!.wards[0], { did: wardDid, anchor: wardAnchor }, "same record, same anchor -- not released and not replaced");
});
