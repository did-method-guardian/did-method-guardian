// R2-0.5 scoping (per thoward-59's review): submitOperation must only
// revoke sessions/login_secret when an `update` actually changes
// `keys` -- a services-only update must leave both alone. Tested here
// directly against submitOperation with a minimal, stateful fake D1
// (same convention as registrar.test.ts/db.test.ts's own fakeEnv), since
// no live route submits a same-keys update for a held identity to drive
// this through http-endpoints.test.ts's real wrangler-dev instance.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createProof, generateKeypair, operationHash, DEFAULT_POLICY } from "@did-guardian/lib";
import type { CreateOp, UpdateOp } from "@did-guardian/lib";
import { submitOperation } from "../src/registrar.js";
import type { Env } from "../src/env.js";

interface LogRow {
  did: string;
  seq: number;
  prev: string;
  operation: string;
  created_at: string;
}

function fakeEnv(seedLog: LogRow[]): Env & { sawSessionRevocation: boolean; sawLoginSecretInvalidation: boolean } {
  const state = { sawSessionRevocation: false, sawLoginSecretInvalidation: false };
  const logs = [...seedLog];

  const db = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          return {
            async all() {
              if (/SELECT operation FROM logs WHERE did = \?/.test(sql)) {
                const [did] = args as [string];
                return { results: logs.filter((r) => r.did === did).sort((a, b) => a.seq - b.seq) };
              }
              return { results: [] };
            },
            async first() {
              return null;
            },
            async run() {
              if (/INSERT INTO logs/.test(sql)) {
                const [did, seq, prev, operation, created_at] = args as [string, number, string, string, string];
                logs.push({ did, seq, prev, operation, created_at });
                return { success: true, meta: { rows_written: 1 } };
              }
              if (/DELETE FROM login_sessions/.test(sql)) {
                state.sawSessionRevocation = true;
                return { success: true, meta: { rows_written: 0 } };
              }
              if (/UPDATE held_keys SET login_secret_hash = NULL/.test(sql)) {
                state.sawLoginSecretInvalidation = true;
                return { success: true, meta: { rows_written: 0 } };
              }
              return { success: true, meta: { rows_written: 0 } };
            },
          };
        },
      };
    },
  };

  return {
    DB: db,
    REGISTRAR_DOMAIN: "example.com",
    get sawSessionRevocation() {
      return state.sawSessionRevocation;
    },
    get sawLoginSecretInvalidation() {
      return state.sawLoginSecretInvalidation;
    },
  } as unknown as Env & { sawSessionRevocation: boolean; sawLoginSecretInvalidation: boolean };
}

test("submitOperation: a services-only update (same keys) does NOT revoke sessions or the login_secret", async () => {
  const did = "did:guardian:example.com" as const; // root -- no attestation needed (REQ-7-7)
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
  const createProof1 = await createProof(createBase, key.publicKey, key.privateKey);
  const createOp: CreateOp = { ...createBase, proof: [createProof1] };

  const env = fakeEnv([{ did, seq: 0, prev: "", operation: JSON.stringify(createOp), created_at: new Date().toISOString() }]);

  const updateBase: Omit<UpdateOp, "proof"> = {
    type: "update",
    keys: [key.publicKey], // same key as before
    services: [{ id: "#agent", type: "AgentCard", serviceEndpoint: "https://example.com/agent" }],
    alsoKnownAs: [],
    prev: await operationHash(createOp),
  };
  const updateProof = await createProof(updateBase, key.publicKey, key.privateKey);
  const updateOp: UpdateOp = { ...updateBase, proof: [updateProof] };

  const result = await submitOperation(env, did, updateOp);
  assert.equal(result.type, "update");
  assert.equal(env.sawSessionRevocation, false, "a same-keys update must not revoke sessions");
  assert.equal(env.sawLoginSecretInvalidation, false, "a same-keys update must not invalidate the login_secret");
});

test("submitOperation: an update that DOES change keys revokes sessions and the login_secret", async () => {
  const did = "did:guardian:example.com" as const;
  const key1 = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did,
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

  const env = fakeEnv([{ did, seq: 0, prev: "", operation: JSON.stringify(createOp), created_at: new Date().toISOString() }]);

  const key2 = await generateKeypair();
  const updateBase: Omit<UpdateOp, "proof"> = {
    type: "update",
    keys: [key2.publicKey], // a genuinely new key
    services: [],
    alsoKnownAs: [],
    prev: await operationHash(createOp),
  };
  const newKeyProof = await createProof(updateBase, key2.publicKey, key2.privateKey);
  const oldKeyProof = await createProof(updateBase, key1.publicKey, key1.privateKey);
  const updateOp: UpdateOp = { ...updateBase, proof: [newKeyProof, oldKeyProof].sort((a, b) => (a.verificationMethod < b.verificationMethod ? -1 : 1)) };

  await submitOperation(env, did, updateOp);
  assert.equal(env.sawSessionRevocation, true, "a keys-changing update must revoke sessions");
  assert.equal(env.sawLoginSecretInvalidation, true, "a keys-changing update must invalidate the login_secret");
});
