// REQ-10-8 (at most one accepted operation per prev): appendOperation must
// read a UNIQUE constraint violation on (did, prev) as "lost the race,"
// returning false rather than throwing, and any other D1 error must still
// propagate. Same minimal-fake-D1 pattern clientAuth.test.ts already uses
// for db.ts-adjacent logic.

import { test } from "node:test";
import assert from "node:assert/strict";
import { appendOperation, insertNameEntry } from "../src/db.js";
import type { Env } from "../src/env.js";
import type { CreateOp } from "@did-guardian/lib";

interface Capture {
  lastSql?: string;
  lastBind?: unknown[];
}

function fakeEnv(behavior: "ok" | "conflict" | "other-error", capture: Capture): Env {
  const db = {
    prepare(sql: string) {
      capture.lastSql = sql;
      return {
        bind(...args: unknown[]) {
          capture.lastBind = args;
          return {
            async run() {
              if (behavior === "conflict") throw new Error("D1_ERROR: UNIQUE constraint failed: logs.did, logs.prev");
              if (behavior === "other-error") throw new Error("D1_ERROR: some other failure");
              return { success: true, meta: { rows_written: 1 } } as any;
            },
          };
        },
      };
    },
  };
  return { DB: db } as unknown as Env;
}

const sampleOp: CreateOp = {
  type: "create",
  did: "did:guardian:example.com:alice",
  keys: ["zAlice"],
  guardians: [],
  successor: null,
  policy: {},
  services: [],
  alsoKnownAs: [],
  prev: null,
  proof: [],
};

test("appendOperation returns true on an ordinary successful insert", async () => {
  const capture: Capture = {};
  const ok = await appendOperation(fakeEnv("ok", capture), sampleOp.did, 0, "", sampleOp, "2026-01-01T00:00:00.000Z");
  assert.equal(ok, true);
});

test("appendOperation returns false (not a throw) when the (did, prev) slot was already taken -- the race case REQ-10-8 guards against", async () => {
  const capture: Capture = {};
  const ok = await appendOperation(fakeEnv("conflict", capture), sampleOp.did, 0, "", sampleOp, "2026-01-01T00:00:00.000Z");
  assert.equal(ok, false);
});

test("appendOperation still throws on a D1 error that isn't the unique-constraint race", async () => {
  const capture: Capture = {};
  await assert.rejects(() => appendOperation(fakeEnv("other-error", capture), sampleOp.did, 0, "", sampleOp, "2026-01-01T00:00:00.000Z"));
});

test("insertNameEntry returns false (not a throw) when the (domain, name) pair is already taken -- REQ-10-12's own race-free check", async () => {
  const capture: Capture = {};
  const ok = await insertNameEntry(fakeEnv("conflict", capture), "example.com", "alice", sampleOp.did, "2026-01-01T00:00:00.000Z");
  assert.equal(ok, false);
});
