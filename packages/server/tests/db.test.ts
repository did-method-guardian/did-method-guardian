// Regression test for WS-1.12 (audit): appendOperationIfCountMatches must
// bind the (did, prev_cid, expectedExistingCount) guard correctly and read
// the insert's actual rows_written back honestly, so a caller can tell a
// real insert apart from one the WHERE clause silently turned into a no-op
// (the race-closing mechanism this function exists for). Verified
// end-to-end against a real D1 (wrangler dev, scratch database, torn down
// afterward) separately -- see docs-internal/audit-2026-11-21/checklist.md,
// WS-1.12 -- this test pins down the query shape and the meta.rows_written
// contract in isolation, the same minimal-fake-D1 pattern clientAuth.test.ts
// already uses for db.ts-adjacent logic.

import { test } from "node:test";
import assert from "node:assert/strict";
import { appendOperationIfCountMatches } from "../src/db.js";
import type { OperationRow } from "../src/db.js";
import type { Env } from "../src/env.js";

interface Capture {
  lastSql?: string;
  lastBind?: unknown[];
}

function fakeEnv(rowsWritten: number, capture: Capture): Env {
  const db = {
    prepare(sql: string) {
      capture.lastSql = sql;
      return {
        bind(...args: unknown[]) {
          capture.lastBind = args;
          return {
            async run() {
              return { success: true, meta: { rows_written: rowsWritten } } as any;
            },
          };
        },
      };
    },
  };
  return { DB: db } as unknown as Env;
}

const sampleOp: OperationRow = {
  cid: "zCid1",
  did: "did:guardian:example.com:alice",
  prev_cid: "zCid0",
  op_type: "custodial_rotate",
  payload: "{}",
  created_at: "2026-01-01T00:00:00.000Z",
};

test("audit WS-1.12: appendOperationIfCountMatches returns true when the insert actually wrote a row", async () => {
  const capture: Capture = {};
  const inserted = await appendOperationIfCountMatches(fakeEnv(1, capture), sampleOp, 0);
  assert.equal(inserted, true);
});

test("audit WS-1.12: appendOperationIfCountMatches returns false when the WHERE clause matched nothing -- the race case, not an error", async () => {
  const capture: Capture = {};
  const inserted = await appendOperationIfCountMatches(fakeEnv(0, capture), sampleOp, 0);
  assert.equal(inserted, false);
});

test("audit WS-1.12: the guard binds did/prev_cid/expectedExistingCount in addition to the row's own values, in the order the SQL text expects them", async () => {
  const capture: Capture = {};
  await appendOperationIfCountMatches(fakeEnv(1, capture), sampleOp, 0);
  assert.match(capture.lastSql ?? "", /WHERE \(SELECT COUNT\(\*\) FROM operations WHERE did = \? AND prev_cid IS \?\) = \?/);
  assert.deepEqual(capture.lastBind, [sampleOp.cid, sampleOp.did, sampleOp.prev_cid, sampleOp.op_type, sampleOp.payload, sampleOp.created_at, sampleOp.did, sampleOp.prev_cid, 0]);
});

test("audit WS-1.12: a nullification's expected count (1) is passed through distinctly from an ordinary append's (0)", async () => {
  const capture: Capture = {};
  await appendOperationIfCountMatches(fakeEnv(1, capture), sampleOp, 1);
  assert.equal(capture.lastBind?.[capture.lastBind.length - 1], 1);
});
