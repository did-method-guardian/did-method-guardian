// Model-based coverage for pendingOpMachine.ts, via xstate/graph's own path
// generation (replacing the deprecated standalone @xstate/test package) --
// every path getSimplePaths finds is replayed against a REAL actor here, so
// this both generates the test cases and proves the machine actually
// behaves the way each path claims.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createActor } from "xstate";
import { getSimplePaths } from "xstate/graph";
import { pendingOperationMachine } from "../src/pendingOpMachine.js";
import type { PendingOpEvent } from "../src/pendingOpMachine.js";

const EVENT_CASES: PendingOpEvent[] = [
  { type: "CONTRIBUTE", did: "did:guardian:g1:example.com", sig: "s1", satisfiedNow: false },
  { type: "CONTRIBUTE", did: "did:guardian:g2:example.com", sig: "s2", satisfiedNow: true },
  { type: "DECLINE" },
  { type: "EXPIRE" },
  { type: "FINALIZED" },
  { type: "FINALIZE_FAILED" },
];

function pathsFrom(satisfiedAtPropose: boolean) {
  return getSimplePaths(pendingOperationMachine, {
    input: { collectedSigs: {}, satisfiedAtPropose },
    events: EVENT_CASES,
  });
}

test("every simple path from a not-yet-satisfied proposal replays correctly against a real actor", () => {
  const paths = pathsFrom(false);
  assert.ok(paths.length > 0, "expected at least one path");
  for (const path of paths) {
    const actor = createActor(pendingOperationMachine, { input: { collectedSigs: {}, satisfiedAtPropose: false } }).start();
    for (const step of path.steps) {
      actor.send(step.event);
      assert.equal(
        actor.getSnapshot().value,
        step.state.value,
        `after ${JSON.stringify(step.event)}, expected ${JSON.stringify(step.state.value)}`,
      );
    }
    assert.equal(actor.getSnapshot().value, path.state.value);
  }
});

test("every simple path from an already-satisfied proposal replays correctly, starting past collecting", () => {
  const paths = pathsFrom(true);
  assert.ok(paths.length > 0, "expected at least one path");
  for (const path of paths) {
    const actor = createActor(pendingOperationMachine, { input: { collectedSigs: {}, satisfiedAtPropose: true } }).start();
    assert.equal(actor.getSnapshot().value, "satisfied", "a proposal satisfied at propose time must skip collecting entirely");
    for (const step of path.steps) {
      actor.send(step.event);
      assert.equal(actor.getSnapshot().value, step.state.value);
    }
  }
});

test("the full reachable state set, from a not-yet-satisfied proposal, is exactly the five documented states", () => {
  const paths = pathsFrom(false);
  const reached = new Set(paths.map((p) => p.state.value));
  reached.add("collecting"); // getSimplePaths's own target set starts after the transient `proposed` micro-state, but the 0-step path (collecting itself) is always one of the returned paths
  assert.deepEqual(
    [...reached].sort(),
    ["collecting", "declined", "expired", "finalized", "satisfied"].sort(),
  );
});

test("CONTRIBUTE always merges the new signature into context, whichever branch it takes", () => {
  const actor = createActor(pendingOperationMachine, { input: { collectedSigs: {}, satisfiedAtPropose: false } }).start();
  actor.send({ type: "CONTRIBUTE", did: "did:guardian:g1:example.com", sig: "s1", satisfiedNow: false });
  assert.deepEqual(actor.getSnapshot().context.collectedSigs, { "did:guardian:g1:example.com": "s1" });
  actor.send({ type: "CONTRIBUTE", did: "did:guardian:g2:example.com", sig: "s2", satisfiedNow: true });
  assert.deepEqual(actor.getSnapshot().context.collectedSigs, {
    "did:guardian:g1:example.com": "s1",
    "did:guardian:g2:example.com": "s2",
  });
  assert.equal(actor.getSnapshot().value, "satisfied");
});

test("FINALIZE_FAILED keeps a satisfied proposal retriable rather than dead-ending it", () => {
  const actor = createActor(pendingOperationMachine, { input: { collectedSigs: {}, satisfiedAtPropose: true } }).start();
  assert.equal(actor.getSnapshot().value, "satisfied");
  actor.send({ type: "FINALIZE_FAILED" });
  assert.equal(actor.getSnapshot().value, "satisfied");
  actor.send({ type: "FINALIZED" });
  assert.equal(actor.getSnapshot().value, "finalized");
});

test("machine.resolveState reconstructs a valid, resumable snapshot from plain {value, context} alone -- the shape pendingOps.ts persists to D1", () => {
  const resolved = pendingOperationMachine.resolveState({
    value: "collecting",
    context: { collectedSigs: { "did:guardian:g1:example.com": "s1" }, satisfiedAtPropose: false },
  });
  // `input` is only consulted when no snapshot is given, but XState's own types require it be passed regardless.
  const actor = createActor(pendingOperationMachine, { snapshot: resolved, input: resolved.context }).start();
  assert.equal(actor.getSnapshot().value, "collecting");
  actor.send({ type: "CONTRIBUTE", did: "did:guardian:g2:example.com", sig: "s2", satisfiedNow: true });
  assert.equal(actor.getSnapshot().value, "satisfied");
});
