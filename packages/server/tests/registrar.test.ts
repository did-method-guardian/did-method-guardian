import { test } from "node:test";
import assert from "node:assert/strict";
import { callerMayAutoSignAsGuardian } from "../src/registrar.js";

// Audit WS-1.11: an admin console (or any other future caller of
// registerWard) must never be able to establish some OTHER account as
// a new ward's guardian just by naming it in a request, even when this
// registrar happens to hold that other account's key -- that's not the
// named guardian's own consent. Verified end-to-end live-but-local
// (see docs-internal/audit-2026-11-21/checklist.md, WS-1.11): an admin
// naming a different registrar-held account goes through the pending,
// guardian-signs-it-themselves flow; naming the admin's own DID stays
// synchronous. These tests pin down the one boolean that decision
// actually turns on, so it can't be silently loosened later.

test("audit WS-1.11: the caller naming itself may auto-sign", () => {
  const did = "did:guardian:example.com";
  assert.equal(callerMayAutoSignAsGuardian(did, did), true);
});

test("audit WS-1.11: the caller naming a DIFFERENT account, even one this registrar custodies, may never auto-sign on that account's behalf", () => {
  assert.equal(callerMayAutoSignAsGuardian("did:guardian:example.com:other-ward", "did:guardian:example.com"), false);
});

test("audit WS-1.11: no caller identity at all (e.g. the Managed Identity API with no bearer token) never auto-signs", () => {
  assert.equal(callerMayAutoSignAsGuardian("did:guardian:example.com:guardian", null), false);
  assert.equal(callerMayAutoSignAsGuardian("did:guardian:example.com:guardian", undefined), false);
});
