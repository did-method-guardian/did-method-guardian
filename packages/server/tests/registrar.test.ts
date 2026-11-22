import { test } from "node:test";
import assert from "node:assert/strict";
import { callerMayAutoSignAsGuardian, findWard, adoptWard, RegistrarError } from "../src/registrar.js";
import type { Env } from "../src/env.js";
import type { Did } from "@did-guardian/lib";

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

test("audit WS-1.15: findWard(env, null) (the bare-domain root identity) never writes -- a GET must stay safe, never silently provisioning a keypair and a genesis entry", async () => {
  let prepareCalls = 0;
  const db = {
    prepare(sql: string) {
      prepareCalls++;
      if (/^\s*INSERT/i.test(sql)) throw new Error(`findWard must never INSERT -- it ran: ${sql}`);
      return {
        bind(..._args: unknown[]) {
          return { async first() { return null; } };
        },
      };
    },
  };
  const env = { DB: db } as unknown as Env;
  const result = await findWard(env, null);
  assert.equal(result, null, "an unprovisioned root identity must resolve to null, not be silently created");
  assert.ok(prepareCalls > 0, "sanity: findWard did query something");
});

// R2-0.1 (round-2 audit, docs-internal/audit-2026-11-21/round2.md): adoptWard
// used to sign a guardian_add with the TARGET ward's own stored key on the
// strength of the INCOMING guardian's session alone -- the ward (root
// included, and both live roots had no guardian at all) never consented.
// Reproduced live-but-local in docs-internal/audit-2026-11-21/reaudit-server/
// p7_adopt_root.mjs: register, adopt the root, take custody of the
// attacker's own key, then a guardian-signed rotate of the root succeeded.
// The route-level fix (index.ts) now requires a session/trusted-client AS
// THE WARD, same as /relinquish and /remove; this test pins down the one
// guard adoptWard keeps for itself regardless of what the route checks --
// the root can never be adopted through this function at all, full stop.
test("audit R2-0.1: adoptWard refuses to adopt the bare-domain root identity, before touching the DB at all", async () => {
  const env = {
    DB: {
      prepare() {
        throw new Error("adoptWard must reject the root before running any query");
      },
    },
  } as unknown as Env;
  await assert.rejects(
    () => adoptWard(env, "", "did:guardian:example.com:someone" as Did),
    (e: unknown) => e instanceof RegistrarError && e.status === 400,
  );
});
