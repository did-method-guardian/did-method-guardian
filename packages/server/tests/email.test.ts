import { test } from "node:test";
import assert from "node:assert/strict";
import { handleEmail } from "../src/email.js";
import type { Env } from "../src/env.js";

function makeMockMessage(to: string) {
  const calls: { forwarded?: string; rejected?: string } = {};
  const message = {
    to,
    async forward(address: string) {
      calls.forwarded = address;
    },
    setReject(reason: string) {
      calls.rejected = reason;
    },
  };
  return { message: message as unknown as ForwardableEmailMessage, calls };
}

function makeMockEnv(overrides: Partial<{ ward: { name: string; did: string } | null; forwarding: { forward_to: string } | null }>): Env {
  // Minimal stand-in for D1 -- enough to exercise handleEmail's own branching
  // logic without standing up a real database for a unit test.
  const ward = overrides.ward;
  const forwarding = overrides.forwarding;
  return {
    REGISTRAR_DOMAIN: "guardianspec.org",
    KEY_ENCRYPTION_KEY: "unused",
    DB: {
      prepare(sql: string) {
        return {
          bind(..._args: unknown[]) {
            return this;
          },
          async first() {
            if (sql.includes("FROM wards WHERE name")) return ward ? { name: ward.name, did: ward.did } : null;
            if (sql.includes("FROM email_forwarding WHERE did") && sql.includes("verified = 1")) return forwarding ?? null;
            return null;
          },
        };
      },
    } as unknown as D1Database,
  };
}

test("handleEmail rejects mail for an unknown local part", async () => {
  const { message, calls } = makeMockMessage("nobody@guardianspec.org");
  const env = makeMockEnv({ ward: null });
  await handleEmail(message, env);
  assert.ok(calls.rejected?.includes("no such identity"), calls.rejected);
  assert.equal(calls.forwarded, undefined);
});

test("handleEmail rejects mail for a ward with no verified forwarding set up", async () => {
  const { message, calls } = makeMockMessage("carol@guardianspec.org");
  const env = makeMockEnv({ ward: { name: "carol", did: "did:guardian:carol:guardianspec:org" }, forwarding: null });
  await handleEmail(message, env);
  assert.ok(calls.rejected?.includes("not set up"), calls.rejected);
  assert.equal(calls.forwarded, undefined);
});

test("handleEmail forwards to the verified destination for a known, verified ward", async () => {
  const { message, calls } = makeMockMessage("carol@guardianspec.org");
  const env = makeMockEnv({
    ward: { name: "carol", did: "did:guardian:carol:guardianspec:org" },
    forwarding: { forward_to: "real-inbox@example.com" },
  });
  await handleEmail(message, env);
  assert.equal(calls.forwarded, "real-inbox@example.com");
  assert.equal(calls.rejected, undefined);
});
