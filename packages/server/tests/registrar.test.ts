import { test } from "node:test";
import assert from "node:assert/strict";
import { didForSegment, getResourceDocument, getResourceLog, segmentFor } from "../src/registrar.js";
import type { Env } from "../src/env.js";
import type { Did } from "@did-guardian/lib";

function envFor(domain: string): Env {
  return { REGISTRAR_DOMAIN: domain } as unknown as Env;
}

test("didForSegment/segmentFor: '_' is the root identity's own path segment (REQ-4-5)", () => {
  const env = envFor("example.com");
  assert.equal(didForSegment(env, "_"), "did:guardian:example.com");
  assert.equal(segmentFor("did:guardian:example.com" as Did, env), "_");
});

test("didForSegment/segmentFor: an ordinary name round-trips", () => {
  const env = envFor("example.com");
  assert.equal(didForSegment(env, "alice"), "did:guardian:example.com:alice");
  assert.equal(segmentFor("did:guardian:example.com:alice" as Did, env), "alice");
});

test("segmentFor: a DID on a different domain is not this registrar's own resource", () => {
  const env = envFor("example.com");
  assert.equal(segmentFor("did:guardian:other.example:alice" as Did, env), undefined);
});

// REQ-10-2: a GET request must not change any state. getResourceLog and
// getResourceDocument must never run anything but a plain read -- pinning
// this down the same way the pre-reset suite pinned down findWard(env,
// null) never provisioning a keypair on a GET.
test("REQ-10-2: getResourceLog never writes, even for an identity with no log yet", async () => {
  const db = {
    prepare(sql: string) {
      if (/^\s*INSERT|^\s*UPDATE|^\s*DELETE/i.test(sql)) throw new Error(`getResourceLog must never write -- it ran: ${sql}`);
      return {
        bind(..._args: unknown[]) {
          return { async all() { return { results: [] }; } };
        },
      };
    },
  };
  const env = { DB: db, REGISTRAR_DOMAIN: "example.com" } as unknown as Env;
  const result = await getResourceLog(env, "nobody");
  assert.equal(result, undefined);
});

test("REQ-10-2: getResourceDocument never writes, even for an identity with no log yet", async () => {
  const db = {
    prepare(sql: string) {
      if (/^\s*INSERT|^\s*UPDATE|^\s*DELETE/i.test(sql)) throw new Error(`getResourceDocument must never write -- it ran: ${sql}`);
      return {
        bind(..._args: unknown[]) {
          return { async all() { return { results: [] }; } };
        },
      };
    },
  };
  const env = { DB: db, REGISTRAR_DOMAIN: "example.com" } as unknown as Env;
  const result = await getResourceDocument(env, "nobody");
  assert.equal(result, undefined);
});
