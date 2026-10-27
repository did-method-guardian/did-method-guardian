import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDid, wellKnownPath } from "../src/resolve.js";

test("parseDid: named identity splits on the single colon, domain first", () => {
  assert.deepEqual(parseDid("did:guardian:acme.com:alice"), { name: "alice", domain: "acme.com" });
});

test("parseDid: bare domain (no colon) has no name", () => {
  assert.deepEqual(parseDid("did:guardian:acme.com"), { name: null, domain: "acme.com" });
});

test("parseDid: a subdomain name never collides with a bare subdomain identity -- the dot/colon split disambiguates both ways", () => {
  assert.deepEqual(parseDid("did:guardian:example.com:www"), { name: "www", domain: "example.com" });
  assert.deepEqual(parseDid("did:guardian:www.example.com"), { name: null, domain: "www.example.com" });
});

test("parseDid: rejects malformed identifiers", () => {
  assert.throws(() => parseDid("did:web:acme.com"));
  assert.throws(() => parseDid("did:guardian:"));
  assert.throws(() => parseDid("did:guardian:a:b:c"));
});

test("wellKnownPath: a real name resolves to its own path, null resolves to the reserved _ segment", () => {
  assert.equal(wellKnownPath("alice"), "/.well-known/guardian/alice");
  assert.equal(wellKnownPath(null), "/.well-known/guardian/_");
});
