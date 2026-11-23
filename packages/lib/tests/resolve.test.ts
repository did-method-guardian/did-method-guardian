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

// F-12 (audit): parseDid used to do only structural (segment-count)
// splitting, accepting anything in the domain/name positions as long
// as the colon count matched -- callers build request URLs and
// redirect targets straight from its output. It must reject the same
// malformed domain/name REQ-4-2/REQ-4-3 already reject elsewhere, not
// just hand back whatever characters were there.
test("parseDid: rejects a syntactically-plausible but invalid domain (REQ-4-2)", () => {
  assert.throws(() => parseDid("did:guardian:not a domain"));
  assert.throws(() => parseDid("did:guardian:evil.com/../escape"));
  assert.throws(() => parseDid("did:guardian:evil.com#fragment"));
});

test("parseDid: rejects a syntactically-plausible but invalid name (REQ-4-3)", () => {
  assert.throws(() => parseDid("did:guardian:acme.com:../../etc"));
  assert.throws(() => parseDid("did:guardian:acme.com:a b"));
  assert.throws(() => parseDid("did:guardian:acme.com:_"));
});

test("wellKnownPath: a real name resolves to its own path, null resolves to the reserved _ segment", () => {
  assert.equal(wellKnownPath("alice"), "/.well-known/guardian/alice");
  assert.equal(wellKnownPath(null), "/.well-known/guardian/_");
});
