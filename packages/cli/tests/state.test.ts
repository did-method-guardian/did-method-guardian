// C-2 (audit, HIGH): requireSessionFor refuses to hand back a session
// whose cookie would be sent to a different registrar than it was
// actually issued by -- isolated to a throwaway XDG_CONFIG_HOME, same
// convention as keystore.test.ts.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import type { Did } from "@did-guardian/lib";

let tmpConfigDir: string;
const originalXdg = process.env.XDG_CONFIG_HOME;

before(() => {
  tmpConfigDir = mkdtempSync(path.join(tmpdir(), "guardian-cli-state-test-"));
  process.env.XDG_CONFIG_HOME = tmpConfigDir;
});

after(() => {
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME;
  else process.env.XDG_CONFIG_HOME = originalXdg;
  rmSync(tmpConfigDir, { recursive: true, force: true });
});

const { saveSession, requireSessionFor, filePinStore } = await import("../src/state.js");

test("requireSessionFor returns the session when its registrar matches the DID's own domain", () => {
  saveSession("did:guardian:good.test:alice" as Did, "good.test", "cookie-value");
  const session = requireSessionFor("did:guardian:good.test:alice" as Did);
  assert.equal(session.registrar, "good.test");
  assert.equal(session.cookie, "cookie-value");
});

test("requireSessionFor refuses to hand back a session for a DID on a different registrar", () => {
  saveSession("did:guardian:good.test:alice" as Did, "good.test", "cookie-value");
  assert.throws(() => requireSessionFor("did:guardian:evil.test:victim" as Did), /refusing to send your session cookie to evil\.test/);
});

// #5/#6 (audit, REQ-11-3/11-4): filePinStore is the CLI's own PinStore
// adapter for the lib's checkPin -- just get/set over the local
// anchors.json file, verified here so the lib's own (already
// thoroughly tested) checkPin logic has a real store to run against
// end to end, not only an in-memory one.
test("filePinStore: get returns undefined before anything is set, then the record after set", async () => {
  const store = filePinStore();
  const did = "did:guardian:good.test:dora" as Did;
  assert.equal(await store.get(did), undefined);
  await store.set(did, { anchor: "zAnchor1", version: "zVersion1" });
  const got = await store.get(did);
  assert.equal(got?.anchor, "zAnchor1");
  assert.equal(got?.version, "zVersion1");
});

test("filePinStore: set overwrites the previous record for the same DID", async () => {
  const store = filePinStore();
  const did = "did:guardian:good.test:erin" as Did;
  await store.set(did, { anchor: "zAnchor1", version: "zVersion1" });
  await store.set(did, { anchor: "zAnchor1", version: "zVersion2" });
  const got = await store.get(did);
  assert.equal(got?.version, "zVersion2");
});
