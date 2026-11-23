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

const { saveSession, requireSessionFor } = await import("../src/state.js");

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
