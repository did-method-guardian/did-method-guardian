// C-1 (audit): keystore.ts's own overwrite protection and label
// sanitization, in isolation -- never touching the real user's config
// directory (XDG_CONFIG_HOME is pointed at a throwaway temp dir before
// keystore.ts is ever imported, since configDir() reads it once per call
// rather than caching, so this is safe to set here).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

let tmpConfigDir: string;
const originalXdg = process.env.XDG_CONFIG_HOME;

before(() => {
  tmpConfigDir = mkdtempSync(path.join(tmpdir(), "guardian-cli-keystore-test-"));
  process.env.XDG_CONFIG_HOME = tmpConfigDir;
});

after(() => {
  if (originalXdg === undefined) delete process.env.XDG_CONFIG_HOME;
  else process.env.XDG_CONFIG_HOME = originalXdg;
  rmSync(tmpConfigDir, { recursive: true, force: true });
});

const { saveKey, loadKey, configDir } = await import("../src/keystore.js");

function fakeKey(tag: string) {
  return { publicKey: `pub-${tag}`, privateKey: `priv-${tag}` };
}

function keysDirEntries(): string[] {
  const keysDir = path.join(configDir(), "keys");
  return existsSync(keysDir) ? readdirSync(keysDir) : [];
}

test("saveKey refuses to overwrite an existing key without --force", async () => {
  await saveKey("alice", fakeKey("1"));
  await assert.rejects(() => saveKey("alice", fakeKey("2")), /already saved/);
  const stillOriginal = await loadKey("alice");
  assert.equal(stillOriginal.publicKey, "pub-1");
});

test("saveKey overwrites when --force is passed", async () => {
  await saveKey("bob", fakeKey("1"));
  await saveKey("bob", fakeKey("2"), { force: true });
  const loaded = await loadKey("bob");
  assert.equal(loaded.publicKey, "pub-2");
});

test("a label containing ':', '/' or '\\' is sanitized, never escapes the keys directory", async () => {
  await saveKey("did:guardian:evil.test:carol", fakeKey("3"));
  const entries = keysDirEntries();
  assert.ok(entries.some((f) => f.includes("evil.test")), "the sanitized file landed inside keysDir");
  assert.ok(!entries.some((f) => f.includes(":")), "no raw ':' survived into a filename");

  // A traversal attempt is neutralized (the '/' becomes '_'), not
  // honored -- it must land inside keysDir, never escape it.
  await assert.doesNotReject(() => saveKey("../../etc/passwd", fakeKey("4")));
  const afterTraversal = keysDirEntries();
  assert.ok(
    afterTraversal.includes(".._.._etc_passwd.json"),
    `expected a sanitized file inside keysDir, got: ${JSON.stringify(afterTraversal)}`,
  );
});

test("an empty, '.', or '..' label is rejected outright", async () => {
  await assert.rejects(() => saveKey("", fakeKey("5")));
  await assert.rejects(() => saveKey(".", fakeKey("6")));
  await assert.rejects(() => saveKey("..", fakeKey("7")));
});

test("loadKey reports a clear error for a label that was never saved", async () => {
  await assert.rejects(() => loadKey("never-saved-this-one"), /no local key named/);
});
