// End-to-end tests for registrar-client.ts (the shared logic every CLI
// command routes through) against a real, local packages/server
// wrangler dev instance with its own scratch D1 -- never a live
// registrar. Rewrites any https://guardianspec.org/... fetch to
// http://localhost:<port>/..., since registrar-client.ts always talks
// to a real domain over HTTPS and has no "local testing" mode of its
// own (nor should it -- that's this test's own concern, not
// production code's).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { createProof, generateKeypair, operationHash, verifyLog, resolve, checkMutuality } from "@did-guardian/lib";
import type { Did, UpdateOp } from "@did-guardian/lib";

const PORT = 19799 + Math.floor(Math.random() * 1000);
const DOMAIN = "guardianspec.org";
const SERVER_DIR = path.resolve(import.meta.dirname, "..", "..", "..", "server");
let persistDir: string;
let devProcess: ChildProcessWithoutNullStreams;

const realFetch = globalThis.fetch;
globalThis.fetch = ((url: string | URL, init?: RequestInit) => {
  const rewritten = typeof url === "string" ? url.replace(`https://${DOMAIN}`, `http://localhost:${PORT}`) : url;
  return realFetch(rewritten, init);
}) as typeof fetch;

const {
  registerWard,
  login,
  resolveDocument,
  fetchLog,
  proposeAdopt,
  confirmAdopt,
  submitOperation,
  takeCustody,
  makeLiveResolver,
} = await import("../src/registrar-client.js");

function run(cmd: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd: SERVER_DIR, stdio: "ignore" });
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} ${args.join(" ")} exited ${code}`))));
    child.on("error", reject);
  });
}

async function waitForReady(timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await realFetch(`http://localhost:${PORT}/.well-known/guardian/_`);
      if (r.status === 404 || r.status === 200) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error("wrangler dev did not become ready in time");
}

before(async () => {
  persistDir = mkdtempSync(path.join(tmpdir(), "guardian-cli-test-"));
  await run("npx", ["wrangler", "d1", "migrations", "apply", "guardian-server", "--local", "--persist-to", persistDir]);
  devProcess = spawn("npx", ["wrangler", "dev", "--port", String(PORT), "--persist-to", persistDir], { cwd: SERVER_DIR, stdio: "pipe" });
  devProcess.stdout.on("data", () => {});
  devProcess.stderr.on("data", () => {});
  await waitForReady(30_000);
});

after(async () => {
  devProcess?.kill();
  rmSync(persistDir, { recursive: true, force: true });
});

function uniqueName(prefix: string): string {
  return `${prefix}${Date.now().toString(36)}${Math.floor(Math.random() * 1000)}`;
}

test("registerWard, resolveDocument, fetchLog", async () => {
  const name = uniqueName("alice");
  const reg = await registerWard(DOMAIN, name);
  assert.equal(reg.did, `did:guardian:${DOMAIN}:${name}`);
  assert.equal(typeof reg.login_secret, "string");

  const doc = (await resolveDocument(reg.did)) as { id: string };
  assert.equal(doc.id, reg.did);

  const log = await fetchLog(reg.did);
  assert.equal(log.length, 1);
  assert.equal(log[0].type, "create");
});

test("login returns a usable session cookie", async () => {
  const name = uniqueName("alice");
  const reg = await registerWard(DOMAIN, name);
  const cookie = await login(DOMAIN, name, reg.login_secret!);
  assert.ok(cookie.length > 0);
});

test("two-step adopt, then resolve()'s own mutuality report says mutual", async () => {
  const aliceName = uniqueName("alice");
  const bobName = uniqueName("bob");
  const alice = await registerWard(DOMAIN, aliceName);
  const bob = await registerWard(DOMAIN, bobName);
  const aliceCookie = await login(DOMAIN, aliceName, alice.login_secret!);
  const bobCookie = await login(DOMAIN, bobName, bob.login_secret!);

  const step1 = await proposeAdopt(alice.did, bobCookie);
  assert.ok(step1.pendingId);
  const step2 = await confirmAdopt(alice.did, aliceCookie, step1.pendingId);
  assert.equal(step2.accepted, true);

  const aliceLog = await fetchLog(alice.did);
  const addGuardianOp = aliceLog.find((op) => op.type === "addGuardian") as { entry: { did: Did } } | undefined;
  assert.ok(addGuardianOp);
  assert.equal(addGuardianOp!.entry.did, bob.did);

  const resolveLog = makeLiveResolver();
  const resolved = await resolve(alice.did, aliceLog, resolveLog);
  assert.equal(resolved.result, "valid");
  const verified = await verifyLog(alice.did, aliceLog);
  const bobEntry = verified.state!.guardians.find((g) => g.did === bob.did)!;
  const mutuality = await checkMutuality(alice.did, resolved.metadata!.anchor, bobEntry, resolveLog);
  assert.equal(mutuality, "mutual");
});

test("takeCustody: a client-generated key replaces this registrar's held key", async () => {
  const name = uniqueName("alice");
  const alice = await registerWard(DOMAIN, name);
  const cookie = await login(DOMAIN, name, alice.login_secret!);

  const log = await fetchLog(alice.did);
  const prev = await operationHash(log[log.length - 1]);
  const keypair = await generateKeypair();
  const updateOp: Omit<UpdateOp, "proof"> = { type: "update", keys: [keypair.publicKey], services: [], alsoKnownAs: [], prev };
  const proof = await createProof(updateOp, keypair.publicKey, keypair.privateKey);

  const result = await takeCustody(alice.did, cookie, updateOp, proof);
  assert.equal(result.accepted, true);

  const newLog = await fetchLog(alice.did);
  const verified = await verifyLog(alice.did, newLog);
  assert.deepEqual(verified.state!.keys, [keypair.publicKey]);
});

test("submitOperation reports a clean rejection reason for a malformed operation", async () => {
  const name = uniqueName("carol");
  const did = `did:guardian:${DOMAIN}:${name}` as Did;
  const result = await submitOperation(did, { type: "create" } as never);
  assert.equal(result.accepted, false);
  assert.equal(typeof result.reason, "string");
});
