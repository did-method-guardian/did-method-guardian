// C-2/multi-key (audit r3, CLI findings): addFirstGuardian (guardian.ts)
// against a real, local packages/server wrangler dev instance -- same
// harness convention as registrar-client.test.ts (its own module-level
// fetch rewrite applies here too, since node:test loads every file in
// the same process).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { createProof, generateKeypair, operationHash, anchorOf, DEFAULT_POLICY, verifyLog } from "@did-guardian/lib";
import type { CreateOp, Did, UpdateOp } from "@did-guardian/lib";

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

const { submitOperation, fetchLog } = await import("../src/registrar-client.js");
const { addFirstGuardian } = await import("../src/commands/guardian.js");

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
  persistDir = mkdtempSync(path.join(tmpdir(), "guardian-cli-add-test-"));
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

interface SelfHeld {
  did: Did;
  key: { publicKey: string; privateKey: string };
}

/** A self-held (not registrar-custodied) identity -- the shape "guardian add" needs on both sides. */
async function createSelfHeld(name: string): Promise<SelfHeld> {
  const did = `did:guardian:${DOMAIN}:${name}` as Did;
  const key = await generateKeypair();
  const createBase: Omit<CreateOp, "proof"> = {
    type: "create",
    did,
    keys: [key.publicKey],
    guardians: [],
    successor: null,
    policy: DEFAULT_POLICY,
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const proof = await createProof(createBase, key.publicKey, key.privateKey);
  const result = await submitOperation(did, { ...createBase, proof: [proof] });
  assert.equal(result.accepted, true, `create for ${did} was rejected: ${result.reason}`);
  return { did, key };
}

test("addFirstGuardian: ordinary single-key case succeeds", async () => {
  const ward = await createSelfHeld(uniqueName("ward"));
  const guardian = await createSelfHeld(uniqueName("guardian"));

  const result = await addFirstGuardian(ward.did, guardian.did, ward.key, [guardian.key]);
  assert.equal(result.accepted, true, `rejected: ${result.reason}`);
});

test("C-2: a half-done add (guardian already accepted the ward, but the ward's own addGuardian never landed) resumes cleanly on retry, reusing the existing consent", async () => {
  const ward = await createSelfHeld(uniqueName("ward"));
  const guardian = await createSelfHeld(uniqueName("guardian"));

  // Drive step 1 alone, exactly the way addFirstGuardian's own step 1
  // would -- simulating a prior run that got this far and then died
  // or failed before step 2.
  const guardianLog = await fetchLog(guardian.did);
  const wardAnchor = await anchorOf((await fetchLog(ward.did))[0] as CreateOp);
  const acceptBase = { type: "acceptWard" as const, ward: { did: ward.did, anchor: wardAnchor }, prev: await operationHash(guardianLog[guardianLog.length - 1]) };
  const acceptProof = await createProof(acceptBase, guardian.key.publicKey, guardian.key.privateKey);
  const preAccept = await submitOperation(guardian.did, { ...acceptBase, proof: [acceptProof] });
  assert.equal(preAccept.accepted, true, `pre-accept step failed: ${preAccept.reason}`);

  // Now the "retry" -- addFirstGuardian must notice the guardian
  // already accepted this exact ward and skip straight to step 2,
  // not attempt (and potentially fail or duplicate) a second
  // acceptWard.
  const result = await addFirstGuardian(ward.did, guardian.did, ward.key, [guardian.key]);
  assert.equal(result.accepted, true, `retry was rejected: ${result.reason}`);

  const finalGuardianLog = await fetchLog(guardian.did);
  const acceptWardCount = finalGuardianLog.filter((op) => op.type === "acceptWard").length;
  assert.equal(acceptWardCount, 1, "the retry must reuse the existing acceptWard, not submit a second one");
});

test("multi-key: a guardian with two current keys needs a proof from both, and succeeds when given both", async () => {
  const ward = await createSelfHeld(uniqueName("ward"));
  const guardian = await createSelfHeld(uniqueName("guardian"));

  // Rotate the guardian to TWO current keys (an update naming both).
  const key2 = await generateKeypair();
  const guardianLog = await fetchLog(guardian.did);
  const updateBase: Omit<UpdateOp, "proof"> = {
    type: "update",
    keys: [guardian.key.publicKey, key2.publicKey],
    services: [],
    alsoKnownAs: [],
    prev: await operationHash(guardianLog[guardianLog.length - 1]),
  };
  const oldKeyProof = await createProof(updateBase, guardian.key.publicKey, guardian.key.privateKey);
  const newKeyProof = await createProof(updateBase, key2.publicKey, key2.privateKey);
  const updateResult = await submitOperation(guardian.did, { ...updateBase, proof: [oldKeyProof, newKeyProof].sort((a, b) => (a.verificationMethod < b.verificationMethod ? -1 : 1)) });
  assert.equal(updateResult.accepted, true, `rotating to two keys failed: ${updateResult.reason}`);

  const verified = await verifyLog(guardian.did, await fetchLog(guardian.did));
  assert.equal(verified.state!.keys.length, 2);

  const result = await addFirstGuardian(ward.did, guardian.did, ward.key, [guardian.key, key2]);
  assert.equal(result.accepted, true, `two-key guardian add was rejected: ${result.reason}`);
});
