// End-to-end HTTP tests against a real, local wrangler dev instance with
// a scratch D1 (never a live registrar): this is the only way to
// actually exercise index.ts's own routing, auth gating, and cookie
// handling, none of which the unit tests above touch. Each run gets its
// own throwaway persistence directory, migrated fresh, torn down after.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { createProof, generateKeypair, operationHash } from "@did-guardian/lib";

const PORT = 18799 + Math.floor(Math.random() * 1000);
const BASE = `http://localhost:${PORT}`;
const SERVER_DIR = path.resolve(import.meta.dirname, "..");
let persistDir: string;
let devProcess: ChildProcessWithoutNullStreams;

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
      const r = await fetch(`${BASE}/.well-known/guardian/_`);
      if (r.status === 404 || r.status === 200) return;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error("wrangler dev did not become ready in time");
}

before(async () => {
  persistDir = mkdtempSync(path.join(tmpdir(), "guardian-server-test-"));
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

function cookieFrom(resp: Response): string | null {
  const sc = resp.headers.get("set-cookie") ?? "";
  const m = /gw_session=([^;]+)/.exec(sc);
  return m ? m[1] : null;
}

async function registerHeld(name: string): Promise<{ did: string; loginSecret: string }> {
  const r = await fetch(`${BASE}/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name }) });
  assert.equal(r.status, 201, `register ${name}`);
  const body = (await r.json()) as { did: string; login_secret: string };
  return { did: body.did, loginSecret: body.login_secret };
}

async function loginAs(name: string, loginSecret: string): Promise<string> {
  const r = await fetch(`${BASE}/guardian-login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ name, login_secret: loginSecret, return_to: "/account" }),
  });
  const cookie = cookieFrom(r);
  assert.ok(cookie, `login as ${name} sets a session cookie`);
  return cookie!;
}

test("REQ-10-2: GET the root identity's document before anything has ever been created is 404, not auto-provisioned", async () => {
  // Only meaningful before the first registration in this run's own
  // fresh persistence directory -- run first, deliberately.
  const r = await fetch(`${BASE}/.well-known/guardian/_`);
  assert.equal(r.status, 404);
});

test("S-F1: the root identity cannot be claimed by a submitted create, through /operations or /propose", async () => {
  const keypair = await generateKeypair();
  const rootCreate = {
    type: "create" as const,
    did: "did:guardian:guardianspec.org" as const,
    keys: [keypair.publicKey],
    guardians: [],
    successor: null,
    policy: {},
    services: [],
    alsoKnownAs: [],
    prev: null,
  };
  const proof = await createProof(rootCreate, keypair.publicKey, keypair.privateKey);

  const viaOperations = await fetch(`${BASE}/.well-known/guardian/_/operations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...rootCreate, proof: [proof] }),
  });
  assert.equal(viaOperations.status, 400, "an attacker-signed root create through /operations must be rejected");

  const viaPropose = await fetch(`${BASE}/.well-known/guardian/_/propose`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation: rootCreate, proof }),
  });
  assert.equal(viaPropose.status, 400, "an attacker-signed root create through /propose must be rejected too -- it reaches the same acceptance path");

  // The root was never claimed by the attacker -- it still doesn't
  // exist yet (nothing else in this run has created it either).
  const rootLog = await fetch(`${BASE}/.well-known/guardian/_/log`);
  assert.equal(rootLog.status, 404);
});

test("register, resolve, and the root identity is lazily bootstrapped as a side effect", async () => {
  const name = uniqueName("alice");
  const { did } = await registerHeld(name);
  assert.equal(did, `did:guardian:guardianspec.org:${name}`);

  const doc = (await (await fetch(`${BASE}/.well-known/guardian/${name}`)).json()) as { id: string };
  assert.equal(doc.id, did);

  const log = (await (await fetch(`${BASE}/.well-known/guardian/${name}/log`)).json()) as Array<{ type: string }>;
  assert.equal(log.length, 1);
  assert.equal(log[0].type, "create");

  const rootResp = await fetch(`${BASE}/.well-known/guardian/_`);
  assert.equal(rootResp.status, 200);
  const rootDoc = (await rootResp.json()) as { id: string };
  assert.equal(rootDoc.id, "did:guardian:guardianspec.org");
});

test("login, the account dashboard, and self-rotate", async () => {
  const name = uniqueName("alice");
  const { loginSecret } = await registerHeld(name);
  const cookie = await loginAs(name, loginSecret);

  const accountBody = await (await fetch(`${BASE}/account`, { headers: { cookie: `gw_session=${cookie}` } })).text();
  assert.match(accountBody, new RegExp(name));

  const rotateResp = await fetch(`${BASE}/.well-known/guardian/${name}/rotate`, { method: "POST", headers: { cookie: `gw_session=${cookie}` } });
  assert.equal(rotateResp.status, 200);
});

test("R2-0.5 (re-wired): an accepted key rotation revokes every existing session for that DID", async () => {
  const name = uniqueName("alice");
  const { loginSecret } = await registerHeld(name);
  const cookie = await loginAs(name, loginSecret);

  // Someone who separately holds this session cookie (e.g. a leaked
  // login_secret, used earlier to log in) still has a working session
  // right up until the rotation below -- login_secret and the
  // operational key are unrelated credentials.
  const beforeRotate = await fetch(`${BASE}/account`, { headers: { cookie: `gw_session=${cookie}` } });
  assert.equal(beforeRotate.status, 200);

  const rotateResp = await fetch(`${BASE}/.well-known/guardian/${name}/rotate`, { method: "POST", headers: { cookie: `gw_session=${cookie}` } });
  assert.equal(rotateResp.status, 200);

  // The very same session cookie must now be dead -- the rotation
  // just invalidated it, not only for /rotate but for the dashboard
  // too.
  const afterRotate = await fetch(`${BASE}/account`, { headers: { cookie: `gw_session=${cookie}` }, redirect: "manual" });
  assert.notEqual(afterRotate.status, 200, "the old session must not still work after a key rotation");
});

test("REQ-10-13/10-14 negative: a held key signs only on a request authenticated as that exact identity", async () => {
  const aliceName = uniqueName("alice");
  const bobName = uniqueName("bob");
  const alice = await registerHeld(aliceName);
  const bob = await registerHeld(bobName);
  const bobCookie = await loginAs(bobName, bob.loginSecret);

  const noAuth = await fetch(`${BASE}/.well-known/guardian/${aliceName}/rotate`, { method: "POST" });
  assert.equal(noAuth.status, 403, "no session or trusted client at all");

  const wrongIdentity = await fetch(`${BASE}/.well-known/guardian/${aliceName}/rotate`, { method: "POST", headers: { cookie: `gw_session=${bobCookie}` } });
  assert.equal(wrongIdentity.status, 403, "a session for a DIFFERENT identity may not rotate alice's key");
  void alice;
});

test("two-step adopt: the guardian accepts, then the ward confirms, and the ward's log gets the addGuardian", async () => {
  const aliceName = uniqueName("alice");
  const bobName = uniqueName("bob");
  const alice = await registerHeld(aliceName);
  const bob = await registerHeld(bobName);
  const aliceCookie = await loginAs(aliceName, alice.loginSecret);
  const bobCookie = await loginAs(bobName, bob.loginSecret);

  const step1 = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt`, { method: "POST", headers: { cookie: `gw_session=${bobCookie}` } });
  assert.equal(step1.status, 202);
  const { pendingId } = (await step1.json()) as { pendingId: string };
  assert.ok(pendingId);

  // alice reviews the pending op (its own digest, and -- per F2 review
  // -- who specifically it names as the guardian) before confirming.
  const pendingStatus = (await (await fetch(`${BASE}/.well-known/guardian/pending/${pendingId}`, { headers: { accept: "application/json" } })).json()) as {
    digest: string;
    operation: { entry?: { did?: string } };
  };
  assert.equal(pendingStatus.operation.entry?.did, bob.did);

  const step2 = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt/confirm`, {
    method: "POST",
    headers: { cookie: `gw_session=${aliceCookie}`, "content-type": "application/json" },
    body: JSON.stringify({ pending_id: pendingId, digest: pendingStatus.digest }),
  });
  assert.equal(step2.status, 200);
  const confirmed = (await step2.json()) as { ok: boolean };
  assert.equal(confirmed.ok, true);

  const log = (await (await fetch(`${BASE}/.well-known/guardian/${aliceName}/log`)).json()) as Array<{ type: string; entry?: { did: string } }>;
  const addGuardianOp = log.find((op) => op.type === "addGuardian");
  assert.ok(addGuardianOp);
  assert.equal(addGuardianOp!.entry!.did, bob.did);
});

test("F2 (reviewed): confirm-adopt requires the digest of the pending op actually shown -- missing or stale is refused", async () => {
  const aliceName = uniqueName("alice");
  const bobName = uniqueName("bob");
  const alice = await registerHeld(aliceName);
  const bob = await registerHeld(bobName);
  const aliceCookie = await loginAs(aliceName, alice.loginSecret);
  const bobCookie = await loginAs(bobName, bob.loginSecret);

  const step1 = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt`, { method: "POST", headers: { cookie: `gw_session=${bobCookie}` } });
  const { pendingId } = (await step1.json()) as { pendingId: string };

  const noDigest = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt/confirm`, {
    method: "POST",
    headers: { cookie: `gw_session=${aliceCookie}`, "content-type": "application/json" },
    body: JSON.stringify({ pending_id: pendingId }),
  });
  assert.equal(noDigest.status, 400, "no digest at all must be refused");

  const wrongDigest = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt/confirm`, {
    method: "POST",
    headers: { cookie: `gw_session=${aliceCookie}`, "content-type": "application/json" },
    body: JSON.stringify({ pending_id: pendingId, digest: "not-the-real-digest" }),
  });
  assert.equal(wrongDigest.status, 400, "a wrong digest must be refused");

  // Alice never actually confirmed -- bob is not her guardian.
  const log = (await (await fetch(`${BASE}/.well-known/guardian/${aliceName}/log`)).json()) as Array<{ type: string }>;
  assert.ok(!log.some((op) => op.type === "addGuardian"));
});

test("F2: confirm-adopt refuses to sign a pending op that isn't a genuine addGuardian for alice", async () => {
  const aliceName = uniqueName("alice");
  const alice = await registerHeld(aliceName);
  const aliceCookie = await loginAs(aliceName, alice.loginSecret);

  // The attack: /propose has no auth gate at all, so anyone can plant a
  // pending operation naming alice as its target -- here, a key
  // rotation to a key the attacker controls, disguised as something
  // alice might be lured into "confirming" as if it were an ordinary
  // guardian request.
  const log = (await (await fetch(`${BASE}/.well-known/guardian/${aliceName}/log`)).json()) as object[];
  const prev = await operationHash(log[log.length - 1] as never);
  const attackerKey = await generateKeypair();
  const maliciousUpdate = { type: "update" as const, keys: [attackerKey.publicKey], services: [], alsoKnownAs: [], prev };
  const attackerProof = await createProof(maliciousUpdate, attackerKey.publicKey, attackerKey.privateKey);

  const proposeResp = await fetch(`${BASE}/.well-known/guardian/${aliceName}/propose`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation: maliciousUpdate, proof: attackerProof }),
  });
  assert.equal(proposeResp.status, 202, "stored as collecting, not finalized -- the attacker's key alone isn't enough");
  const { id: pendingId } = (await proposeResp.json()) as { id: string };
  assert.ok(pendingId);

  // alice, not knowing any better, fetches and reviews it first (the
  // way the real flow requires) and tries to "confirm" it -- this must
  // be refused, never signed with her held key, even with the correct
  // digest attached.
  const pendingStatus = (await (await fetch(`${BASE}/.well-known/guardian/pending/${pendingId}`, { headers: { accept: "application/json" } })).json()) as { digest: string };
  const confirmResp = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt/confirm`, {
    method: "POST",
    headers: { cookie: `gw_session=${aliceCookie}`, "content-type": "application/json" },
    body: JSON.stringify({ pending_id: pendingId, digest: pendingStatus.digest }),
  });
  assert.equal(confirmResp.status, 400, "confirm-adopt must refuse anything that isn't a genuine addGuardian");

  // alice's key is unchanged -- the attacker never got a proof out of this.
  const rotateStillWorks = await fetch(`${BASE}/.well-known/guardian/${aliceName}/rotate`, { method: "POST", headers: { cookie: `gw_session=${aliceCookie}` } });
  assert.equal(rotateStillWorks.status, 200, "alice's own session still controls her identity -- it was never taken over");
});

test("take-custody: the caller's own freshly-generated key replaces this registrar's held key", async () => {
  const name = uniqueName("alice");
  const alice = await registerHeld(name);
  const cookie = await loginAs(name, alice.loginSecret);

  const log = (await (await fetch(`${BASE}/.well-known/guardian/${name}/log`)).json()) as object[];
  const prev = await operationHash(log[log.length - 1] as never);
  const keypair = await generateKeypair();
  const updateOp = { type: "update" as const, keys: [keypair.publicKey], services: [], alsoKnownAs: [], prev };
  const proof = await createProof(updateOp, keypair.publicKey, keypair.privateKey);

  const custodyResp = await fetch(`${BASE}/.well-known/guardian/${name}/take-custody`, {
    method: "POST",
    headers: { cookie: `gw_session=${cookie}`, "content-type": "application/json" },
    body: JSON.stringify({ operation: updateOp, proof }),
  });
  assert.equal(custodyResp.status, 200);

  // This registrar no longer holds a key for this identity -- it can't
  // sign a rotation on its own behalf any more.
  const rotateAfter = await fetch(`${BASE}/.well-known/guardian/${name}/rotate`, { method: "POST", headers: { cookie: `gw_session=${cookie}` } });
  assert.notEqual(rotateAfter.status, 200);
});

test("F7: the voting page's own Sign/Withdraw form actions route to a real endpoint, not a 404", async () => {
  const aliceName = uniqueName("alice");
  const bobName = uniqueName("bob");
  const alice = await registerHeld(aliceName);
  const bob = await registerHeld(bobName);
  const aliceCookie = await loginAs(aliceName, alice.loginSecret);
  const bobCookie = await loginAs(bobName, bob.loginSecret);

  const step1 = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt`, { method: "POST", headers: { cookie: `gw_session=${bobCookie}` } });
  const { pendingId } = (await step1.json()) as { pendingId: string };

  // The HTML voting page, as alice (the pending op's own target) --
  // its Sign-as-self and Withdraw forms used to post to a nested path
  // (/.well-known/guardian/<name>/pending/<id>/...) that no route
  // actually matched.
  const page = await fetch(`${BASE}/.well-known/guardian/pending/${pendingId}`, {
    headers: { accept: "text/html", cookie: `gw_session=${aliceCookie}` },
  });
  assert.equal(page.status, 200);
  const html = await page.text();
  const signAction = /action="([^"]*\/sign-as-self)"/.exec(html)?.[1];
  const withdrawAction = /action="([^"]*\/withdraw)"/.exec(html)?.[1];
  assert.ok(signAction, "the page renders a sign-as-self form");
  assert.ok(withdrawAction, "the page renders a withdraw form (alice is the proposal's own target)");
  assert.equal(signAction, `/.well-known/guardian/pending/${pendingId}/sign-as-self`);
  assert.equal(withdrawAction, `/.well-known/guardian/pending/${pendingId}/withdraw`);

  const digest = /name="digest" value="([^"]*)"/.exec(html)?.[1];
  assert.ok(digest);
  const signResp = await fetch(`${BASE}${signAction}`, {
    method: "POST",
    headers: { cookie: `gw_session=${aliceCookie}`, "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ digest: digest! }),
  });
  assert.notEqual(signResp.status, 404, "the sign-as-self form action must route to a real endpoint");
  assert.equal(signResp.status, 302, "and finalizing alice's own addGuardian redirects back to the (now-gone) pending op's own page");
});

test("REQ-10-4: a rejected operation gets HTTP 400 with an error message", async () => {
  const name = uniqueName("carol");
  const resp = await fetch(`${BASE}/.well-known/guardian/${name}/operations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ type: "create" }), // missing required members
  });
  assert.equal(resp.status, 400);
  const body = (await resp.json()) as { error: string };
  assert.equal(typeof body.error, "string");
});

test("F4: setting up email forwarding writes to the DB without hitting the dropped wards FK (migration 0014)", async () => {
  const name = uniqueName("dana");
  const { loginSecret } = await registerHeld(name);
  const cookie = await loginAs(name, loginSecret);

  const resp = await fetch(`${BASE}/account/email`, {
    method: "POST",
    headers: { cookie: `gw_session=${cookie}`, "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ forward_to: "dana@example.com" }),
  });
  // Before migration 0014, the INSERT itself threw (D1_ERROR: no such
  // table: main.wards), surfacing as a 500 regardless of whether an
  // email provider is configured. This test's own environment has none
  // configured, so success here is the redirect-with-a-message path
  // (requestEmailForwarding's own graceful "no provider" case) -- what
  // matters is that it's never a 500.
  assert.notEqual(resp.status, 500, "the email_forwarding INSERT must not throw on the dropped wards FK");
  assert.equal(resp.status, 302);
});
