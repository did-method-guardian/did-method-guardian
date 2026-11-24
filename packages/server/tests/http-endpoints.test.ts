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
import { createHash, randomBytes } from "node:crypto";
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

test("R2-0.5 (re-wired, per review): a key rotation revokes every existing session AND the old login_secret for that DID", async () => {
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

  // And the OLD login_secret itself must no longer produce a NEW
  // session either -- otherwise whoever also holds the leaked
  // login_secret just logs back in, defeating the point of the
  // rotation.
  const reLoginAttempt = await fetch(`${BASE}/guardian-login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ name, login_secret: loginSecret, return_to: "/account" }),
  });
  assert.equal(cookieFrom(reLoginAttempt), null, "the old login_secret must no longer produce a session after a key rotation");
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

test("post-recovery login secret reissue (user-decided design, 2026-11-23): a guardian-only recovery issues alice a fresh login secret, usable once; the old secret and session are both dead", async () => {
  const aliceName = uniqueName("alice");
  const bobName = uniqueName("bob");
  const alice = await registerHeld(aliceName);
  const bob = await registerHeld(bobName);
  const aliceCookie = await loginAs(aliceName, alice.loginSecret);
  const bobCookie = await loginAs(bobName, bob.loginSecret);

  // bob becomes alice's guardian (same two-step flow as above) -- the
  // default policy's recovery threshold is "majority" of N=1, so bob
  // alone is enough to approve the recovery below.
  const adoptStep1 = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt`, { method: "POST", headers: { cookie: `gw_session=${bobCookie}` } });
  const { pendingId: adoptPendingId } = (await adoptStep1.json()) as { pendingId: string };
  const adoptStatus = (await (await fetch(`${BASE}/.well-known/guardian/pending/${adoptPendingId}`, { headers: { accept: "application/json" } })).json()) as { digest: string };
  const adoptConfirm = await fetch(`${BASE}/.well-known/guardian/${aliceName}/adopt/confirm`, {
    method: "POST",
    headers: { cookie: `gw_session=${aliceCookie}`, "content-type": "application/json" },
    body: JSON.stringify({ pending_id: adoptPendingId, digest: adoptStatus.digest }),
  });
  assert.equal(adoptConfirm.status, 200);

  // alice lost her key -- someone recovering on her behalf generates a
  // fresh one and proves possession of it, but has no current key of
  // alice's own to co-sign with. That's exactly the trigger: a
  // keys-changing update with no proof from any of alice's prior keys.
  const log = (await (await fetch(`${BASE}/.well-known/guardian/${aliceName}/log`)).json()) as object[];
  const prev = await operationHash(log[log.length - 1] as never);
  const recoveryKeypair = await generateKeypair();
  const updateOp = { type: "update" as const, keys: [recoveryKeypair.publicKey], services: [], alsoKnownAs: [], prev };
  const newKeyProof = await createProof(updateOp, recoveryKeypair.publicKey, recoveryKeypair.privateKey);

  const proposeResp = await fetch(`${BASE}/.well-known/guardian/${aliceName}/propose`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation: updateOp, proof: newKeyProof }),
  });
  assert.equal(proposeResp.status, 202, "the new key's own proof of possession alone isn't enough -- still needs a guardian");
  const { id: pendingId } = (await proposeResp.json()) as { id: string };

  // bob reviews and signs with his own held key, through the same
  // voting-page sign-as-self flow as F7's own test above.
  const pendingPage = await fetch(`${BASE}/.well-known/guardian/pending/${pendingId}`, { headers: { accept: "text/html", cookie: `gw_session=${bobCookie}` } });
  const pendingHtml = await pendingPage.text();
  const signAction = /action="([^"]*\/sign-as-self)"/.exec(pendingHtml)?.[1];
  const digest = /name="digest" value="([^"]*)"/.exec(pendingHtml)?.[1];
  assert.ok(signAction && digest);

  const signResp = await fetch(`${BASE}${signAction}`, {
    method: "POST",
    headers: { cookie: `gw_session=${bobCookie}`, "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ digest: digest! }),
  });
  assert.equal(signResp.status, 200, "finalizing a recovery that reissues a login secret renders it inline, not a bare redirect");
  const signHtml = await signResp.text();
  const newLoginSecret = /<code>([^<]+)<\/code>/.exec(signHtml)?.[1];
  assert.ok(newLoginSecret, "the response shows the freshly issued login secret");

  // The new secret works, once.
  const newCookie = await loginAs(aliceName, newLoginSecret!);
  assert.ok(newCookie);

  // The old login_secret must no longer work -- R2-0.5's own
  // invalidation still fires first, same as a self-service rotation.
  const oldSecretAttempt = await fetch(`${BASE}/guardian-login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ name: aliceName, login_secret: alice.loginSecret, return_to: "/account" }),
  });
  assert.equal(cookieFrom(oldSecretAttempt), null, "the pre-recovery login_secret must no longer produce a session");

  // And alice's session from before the recovery is dead too.
  const oldSessionAttempt = await fetch(`${BASE}/account`, { headers: { cookie: `gw_session=${aliceCookie}` }, redirect: "manual" });
  assert.notEqual(oldSessionAttempt.status, 200, "the pre-recovery session must not still work after a guardian-approved recovery");
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

// Audit r4 regression tests, below -- each one reproduces a specific
// repro script a clean-room review used to find the gap, directly
// against this file's own shared wrangler dev instance.

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function registerOidcClient(): Promise<{ client_id: string }> {
  const r = await fetch(`${BASE}/oauth/register-client`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: ["https://rp.example/cb"], token_endpoint_auth_method: "none" }),
  });
  assert.equal(r.status, 201);
  return (await r.json()) as { client_id: string };
}

/** Full authorization_code + PKCE flow for an already-registered name, returning a usable access_token. */
async function getAccessToken(name: string, loginSecret: string, clientId: string, scope: string): Promise<{ access_token: string; scope: string }> {
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const authorizeUrl = `${BASE}/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: "https://rp.example/cb", response_type: "code", scope, code_challenge: challenge, code_challenge_method: "S256" })}`;

  const loginResp = await fetch(authorizeUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ name, login_secret: loginSecret, return_to: "/account" }),
  });
  const cookie = cookieFrom(loginResp);
  assert.ok(cookie, "authorize's own login step sets a session cookie");

  const consentResp = await fetch(authorizeUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie: `gw_session=${cookie}` },
    redirect: "manual",
    body: new URLSearchParams({ consent: "allow" }),
  });
  const code = new URL(consentResp.headers.get("location")!).searchParams.get("code");
  assert.ok(code, "consent redirects back with an authorization code");

  const tokenResp = await fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: code!, redirect_uri: "https://rp.example/cb", code_verifier: verifier, client_id: clientId }),
  });
  assert.equal(tokenResp.status, 200, "a fresh DB must issue a token on the very first authorization_code exchange (fix D: signing-key format)");
  return (await tokenResp.json()) as { access_token: string; scope: string };
}

test("fix D: a fresh DB issues /token on the very first exchange (signing key Multikey/SPKI mismatch)", async () => {
  const name = uniqueName("oidcfresh");
  const { loginSecret, did } = await registerHeld(name);
  const client = await registerOidcClient();
  const tok = await getAccessToken(name, loginSecret, client.client_id, "openid");
  assert.ok(tok.access_token);
  void did;
});

test("fix C: token-exchange cannot escalate scope, and a legitimate narrowing exchange still works", async () => {
  const name = uniqueName("oidcnar");
  const { loginSecret, did } = await registerHeld(name);
  const client = await registerOidcClient();
  const tok = await getAccessToken(name, loginSecret, client.client_id, "openid email");

  const escalate = await fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", subject_token: tok.access_token, resource: did, client_id: client.client_id, scope: "create:managed-identity" }),
  });
  assert.notEqual(escalate.status, 200, "exchanging for a scope the subject_token never had must be refused");

  const narrow = await fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", subject_token: tok.access_token, resource: did, client_id: client.client_id, scope: "openid" }),
  });
  assert.equal(narrow.status, 200, "exchanging for a scope that IS a subset of the subject_token's own scope must still work");
});

test("fix C: a guardian cannot token-exchange into create:managed-identity acting as its ward", async () => {
  const guardianName = uniqueName("oidcguard");
  const wardName = uniqueName("oidcward");
  const guardian = await registerHeld(guardianName);
  const ward = await registerHeld(wardName);
  const guardianCookie = await loginAs(guardianName, guardian.loginSecret);
  const wardCookie = await loginAs(wardName, ward.loginSecret);

  const adopt = await fetch(`${BASE}/.well-known/guardian/${wardName}/adopt`, { method: "POST", headers: { cookie: `gw_session=${guardianCookie}` } });
  const { pendingId } = (await adopt.json()) as { pendingId: string };
  const pendingStatus = (await (await fetch(`${BASE}/.well-known/guardian/pending/${pendingId}`, { headers: { accept: "application/json" } })).json()) as { digest: string };
  await fetch(`${BASE}/.well-known/guardian/${wardName}/adopt/confirm`, {
    method: "POST",
    headers: { cookie: `gw_session=${wardCookie}`, "content-type": "application/json" },
    body: JSON.stringify({ pending_id: pendingId, digest: pendingStatus.digest }),
  });

  const client = await registerOidcClient();
  const tok = await getAccessToken(guardianName, guardian.loginSecret, client.client_id, "openid");

  const actAsWard = await fetch(`${BASE}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", subject_token: tok.access_token, resource: ward.did, client_id: client.client_id, scope: "create:managed-identity" }),
  });
  assert.notEqual(actAsWard.status, 200, "a guardian's own standing over a ward must never grant it OIDC-level impersonation scope for that ward");
});

test("fix B2 (REQ-5-17): sign-as-self refuses a proposal whose prev is a DIFFERENT identity's head (the ward-takeover-its-guardian class)", async () => {
  const guardianName = uniqueName("relayg");
  const wardName = uniqueName("relayw");
  const guardian = await registerHeld(guardianName);
  const ward = await registerHeld(wardName);
  const guardianCookie = await loginAs(guardianName, guardian.loginSecret);
  const wardCookie = await loginAs(wardName, ward.loginSecret);

  const adopt = await fetch(`${BASE}/.well-known/guardian/${wardName}/adopt`, { method: "POST", headers: { cookie: `gw_session=${guardianCookie}` } });
  const { pendingId: adoptId } = (await adopt.json()) as { pendingId: string };
  const adoptStatus = (await (await fetch(`${BASE}/.well-known/guardian/pending/${adoptId}`, { headers: { accept: "application/json" } })).json()) as { digest: string };
  await fetch(`${BASE}/.well-known/guardian/${wardName}/adopt/confirm`, {
    method: "POST",
    headers: { cookie: `gw_session=${wardCookie}`, "content-type": "application/json" },
    body: JSON.stringify({ pending_id: adoptId, digest: adoptStatus.digest }),
  });

  const guardianLog = (await (await fetch(`${BASE}/.well-known/guardian/${guardianName}/log`)).json()) as object[];
  const guardianHead = await operationHash(guardianLog[guardianLog.length - 1] as never);

  // The ward proposes, UNDER ITS OWN DID, an "update" whose prev is
  // actually the GUARDIAN's own current head -- a throwaway key's
  // proof is enough to get it into the pending queue (/propose's own
  // trust model: the proof is the authorization, checked for real
  // only at finalization).
  const attacker = await generateKeypair();
  const evilOp = { type: "update" as const, keys: [attacker.publicKey], services: [], alsoKnownAs: [], prev: guardianHead };
  const evilProof = await createProof(evilOp, attacker.publicKey, attacker.privateKey);
  const proposeResp = await fetch(`${BASE}/.well-known/guardian/${wardName}/propose`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation: evilOp, proof: evilProof }),
  });
  const proposed = (await proposeResp.json()) as { id: string };
  assert.ok(proposed.id);

  // The guardian opens the pending op and signs as itself.
  const status = (await (await fetch(`${BASE}/.well-known/guardian/pending/${proposed.id}`)).json()) as { digest: string };
  const signAsSelfResp = await fetch(`${BASE}/.well-known/guardian/pending/${proposed.id}/sign-as-self`, {
    method: "POST",
    headers: { cookie: `gw_session=${guardianCookie}`, "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ digest: status.digest }),
  });
  assert.equal(signAsSelfResp.status, 409, "sign-as-self must refuse a proposal whose prev names a different identity's own head");

  // The guardian's own log and login are unaffected.
  const guardianLogAfter = (await (await fetch(`${BASE}/.well-known/guardian/${guardianName}/log`)).json()) as Array<{ type: string }>;
  assert.equal(guardianLogAfter.length, guardianLog.length, "the guardian's own log must not have gained an operation");
  const relogin = await fetch(`${BASE}/guardian-login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ name: guardianName, login_secret: guardian.loginSecret, return_to: "/account" }),
  });
  assert.ok(cookieFrom(relogin), "the guardian's own login must still work afterward");
});

test("fix D: self-rotation reissues a working login secret instead of leaving the requester locked out", async () => {
  const name = uniqueName("rot");
  const { loginSecret } = await registerHeld(name);
  const cookie = await loginAs(name, loginSecret);

  const rotateResp = await fetch(`${BASE}/account/rotate`, { method: "POST", headers: { cookie: `gw_session=${cookie}`, "content-type": "application/x-www-form-urlencoded" }, redirect: "manual", body: "" });
  const page = await rotateResp.text();
  const newSecret = /<code[^>]*>([^<]+)<\/code>/.exec(page)?.[1];
  assert.ok(newSecret, "the rotation response must show a new login secret, not just confirm the rotation");

  const loginWithNew = await fetch(`${BASE}/guardian-login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ name, login_secret: newSecret!, return_to: "/account" }),
  });
  assert.ok(cookieFrom(loginWithNew), "the newly-issued secret must actually work -- otherwise self-rotation still locks the requester out");

  const loginWithOld = await fetch(`${BASE}/guardian-login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
    body: new URLSearchParams({ name, login_secret: loginSecret, return_to: "/account" }),
  });
  assert.equal(cookieFrom(loginWithOld), null, "the OLD secret must be dead after rotation");
});

test("fix E: reissueLoginSecret ends the identity's other existing sessions, not just future logins", async () => {
  const name = uniqueName("reissue");
  const { loginSecret } = await registerHeld(name);
  const staleCookie = await loginAs(name, loginSecret);

  const beforeReissue = await fetch(`${BASE}/account`, { headers: { cookie: `gw_session=${staleCookie}` } });
  assert.equal(beforeReissue.status, 200, "sanity: the session works before reissuing");

  const reissueResp = await fetch(`${BASE}/account/login-secret/reissue`, { method: "POST", headers: { cookie: `gw_session=${staleCookie}`, "content-type": "application/x-www-form-urlencoded" }, redirect: "manual", body: "" });
  assert.notEqual(reissueResp.status, 500);

  const afterReissue = await fetch(`${BASE}/account`, { headers: { cookie: `gw_session=${staleCookie}` }, redirect: "manual" });
  assert.notEqual(afterReissue.status, 200, "the session that was already open before the reissue must be ended by it");
});
