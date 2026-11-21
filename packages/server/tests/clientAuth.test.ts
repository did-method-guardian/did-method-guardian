// Regression test for the hotfix in migration 0012: authenticateOidcClient
// must never treat an untrusted (e.g. self-registered via the open
// POST /oauth/register-client) client as a "trusted client acting on a
// ward's behalf." Uses a minimal fake D1 binding -- just enough of the
// prepare().bind().first() chain getOidcClient actually calls -- rather
// than standing up wrangler dev, since this is the one query path under
// test.

import { test } from "node:test";
import assert from "node:assert/strict";
import { authenticateOidcClient } from "../src/clientAuth.js";
import { hashSecret } from "../src/secretBox.js";
import type { OidcClientRow } from "../src/db.js";
import type { Env } from "../src/env.js";

function fakeEnv(client: OidcClientRow | null): Env {
  const db = {
    prepare(_sql: string) {
      return {
        bind(..._args: unknown[]) {
          return {
            async first<T>() {
              return client as T | null;
            },
          };
        },
      };
    },
  };
  return { DB: db } as unknown as Env;
}

function basicAuthHeader(clientId: string, clientSecret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

test("an untrusted client (e.g. dynamically self-registered) is never authenticated as a trusted client, even with the correct secret", async () => {
  const clientSecret = "correct-secret";
  const client: OidcClientRow = {
    client_id: "self-registered-client",
    client_secret_hash: await hashSecret(clientSecret),
    redirect_uris: "[]",
    name: "attacker app",
    token_endpoint_auth_method: "client_secret_basic",
    registration_access_token_hash: null,
    created_at: new Date().toISOString(),
    trusted: 0,
  };
  const request = new Request("https://example.com/", { headers: { authorization: basicAuthHeader(client.client_id, clientSecret) } });
  const result = await authenticateOidcClient(request, fakeEnv(client));
  assert.equal(result, null, "an untrusted client must never authenticate, even with a correct secret");
});

test("a trusted client with the correct secret authenticates", async () => {
  const clientSecret = "correct-secret";
  const client: OidcClientRow = {
    client_id: "operator-vetted-client",
    client_secret_hash: await hashSecret(clientSecret),
    redirect_uris: "[]",
    name: "zz",
    token_endpoint_auth_method: "client_secret_basic",
    registration_access_token_hash: null,
    created_at: new Date().toISOString(),
    trusted: 1,
  };
  const request = new Request("https://example.com/", { headers: { authorization: basicAuthHeader(client.client_id, clientSecret) } });
  const result = await authenticateOidcClient(request, fakeEnv(client));
  assert.equal(result?.client_id, client.client_id);
});

test("a trusted client with the WRONG secret still fails", async () => {
  const client: OidcClientRow = {
    client_id: "operator-vetted-client",
    client_secret_hash: await hashSecret("correct-secret"),
    redirect_uris: "[]",
    name: "zz",
    token_endpoint_auth_method: "client_secret_basic",
    registration_access_token_hash: null,
    created_at: new Date().toISOString(),
    trusted: 1,
  };
  const request = new Request("https://example.com/", { headers: { authorization: basicAuthHeader(client.client_id, "wrong-secret") } });
  const result = await authenticateOidcClient(request, fakeEnv(client));
  assert.equal(result, null);
});

test("no client found at all (unknown client_id) fails, trusted or not", async () => {
  const request = new Request("https://example.com/", { headers: { authorization: basicAuthHeader("nonexistent", "anything") } });
  const result = await authenticateOidcClient(request, fakeEnv(null));
  assert.equal(result, null);
});

test("a request with no Authorization header at all fails", async () => {
  const client: OidcClientRow = {
    client_id: "operator-vetted-client",
    client_secret_hash: await hashSecret("correct-secret"),
    redirect_uris: "[]",
    name: "zz",
    token_endpoint_auth_method: "client_secret_basic",
    registration_access_token_hash: null,
    created_at: new Date().toISOString(),
    trusted: 1,
  };
  const request = new Request("https://example.com/");
  const result = await authenticateOidcClient(request, fakeEnv(client));
  assert.equal(result, null);
});
