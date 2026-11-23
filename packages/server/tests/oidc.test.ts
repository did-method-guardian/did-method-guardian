// F5 (audit r3, MEDIUM): every token-endpoint grant used to check the
// client secret only `if (clientSecret)` was actually supplied,
// silently skipping the check for a confidential client that omitted
// it. requireClientAuth is the shared fix, unit-tested directly here;
// the token-exchange grant's own standing check (the other half of F5)
// is thin glue over checkMutuality, which the lib's own test suite
// already covers extensively -- not re-tested end to end here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { requireClientAuth } from "../src/oidc.js";
import { hashSecret } from "../src/secretBox.js";
import type { OidcClientRow } from "../src/db.js";

function clientRow(overrides: Partial<OidcClientRow>): OidcClientRow {
  return {
    client_id: "test-client",
    client_secret_hash: "unused",
    redirect_uris: "[]",
    name: "Test Client",
    token_endpoint_auth_method: "client_secret_post",
    registration_access_token_hash: "unused",
    created_at: new Date().toISOString(),
    trusted: 0,
    ...overrides,
  } as OidcClientRow;
}

test("requireClientAuth: a public client (token_endpoint_auth_method=none) is exempt, even with no secret at all", async () => {
  const client = clientRow({ token_endpoint_auth_method: "none" });
  assert.equal(await requireClientAuth(client, undefined), true);
});

test("F5: a confidential client supplying NO secret is refused, not silently accepted", async () => {
  const client = clientRow({ token_endpoint_auth_method: "client_secret_post", client_secret_hash: await hashSecret("the-real-secret") });
  assert.equal(await requireClientAuth(client, undefined), false);
});

test("requireClientAuth: a confidential client with the correct secret is accepted", async () => {
  const secret = "the-real-secret";
  const client = clientRow({ token_endpoint_auth_method: "client_secret_post", client_secret_hash: await hashSecret(secret) });
  assert.equal(await requireClientAuth(client, secret), true);
});

test("requireClientAuth: a confidential client with the WRONG secret is refused", async () => {
  const client = clientRow({ token_endpoint_auth_method: "client_secret_post", client_secret_hash: await hashSecret("the-real-secret") });
  assert.equal(await requireClientAuth(client, "a-guessed-secret"), false);
});
