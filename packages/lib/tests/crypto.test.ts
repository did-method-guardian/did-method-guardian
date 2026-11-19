import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair, spkiToMultikey, multikeyToSpki } from "../src/crypto.js";

// Known-answer test: this exact base64url SPKI key (the live root identity's
// own key on guardianspec.org, at the time this test was written) was
// independently decoded and re-derived by hand outside this codebase --
// parsed its DER, confirmed the trailing 65 bytes are the raw uncompressed
// EC point, compressed it, multicodec-prefixed it (p256-pub, 0x1200), and
// base58btc-encoded it -- to get this exact expected string, so this test
// catches a regression in the encoding itself, not just "didn't throw".
test("spkiToMultikey: known-answer test against an independently-derived value", () => {
  const spki =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFilQ5sp0oxrr46nvSc1XwcRq3bPQ_s33mPgpbcg9ovlpOWatMB86DR5lyNUcFi-99WEMIC_ma-QzEtwHnmJkA";
  assert.equal(spkiToMultikey(spki), "zDnaeUm9Y89WYEtwDKgGeqUnWkUUp2C1cg7tcvhSh6syqzkjL");
});

test("spkiToMultikey: output is a valid multibase (z-prefixed base58btc) Multikey string", () => {
  const spki =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFilQ5sp0oxrr46nvSc1XwcRq3bPQ_s33mPgpbcg9ovlpOWatMB86DR5lyNUcFi-99WEMIC_ma-QzEtwHnmJkA";
  const multikey = spkiToMultikey(spki);
  assert.equal(multikey[0], "z", "multibase prefix for base58btc");
  assert.match(multikey.slice(1), /^[1-9A-HJ-NP-Za-km-z]+$/, "base58btc alphabet only (no 0, O, I, l)");
});

test("spkiToMultikey: round-trips for a freshly generated keypair without throwing", async () => {
  const { publicKey } = await generateKeypair();
  const multikey = spkiToMultikey(publicKey);
  assert.equal(multikey[0], "z");
});

test("multikeyToSpki: inverts the same known-answer value exactly", () => {
  const spki =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFilQ5sp0oxrr46nvSc1XwcRq3bPQ_s33mPgpbcg9ovlpOWatMB86DR5lyNUcFi-99WEMIC_ma-QzEtwHnmJkA";
  assert.equal(multikeyToSpki("zDnaeUm9Y89WYEtwDKgGeqUnWkUUp2C1cg7tcvhSh6syqzkjL"), spki);
});

test("multikeyToSpki(spkiToMultikey(k)) round-trips for freshly generated keypairs", async () => {
  for (let i = 0; i < 10; i++) {
    const { publicKey } = await generateKeypair();
    assert.equal(multikeyToSpki(spkiToMultikey(publicKey)), publicKey);
  }
});

test("multikeyToSpki rejects malformed input rather than silently returning a wrong key", () => {
  assert.throws(() => multikeyToSpki("notz-prefixed"));
  assert.throws(() => multikeyToSpki("z123")); // far too short to contain a multicodec + 33-byte point
});
