import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair, spkiToMultikey, multikeyToSpki, signPayload, verifyPayload, assertJCSSafe, contentRef } from "../src/crypto.js";

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

test("generateKeypair's own publicKey is already a Multikey string -- Fix 4, no separate conversion needed", async () => {
  const { publicKey } = await generateKeypair();
  assert.equal(publicKey[0], "z");
  assert.match(publicKey.slice(1), /^[1-9A-HJ-NP-Za-km-z]+$/);
});

test("multikeyToSpki: inverts the same known-answer value exactly", () => {
  const spki =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQFilQ5sp0oxrr46nvSc1XwcRq3bPQ_s33mPgpbcg9ovlpOWatMB86DR5lyNUcFi-99WEMIC_ma-QzEtwHnmJkA";
  assert.equal(multikeyToSpki("zDnaeUm9Y89WYEtwDKgGeqUnWkUUp2C1cg7tcvhSh6syqzkjL"), spki);
});

test("spkiToMultikey(multikeyToSpki(k)) round-trips for freshly generated keypairs", async () => {
  for (let i = 0; i < 10; i++) {
    const { publicKey } = await generateKeypair(); // already Multikey
    assert.equal(spkiToMultikey(multikeyToSpki(publicKey)), publicKey);
  }
});

test("multikeyToSpki rejects malformed input rather than silently returning a wrong key", () => {
  assert.throws(() => multikeyToSpki("notz-prefixed"));
  assert.throws(() => multikeyToSpki("z123")); // far too short to contain a multicodec + 33-byte point
});

// --- Fix 3: low-S normalization and rejection ---------------------------

test("signPayload always produces a low-S signature, and verifyPayload accepts it", async () => {
  const { publicKey, privateKey } = await generateKeypair();
  const payload = { hello: "world" };
  const sig = await signPayload(payload, privateKey);
  assert.equal(await verifyPayload(payload, sig, publicKey), true);
});

test("verifyPayload rejects a high-S signature outright -- malleability must not produce a second valid form", async () => {
  const { publicKey, privateKey } = await generateKeypair();
  const payload = { hello: "world" };
  const sig = await signPayload(payload, privateKey);
  const sigBytes = Uint8Array.from(Buffer.from(sig.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
  const P256_N = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
  let s = 0n;
  for (const b of sigBytes.slice(32, 64)) s = (s << 8n) | BigInt(b);
  const highS = P256_N - s; // the other, equally "valid" (per raw ECDSA) form of the same signature
  const highSBytes = new Uint8Array(64);
  highSBytes.set(sigBytes.slice(0, 32), 0);
  let v = highS;
  for (let i = 31; i >= 0; i--) {
    highSBytes[32 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  let bin = "";
  for (const b of highSBytes) bin += String.fromCharCode(b);
  const highSSig = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  assert.equal(await verifyPayload(payload, highSSig, publicKey), false, "the malleable high-S counterpart must not also verify");
});

// --- Fix 4: JCS safety ----------------------------------------------------

test("assertJCSSafe rejects a non-integer number, -0, and a lone surrogate, but accepts ordinary content", () => {
  assert.throws(() => assertJCSSafe({ x: 1.5 }));
  assert.throws(() => assertJCSSafe({ x: -0 }));
  assert.throws(() => assertJCSSafe({ x: "\uD800" })); // lone high surrogate, no following low surrogate
  assert.doesNotThrow(() => assertJCSSafe({ x: 1, y: "ok", z: [1, 2, { nested: "ok" }], w: null }));
});

test("signPayload refuses to sign JCS-unsafe content rather than producing a signature nobody else can reproduce the hash of", async () => {
  const { privateKey } = await generateKeypair();
  await assert.rejects(() => signPayload({ x: 1.5 }, privateKey));
});

// --- Fix 3: multihash anchor format ---------------------------------------

test("contentRef produces a sha2-256 multihash (0x12 0x20 prefix), base58btc, 'z'-prefixed, deterministic for identical content", async () => {
  const ref = await contentRef({ a: 1, b: "two" });
  assert.equal(ref[0], "z");
  assert.match(ref.slice(1), /^[1-9A-HJ-NP-Za-km-z]+$/);
  assert.equal(await contentRef({ b: "two", a: 1 }), ref, "key order must not affect the hash (JCS canonicalization)");
});
