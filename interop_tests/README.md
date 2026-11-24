# Conformance vectors

The did:guardian conformance suite lives in [`cleanroom/`](cleanroom/README.md)
-- 334 JSON vectors, written independently from the spec text alone
(`did-guardian-spec.md`, v1.0.0), covering verification (§8), registrar
acceptance (§10.2) and resolution (§11). `cleanroom/README.md` documents
the vector format and `cleanroom/verifier.py` is a second, independent
reference implementation.

`packages/lib` runs every vector against its own code in
`packages/lib/tests/verify-vectors.test.ts`,
`packages/lib/tests/resolve-vectors.test.ts` and
`packages/lib/tests/registrar-vectors.test.ts` (`npm test` in
`packages/lib`). An independent implementation of the did:guardian
method should pass the same vectors the same way.
