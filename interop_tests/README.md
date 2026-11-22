# Operation log conformance fixtures

Every file under `operation_log/valid/` and `operation_log/invalid/` is a
test case for `verifyLog` (formal spec [§8](https://guardianspec.org/docs/did-guardian-spec-v0.2.0/#8-verification)).
An independent implementation of the `did:guardian` method should replay
and verify every one of these the same way this reference implementation
does.

Generated from `packages/lib`'s own signing and verification code by
`packages/lib/scripts/gen-fixtures.ts` (`npm run gen-fixtures` in
`packages/lib`) -- never hand-edited. Generation itself verifies every
fixture against this library's own `verifyLog()`: a valid fixture must be
accepted, and an invalid one must be rejected with its own declared `reject_req`
as the rejection reason's prefix. Regenerate after any change to the
method layer (`packages/lib/src/{types,operations,rules,quorum,document,verifyLog}.ts`).

## Fixture format

```json
{
  "description": "what this fixture demonstrates",
  "expect": "accept" | "reject",
  "reject_req": "REQ-7-4",
  "did": "did:guardian:example.com:alice",
  "log": [ /* the operations of did's own log, in order */ ],
  "resolve": {
    "did:guardian:example.com": [ /* the root's own log */ ],
    "did:guardian:example.com:guardone": [ /* a guardian's own log */ ]
  }
}
```

`reject_req` is present only on an `expect: "reject"` fixture, and names
the specific requirement the fixture violates -- the convention every
rejection in this method's own reference implementation already follows:
its rejection reason is a string beginning with that REQ id. `resolve`
supplies every other DID's log a proof in `log` references (REQ-5-14);
a DID absent from `resolve` simulates REQ-8-4 (a log this verifier
cannot retrieve).

## Coverage

Every normative requirement in spec sections 4 through 9 (identifier,
encoding, state, operations, verification, DID document) has at least
one dedicated fixture, valid or invalid, naming it -- except:

- **REQ-8-2** (verification does not depend on the time of verification) is a property of the algorithm itself, not something a single log can demonstrate failing; nothing in this implementation reads the clock during verification.

Sections 10 and 11 (registrar, resolution) govern a registrar's and a
resolver's own HTTP-level behavior, not log verification in isolation,
and are exercised at the server level instead.
