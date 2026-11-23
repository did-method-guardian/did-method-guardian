# did:guardian conformance vectors

This folder holds a test suite for the did:guardian method spec (`did-guardian-spec.md`, final revision). It was written clean-room, from the spec text alone.

- **`vectors-final/`** holds 334 JSON test vectors. Each one is a log plus an expected result. Every log is really signed: P-256, `ecdsa-jcs-2019`, low-S, with keys derived deterministically.
- **`verifier.py`** is a reference implementation:
  - §8 verification;
  - §9 DID documents;
  - §10.2 registrar acceptance, covering REQ-10-5 to 10-9;
  - §11 resolution, covering attestation and mutuality.

  It is not normative. Use it only to compare against your own implementation.
- **`gen.py`** regenerates the vectors. The output is deterministic.
- **`run.py`** runs the vectors against `verifier.py`, then runs the cross-checks and the W3C cryptosuite vectors.

## Running

```sh
python3 -m venv .venv && .venv/bin/pip install cryptography
.venv/bin/python run.py        # summary: vector counts, pass/fail, cross-check, W3C checks
.venv/bin/python run.py -v     # one line per vector, with the reason for each result
.venv/bin/python gen.py        # regenerate vectors-final/ (overwrites it)
```

The summary prints the following:
- the number of vectors passed and failed;
- the counts by kind;
- the "single change" histogram, described below;
- the REQ IDs that are labeled;
- the **extension cross-check**: every `verify` vector is run by a verifier that implements the toy extension and by one that implements none, and the two must never disagree on valid versus invalid;
- extra registrar and resolver checks;
- the 7 W3C `ecdsa-jcs-2019` P-256 test-vector checks.

## Vector format

Each file is one JSON object. The file name is the vector's name.

| Member | Meaning |
|---|---|
| `kind` | Absent for `verify` vectors. Otherwise `"registrar"` or `"resolve"`. |
| `description` | Human-readable explanation of the vector. |
| `did` | The DID under test. |
| `log` | The log, an array of operations. For a `registrar` vector, this is the log **before** the submitted operation, and may be `[]` for a `create`. |
| `op` | `registrar` only: the operation submitted to the registrar. |
| `resolver` | Object mapping DID to log, giving the *current* logs of every other identity. `verify` vectors must not use it (REQ-8-2). `registrar` vectors use it for REQ-10-6, 10-7 and 10-9. `resolve` vectors use it for REQ-11-2, 11-5 and 11-6. |
| `expect.result` | **The only asserted value.** For `verify`: `"valid"`, `"invalid"` or `"unsupported"` (REQ-8-1). For `registrar`: `"accepted"` or `"rejected"` (REQ-10-5). For `resolve`: `"valid"`, `"invalid"` or `"unsupported"`, which combines §8 with the REQ-11-2 attestation check. |
| `targets` | A label naming the REQ the vector is about. **Not asserted.** Implementations may fail a vector for a different reason, and only `expect.result` must match. |
| `base` | For a negative vector: the name of the positive vector it was derived from. |
| `anchor` | Optional. The expected anchor (REQ-5-7), which must also appear in DID document metadata (REQ-9-4). |
| `expectDocument` | Optional. The exact DID document (REQ-9-2, 9-3). |
| `expectState` | Optional. Selected state fields after the last operation: `deactivated`; or the `guardians` DIDs, `successor` and `orphan` after a promotion (REQ-6-10). |
| `expectMutuality` | `resolve` only, optional. The REQ-11-5 results, in order: guardians first, then the successor. |
| `expectWardReports` | `resolve` only, optional. The REQ-11-6 results as `[name, result]` pairs, where `name` is the last DID segment. |
| `implemented` | `registrar` only, optional. The set of extensions the registrar implements. The default is the toy extension below. `[]` means none. |
| `splitIfEnforced` | Optional. A *non-conforming* verifier that applied non-critical extensions would report `invalid` here. Conforming verifiers report `expect.result`. |
| `unsupportedWithout` | Optional. A verifier that does not implement the listed extensions MUST report `unsupported`. |

**The toy extension.** One critical extension, `https://example.org/ext/min-keys`, exists to exercise REQ-7-30 to 7-35. Its configuration is `policy.extensions["https://example.org/ext/min-keys"] = {"k": n}`, with `n` from 1 to 8. While the extension is in the state's `critical`:
- the state MUST have at least `n` keys;
- removing the configuration is invalid. This is how the extension defines removal under REQ-7-35.

An implementer that does not support it must report `unsupported` for those vectors.

**Names.**
- `inv-*` and `ext-inv-*` are invalid.
- `ext-uns-*` are unsupported.
- `reg-*` are registrar vectors, and `res-*` are resolve vectors.
- `table-N{n}-*` are the Appendix A approvals table.
- `ATTACK-*` are attack scenarios from the spec review. Most are now rejected: they are invalid at verification or rejected by the registrar. Some still verify, because only the registrar's REQ-10-7 checks stop them. A few are accepted and acknowledged in §12. `expect.result` is authoritative, and `description` says which case applies.
- `ACK-*` and `STUCK-*` record behaviour that §12 acknowledges. They are not implementation errors.

## How the negative vectors are built

Every invalid, unsupported or rejected vector is **a valid base vector plus exactly one change**. The change is one semantic edit to one operation, such as dropping a signer, changing a member, or rotating a guardian's key just before the operation. It can also be an edit to the vector itself, such as removing a log from `resolver` or replacing the DID.

After an edit to an operation, every affected signer re-signs as it would have done. The edit is therefore the only possible reason for the failure. Edits labeled "after signing", such as tampering, high-S signatures or unpaired surrogates, are deliberately not re-signed.

Some changes cascade through the hash chain: changing the DID, an earlier operation, or another identity's log changes later `prev` values and versions. `run.py` prints how many elements differ from the base, and 183 negative vectors differ in exactly one.

## What the vectors do not cover, and why

| REQ | Why there is no vector |
|---|---|
| REQ-4-5 (path segment), REQ-10-1, 10-2, 10-4 (HTTP resources, GET side effects, error format) | HTTP behaviour. They need a running registrar. |
| REQ-4-6 (DID string equality), REQ-6-7 (state conformance after each operation), REQ-9-1 (document from the last state), REQ-8-2 (log-local verification) | General properties that every vector exercises. `verify` vectors never use `resolver`. |
| REQ-10-3, 10-11, 10-12, 10-13, 10-14 (no forks served, no alteration, no name reuse, held keys) | Registrar conduct over time, or trust that no one else can check. REQ-10-12 name reuse is checked only in `run.py` (`registrar_accept(used_names=…)`). |
| REQ-10-8 (one operation per `prev`), REQ-10-9 (domain, name, current root version), REQ-9-5 (versioned resolution), REQ-11-3 and 11-4 (recorded anchor and version, rollback and fork detection) | These need state across several calls, so they are tested in `run.py`'s extra checks rather than as single vectors. REQ-10-9's root-version check also has `reg-inv-10-8-root-version`. |
| REQ-10-10 (root identity first), REQ-11-1, 11-7, 11-8 (resolution procedure, presentation, presented logs) | Procedure or presentation rules that have no observable result in this format. `resolve` vectors exercise REQ-11-1 as a whole. |
| Duplicate JSON member names (REQ-5-1, I-JSON) | The vectors are stored as parsed JSON, so duplicates cannot be represented. |
| REQ-7-31 and REQ-7-35 in general | Their meaning depends on each extension. They are covered only through the toy extension. |

Every other normative REQ appears in at least one `targets` label. `run.py` prints the full list.
