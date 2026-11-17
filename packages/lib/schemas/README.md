# JSON Schemas

Draft 2020-12 JSON Schemas for `did:guardian`'s own wire formats, hand-written to match `packages/lib/src/types.ts` (a small, stable set -- not worth a generator dependency). Each `description` cites the formal spec requirement it encodes; update both together if either changes.

- `guardian-policy.schema.json` -- `GuardianPolicy` (spec §5).
- `threshold.schema.json` -- the `Threshold` union every `GuardianPolicy` field uses (REQ-5-1).
- `operation.schema.json` -- the union of every current operation type (spec §7). `guardian_transfer` (v0.1, superseded by `guardian_add`/`guardian_remove`) is deliberately excluded -- it's kept in the reference implementation only to replay already-accepted historical log entries, never to construct a new one.
- `operations/*.schema.json` -- one schema per operation type.

Also served at `https://guardianspec.org/schemas/` with the same relative layout, so the `$ref`s between files resolve the same way over HTTP as they do on disk.
