# JSON Schemas

Draft 2020-12 JSON Schemas for `did:guardian`'s own wire formats, matching `packages/lib/src/types.ts` (a small, stable set -- not worth a generator dependency). Each `description` cites the formal spec requirement it encodes; update both together if either changes.

This copy is generated, not hand-written here: `website/static/schemas/` is the source of truth; `website/scripts/sync-schemas.py` copies it into this directory byte-identically. Edit there, then rerun that script -- CI's `website-sync` job fails the build if this directory would still differ from the result.

- `policy.schema.json` -- `Policy` (spec §6.3).
- `setting.schema.json` -- the `Setting` union `policy.recovery`/`membership`/`removal` and `policy.deactivation.threshold` use (REQ-6-11/REQ-6-12).
- `entry.schema.json`, `ward-record.schema.json`, `service.schema.json` -- `Entry` (REQ-6-2), `WardRecord` (REQ-6-4), `Service` (REQ-6-6).
- `data-integrity-proof.schema.json` -- `DataIntegrityProof` (REQ-5-11).
- `operation.schema.json` -- the union of all nine operation types (spec §7).
- `operations/*.schema.json` -- one schema per operation type.

Also served at `https://guardianspec.org/schemas/` with the same relative layout, so the `$ref`s between files resolve the same way over HTTP as they do on disk.
