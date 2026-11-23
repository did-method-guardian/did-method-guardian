// REQ-11-3/REQ-11-4: rollback and fork detection. A resolver that only
// ever checks a log's own internal consistency (verifyLog) has no way
// to notice that a *later* fetch of the same DID came back with fewer
// operations than before (a rollback) or a different, incompatible tail
// (a fork) -- both verify perfectly well on their own. Catching either
// requires remembering what was seen last time, which is why this is a
// pluggable store rather than an in-memory-only check: the same function
// has to serve a CLI's own local file (one person, one machine) and,
// eventually, a registrar's own persistent storage (REQ-10-7, if a
// pending spec amendment requiring this there lands) without either
// caller reimplementing the comparison.
import { anchorOf, operationHash } from "./operations.js";
import { findByHash } from "./resolve.js";
import type { CreateOp, Did, Log } from "./types.js";

export interface PinRecord {
  anchor: string;
  version: string;
}

/**
 * Where pin records live. `get`/`set` may be sync or async -- a CLI's
 * own JSON file is sync; a registrar's D1/KV would be async. There is
 * no `delete`: forgetting a pin on purpose is a caller decision this
 * interface doesn't need an opinion about.
 */
export interface PinStore {
  get(did: Did): PinRecord | undefined | Promise<PinRecord | undefined>;
  set(did: Did, record: PinRecord): void | Promise<void>;
}

export type PinStatus = "new" | "same-identity" | "different-identity" | "rolled-back-or-forked";

export interface PinCheckResult {
  status: PinStatus;
  /** The record this check computed from `log` -- {anchor of log[0], hash of log[log.length-1]}. */
  current: PinRecord;
  /** The previously recorded pin, if there was one (absent only when status is "new"). */
  recorded?: PinRecord;
  /**
   * Records `current` as this DID's new pin. Available regardless of
   * `status` -- advancing past a "different-identity" or
   * "rolled-back-or-forked" result is a legitimate choice a caller can
   * make (after warning loudly, or asking first), not a programming
   * error, so this never refuses to let it happen. A caller that wants
   * to stop instead simply doesn't call this.
   */
  advance(): Promise<void>;
}

/**
 * REQ-11-3/REQ-11-4. `log` MUST already be a log this caller has
 * verified (checkPin trusts its own two hashes, not log's own
 * validity) -- anchorOf/operationHash assume a well-formed `create` at
 * log[0], same precondition every other lib function with that shape
 * has.
 */
export async function checkPin(did: Did, log: Log, store: PinStore): Promise<PinCheckResult> {
  if (log.length === 0) throw new Error("checkPin: an empty log has no anchor or version to pin");
  const anchor = await anchorOf(log[0] as CreateOp);
  const version = await operationHash(log[log.length - 1]);
  const current: PinRecord = { anchor, version };
  const advance = async () => {
    await store.set(did, current);
  };

  const recorded = await store.get(did);
  if (!recorded) return { status: "new", current, advance };
  if (recorded.anchor !== anchor) return { status: "different-identity", current, recorded, advance };

  // REQ-11-4: "does not contain the recorded version" -- the log may
  // have grown since the recorded version was its own current head, so
  // this checks the whole log, not just its own last entry.
  const stillPresent = (await findByHash(log, recorded.version)) !== -1;
  if (!stillPresent) return { status: "rolled-back-or-forked", current, recorded, advance };
  return { status: "same-identity", current, recorded, advance };
}
