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
import { findByHash, type LogResolver } from "./resolve.js";
import { verifyLog } from "./verifyLog.js";
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
 * REQ-11-3/REQ-11-4. `anchorOf`/`operationHash` on `log[0]`/`log` at
 * the end assume a well-formed `create` at `log[0]`, same
 * precondition every other lib function with that shape has -- a
 * caller that wants `current`/`advance` to mean anything should only
 * ever call this with a log it has verified. The rollback/fork check
 * itself makes NO such assumption, deliberately (audit r4, Z-2): this
 * is commonly the first thing a caller does with a freshly fetched,
 * not-yet-verified log (see commands/resolve.ts), specifically because
 * that log might be a fork -- trusting it already verified would defeat
 * the point.
 */
export async function checkPin(did: Did, log: Log, store: PinStore, implementedExtensions: ReadonlySet<string> = new Set()): Promise<PinCheckResult> {
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

  // REQ-11-4 (r7d, audit r4 Z-2): "does not contain the recorded
  // version" alone is not enough -- an attacker who forks right after
  // the anchor can append the honestly-signed, actually-pinned
  // operation AFTER the fork purely so its hash is still found
  // somewhere. Verifying the log from the start through the recorded
  // version's own index is what actually catches that: the forked
  // operation's own `prev` never chains to it.
  const pinnedIndex = await findByHash(log, recorded.version);
  if (pinnedIndex === -1) return { status: "rolled-back-or-forked", current, recorded, advance };
  const verified = await verifyLog(did, log.slice(0, pinnedIndex + 1), implementedExtensions);
  if (verified.result !== "valid") return { status: "rolled-back-or-forked", current, recorded, advance };
  return { status: "same-identity", current, recorded, advance };
}

/**
 * REQ-10-15: wraps a `LogResolver` so every fetch made through it is
 * checked against `store` and recorded there, exactly once per DID per
 * call (cached) regardless of how many separate REQ-10-7 rows end up
 * asking for the same log. A log whose anchor or recorded version no
 * longer matches is handed back as `undefined` -- indistinguishable
 * from a log that could not be fetched at all, which is exactly what
 * REQ-10-7 already says to do with it ("a log that cannot be fetched
 * counts as a log that does not verify") -- and the stored pin is left
 * exactly as it was, since `advance` is simply never called for that
 * fetch. Every other fetch (new, or still matching) advances the
 * stored pin immediately, before this function (or its caller) has any
 * idea whether the operation that triggered it will end up accepted or
 * rejected -- REQ-10-15's own text ("including for operations it
 * rejects") is unconditional, and this wrapper has no way to defer the
 * write until an outcome is known even if it wanted to.
 */
export function makePinningResolver(resolveLog: LogResolver, store: PinStore): LogResolver {
  const cache = new Map<Did, Promise<Log | null | undefined>>();
  return (did: Did): Promise<Log | null | undefined> => {
    let pending = cache.get(did);
    if (!pending) {
      pending = (async () => {
        const log = await resolveLog(did);
        if (log === undefined || log === null) return log;
        const check = await checkPin(did, log, store);
        if (check.status === "different-identity" || check.status === "rolled-back-or-forked") return undefined;
        await check.advance();
        return log;
      })();
      cache.set(did, pending);
    }
    return pending;
  };
}
