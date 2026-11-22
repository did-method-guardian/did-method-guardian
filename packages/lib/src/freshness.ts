// L2 (Fresh as of t) verification -- spec §12.2 (REQ-12-1). A registrar
// signs a small statement naming its current log head and a timestamp, so
// a verifier who holds that statement can trust it's fresh as of that time
// without a live round-trip, the same role OCSP stapling plays for a
// certificate's revocation status. Deliberately not part of operations.ts:
// a LogHeadStatement is never appended to any identity's log and isn't
// an Operation -- it's a side statement about the log, re-derivable (and
// re-signable) fresh on every request, never stored.
import { contentRef } from "./crypto.js";
import { cidFor, unsecuredDocument, createProof, verifyAgainstKeys } from "./operations.js";
import type { Did, LogEntry, DataIntegrityProof } from "./types.js";
import type { KeyResolver } from "./operations.js";

export interface LogHeadStatement {
  did: Did;
  anchor: string; // genesis cid (REQ-6-3) -- lets a verifier confirm this statement is about the identity it thinks it is, not just trust the did field blindly
  headCid: string; // the log's current head cid at the moment this was signed -- excludes every proof (Fix 3), same as any other entryHash, so it stays independent of which valid signature happened to be produced
  /**
   * The log's length at that moment, counting EVERY stored entry,
   * superseded branches included (WS-4.6: this is the full `log` array
   * registrar.ts's own log-head signer is already handed, not the
   * active chain `reconstructChain` would narrow it to) -- lets a
   * verifier confirm a LATER statement from the same registrar is
   * actually later (seq only grows), catching a registrar replaying a
   * stale statement.
   */
  seq: number;
  /**
   * Fix 5: a multihash over the full log -- every entry's op content,
   * proofs included, unlike `headCid`/`anchor` which deliberately
   * exclude them. A registrar's own proof entries carry `created`, the
   * signed acceptance timestamp; without this field there would be
   * nothing stopping that same registrar from later re-signing the
   * identical entries under a different `created` (or any other
   * proof-only change) with no way for a verifier to tell. Computed by
   * `logHashFor`, below.
   */
  logHash: string;
  timestamp: string; // ISO 8601, when this was signed
  registrar: Did; // whose key signed this -- the accepting registrar's identity (REQ-7.1-5's same signer)
  /**
   * WS-4.6/3.5 (audit): a W3C Data Integrity proof, same as every other
   * signature this method produces -- not the raw base64url scheme a
   * previous version of this statement used, which was the one place in
   * the whole method that didn't follow REQ-6-7's own format. Exactly
   * one proof, never an array: a log-head statement has exactly one
   * signer by construction (the accepting registrar), unlike an
   * Operation's own proof set.
   */
  proof: DataIntegrityProof;
}

/**
 * The `logHash` a LogHeadStatement reports -- every entry's full, as-
 * stored content (op and its proofs intact), in log order.
 *
 * WS-2.4 (audit): hashes each entry's RECOMPUTED cid (REQ-6-4), never
 * the stored `e.cid` value as given -- a general-purpose primitive
 * should never take a self-reported content-address at face value, the
 * same reasoning every other recompute-don't-trust check in this
 * library already follows (verifyLog's own cid checks, WS-1.5's
 * duplicate-cid rejection). A caller that already independently
 * verified every cid (verifyLog) sees no difference; one that hasn't
 * gets a hash that's actually tied to each entry's real content instead
 * of whatever cid field happened to be stored alongside it.
 */
export async function logHashFor(log: LogEntry[]): Promise<string> {
  const entries = await Promise.all(log.map(async (e) => ({ cid: await cidFor(e.op), op: e.op, acceptedAt: e.acceptedAt })));
  return contentRef(entries);
}

export async function signLogHeadStatement(
  partial: Omit<LogHeadStatement, "proof">,
  registrarPrivateKey: string,
): Promise<LogHeadStatement> {
  const unsecuredDoc = unsecuredDocument(partial as any);
  const proof = await createProof(unsecuredDoc, `${partial.registrar}#key-0`, registrarPrivateKey, undefined, "assertionMethod");
  return { ...partial, proof };
}

/**
 * Checks the proof against `statement.registrar`'s resolved key(s) --
 * never against a key the caller merely hopes is right. REQ-12-2 (first
 * contact) still applies here exactly as it does for an anchor: `resolve`
 * only ever provides real freshness once the caller already has a reason
 * to trust `registrar`'s key, from a prior L3 resolution or an
 * out-of-band channel -- this function has no opinion on where that trust
 * came from, it only checks the proof against whatever `resolve` returns.
 */
export async function verifyLogHeadStatement(statement: LogHeadStatement, resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  const keys = await resolve(statement.registrar);
  if (!keys || keys.length === 0) return { valid: false, reason: `no known key for registrar ${statement.registrar}` };
  const unsecuredDoc = unsecuredDocument(statement as any);
  const ok = await verifyAgainstKeys(unsecuredDoc, [statement.proof], statement.registrar, keys);
  return ok ? { valid: true } : { valid: false, reason: "invalid registrar signature on log-head statement" };
}

/**
 * WS-2.4 (audit): checks a LogHeadStatement actually commits to THIS
 * log's real state -- anchor, headCid, seq, and logHash all recomputed
 * independently, never compared against whatever the log's own stored
 * fields happen to claim. Checking anchor alone (what the CLI's own
 * `verify --log-head` used to do) let a statement for a stale, or
 * outright different, same-genesis log pass as if it were about the log
 * actually in hand -- headCid/seq/logHash each commit to a different,
 * independent aspect of the log's exact state, and all four have to
 * agree. Only structural -- the statement's own signature is
 * `verifyLogHeadStatement`'s separate job, and which registrar key to
 * trust it against is the caller's own policy (e.g. a pinned one).
 */
export async function verifyLogHeadAgainst(log: LogEntry[], statement: LogHeadStatement): Promise<{ valid: boolean; reason?: string }> {
  if (log.length === 0) return { valid: false, reason: "log is empty" };
  const anchor = await cidFor(log[0].op);
  if (statement.anchor !== anchor) {
    return { valid: false, reason: `statement names anchor ${statement.anchor}, but this log's actual anchor is ${anchor}` };
  }
  const actualHeadCid = await cidFor(log[log.length - 1].op);
  if (statement.headCid !== actualHeadCid) {
    return { valid: false, reason: `statement names head ${statement.headCid}, but this log's actual head is ${actualHeadCid}` };
  }
  if (statement.seq !== log.length) {
    return { valid: false, reason: `statement claims seq ${statement.seq}, but this log has ${log.length} entries` };
  }
  const actualLogHash = await logHashFor(log);
  if (statement.logHash !== actualLogHash) {
    return { valid: false, reason: "statement's logHash does not match this log's actual content" };
  }
  return { valid: true };
}

/** How old a statement is, in milliseconds, relative to `now` (default: the real current time). Negative means the statement claims a time in the future -- a verifier should treat that as suspicious, not just a very fresh zero. */
export function statementAgeMs(statement: LogHeadStatement, now: Date = new Date()): number {
  return now.getTime() - new Date(statement.timestamp).getTime();
}
