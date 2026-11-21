// L2 (Fresh as of t) verification -- spec §12.2 (REQ-12-1). A registrar
// signs a small statement naming its current log head and a timestamp, so
// a verifier who holds that statement can trust it's fresh as of that time
// without a live round-trip, the same role OCSP stapling plays for a
// certificate's revocation status. Deliberately not part of operations.ts:
// a LogHeadStatement is never appended to any identity's log and isn't
// an Operation -- it's a side statement about the log, re-derivable (and
// re-signable) fresh on every request, never stored.
import { signPayload, verifyPayload, contentRef } from "./crypto.js";
import type { Did, LogEntry } from "./types.js";
import type { KeyResolver } from "./operations.js";

export interface LogHeadStatement {
  did: Did;
  anchor: string; // genesis cid (REQ-6-3) -- lets a verifier confirm this statement is about the identity it thinks it is, not just trust the did field blindly
  headCid: string; // the log's current head cid at the moment this was signed -- excludes every proof (Fix 3), same as any other entryHash, so it stays independent of which valid signature happened to be produced
  seq: number; // the log's length at that moment -- lets a verifier confirm a LATER statement from the same registrar is actually later (seq only grows), catching a registrar replaying a stale statement
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
  sig: string;
}

/** The `logHash` a LogHeadStatement reports -- every entry's full, as-stored content (op and its proofs intact), in log order. */
export async function logHashFor(log: LogEntry[]): Promise<string> {
  return contentRef(log.map((e) => ({ cid: e.cid, op: e.op, acceptedAt: e.acceptedAt })));
}

export async function signLogHeadStatement(
  partial: Omit<LogHeadStatement, "sig">,
  registrarPrivateKey: string,
): Promise<LogHeadStatement> {
  const sig = await signPayload(partial, registrarPrivateKey);
  return { ...partial, sig };
}

/**
 * Checks the signature against `statement.registrar`'s resolved key(s) --
 * never against a key the caller merely hopes is right. REQ-12-2 (first
 * contact) still applies here exactly as it does for an anchor: `resolve`
 * only ever provides real freshness once the caller already has a reason
 * to trust `registrar`'s key, from a prior L3 resolution or an
 * out-of-band channel -- this function has no opinion on where that trust
 * came from, it only checks the signature against whatever `resolve`
 * returns.
 */
export async function verifyLogHeadStatement(statement: LogHeadStatement, resolve: KeyResolver): Promise<{ valid: boolean; reason?: string }> {
  const keys = await resolve(statement.registrar);
  if (!keys || keys.length === 0) return { valid: false, reason: `no known key for registrar ${statement.registrar}` };
  const { sig, ...payload } = statement;
  const ok = (await Promise.all(keys.map((pk) => verifyPayload(payload, sig, pk)))).some(Boolean);
  return ok ? { valid: true } : { valid: false, reason: "invalid registrar signature on log-head statement" };
}

/** How old a statement is, in milliseconds, relative to `now` (default: the real current time). Negative means the statement claims a time in the future -- a verifier should treat that as suspicious, not just a very fresh zero. */
export function statementAgeMs(statement: LogHeadStatement, now: Date = new Date()): number {
  return now.getTime() - new Date(statement.timestamp).getTime();
}
