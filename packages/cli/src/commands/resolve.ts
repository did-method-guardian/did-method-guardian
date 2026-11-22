import { readFileSync, writeFileSync } from "node:fs";
import { Command } from "commander";
import { parseDid, verifyLog, verifyLogHeadStatement, verifyLogHeadAgainst, statementAgeMs } from "@did-guardian/lib";
import type { Did, LogEntry, LogHeadStatement, KeyResolver } from "@did-guardian/lib";
import { resolveDid, fetchLog, fetchLogHead, resolveRegistrarKey } from "../registrar-client.js";
import { getPin, savePin, getRegistrarKeyPin, saveRegistrarKeyPin } from "../state.js";

/**
 * WS-2.3 (audit): a resolver that actually earns L3 -- for the bare-
 * domain attestor, fetches and pins that registrar's own key (captured
 * into `resolvedRegistrars` so the caller can pin it ONLY after
 * verifyLog has actually used it to check a real signature, never
 * before); for any other external DID (a cross-registrar guardian),
 * fetches THAT identity's own log and recursively verifies it through
 * this same function, extracting its key from a result that's itself
 * been checked, not from an unverified bare document fetch. `visited`
 * bounds a pathological mutual-guardian cycle (A's guardian is B, B's
 * is A) to one pass each instead of recursing forever.
 */
function makeLiveResolver(): { resolve: KeyResolver; resolvedRegistrars: Map<string, { did: Did; publicKey: string }> } {
  const resolvedRegistrars = new Map<string, { did: Did; publicKey: string }>();
  const visited = new Set<Did>();
  const resolve: KeyResolver = async (did: Did) => {
    if (visited.has(did)) return undefined;
    visited.add(did);
    let name: string | null, domain: string;
    try {
      ({ name, domain } = parseDid(did));
    } catch {
      return undefined;
    }
    if (name === null) {
      try {
        const key = await resolveRegistrarKey(domain);
        if (key.did === did) resolvedRegistrars.set(domain, key);
        return [key.publicKey];
      } catch {
        return undefined;
      }
    }
    try {
      const log = await fetchLog(did);
      const result = await verifyLog(did, log, resolve);
      return result.valid ? result.state.operationalKeys : undefined;
    } catch {
      return undefined;
    }
  };
  return { resolve, resolvedRegistrars };
}

/**
 * WS-2.2 (audit): an offline resolver, for `verify` -- no network calls
 * at all. The only key it can ever produce is the registrar's own,
 * read from a PRIOR `resolve`'s domain-keyed pin (state.ts); any other
 * DID (an external guardian) returns undefined, which is the honest
 * answer offline -- a log whose acceptance genuinely depended on that
 * guardian's own signature can reach at most "verification failed here,"
 * never a false L0.
 */
function makeOfflineResolver(): KeyResolver {
  return (did: Did) => {
    let name: string | null, domain: string;
    try {
      ({ name, domain } = parseDid(did));
    } catch {
      return undefined;
    }
    if (name !== null) return undefined;
    const pin = getRegistrarKeyPin(domain);
    return pin && pin.registrarDid === did ? [pin.registrarKey] : undefined;
  };
}

export function registerResolveCommand(program: Command): void {
  program
    .command("resolve <did>")
    .description("fetch a did:guardian identity's current operation log live, verify it from scratch, and pin its anchor and registrar key (L3)")
    .option("--log", "print the full verified operation log instead of the current document")
    .option("--save-log-head <file>", "also fetch a signed log-head statement (REQ-12-1's L2) and save it to this file, for later offline freshness checks")
    .option("--json", "skip the level/pinning line, print only the raw response")
    .action(async (did: Did, opts: { log?: boolean; saveLogHead?: string; json?: boolean }) => {
      const log = await fetchLog(did);
      const { resolve, resolvedRegistrars } = makeLiveResolver();
      const result = await verifyLog(did, log, resolve);
      if (!result.valid) {
        console.log(`VERIFICATION FAILED -- not pinning anything: ${result.reason}`);
        process.exitCode = 1;
        return;
      }
      const { anchor, registrarDid } = result;
      const { domain } = parseDid(did);
      // WS-2.3: the registrar's key was already live-resolved AND
      // cryptographically checked (against genesis's own attestation
      // proof) by the verifyLog call above -- pin exactly that, keyed by
      // domain, never a second, independent, unverified fetch.
      const registrarKey = registrarDid ? resolvedRegistrars.get(domain) : undefined;

      if (!opts.json) printLevelLine(did, anchor, registrarDid, registrarKey, "L3 (Live, verified)");
      if (opts.log) {
        console.log(JSON.stringify(log, null, 2));
      } else {
        const document = await resolveDid(did);
        console.log(JSON.stringify(document, null, 2));
      }
      if (opts.saveLogHead) {
        const statement = await fetchLogHead(did);
        writeFileSync(opts.saveLogHead, JSON.stringify(statement, null, 2));
        if (!opts.json) console.log(`Saved a signed log-head statement to ${opts.saveLogHead} (seq ${statement.seq}, ${statement.timestamp}).`);
      }
    });

  program
    .command("verify <did>")
    .description("check a log you already have offline, from scratch (signatures and all) -- reports the highest level reached (L0/L1, or L2 with --log-head), never a bare \"valid\". Never pins -- only resolve does that.")
    .requiredOption("--log <file>", "a local JSON file containing the operation log (as returned by \"resolve --log\")")
    .option("--log-head <file>", "a signed log-head statement (as saved by \"resolve --save-log-head\") -- checked against the pinned registrar key for L2")
    .option("--max-age <seconds>", "the oldest a log-head statement may be and still count as L2 (default: 300)", "300")
    .action(async (did: Did, opts: { log: string; logHead?: string; maxAge: string }) => {
      const log = JSON.parse(readFileSync(opts.log, "utf8")) as LogEntry[];
      const result = await verifyLog(did, log, makeOfflineResolver());
      if (!result.valid) {
        console.log(`L-: does not verify -- ${result.reason}`);
        process.exitCode = 1;
        return;
      }
      const { anchor } = result;
      const pin = getPin(did);

      if (opts.logHead) {
        const statement = JSON.parse(readFileSync(opts.logHead, "utf8")) as LogHeadStatement;
        await checkLogHead(did, anchor, log, statement, Number(opts.maxAge));
        return;
      }
      console.log(levelFromPin(anchor, pin));
    });
}

async function checkLogHead(did: Did, anchor: string, log: LogEntry[], statement: LogHeadStatement, maxAgeSeconds: number): Promise<void> {
  if (statement.did !== did) {
    console.log(`L0 (Consistent) only -- the log-head statement is for ${statement.did}, not ${did}.`);
    return;
  }
  // WS-2.4 (audit): anchor/headCid/seq/logHash all have to agree with
  // this log's own actual, recomputed state -- checking anchor alone let
  // a stale or outright different (but same-genesis) log pass as if this
  // statement were about it.
  const structural = await verifyLogHeadAgainst(log, statement);
  if (!structural.valid) {
    console.log(`L0 (Consistent) only -- ${structural.reason}. Do not trust either.`);
    return;
  }
  const { domain } = parseDid(did);
  const registrarPin = getRegistrarKeyPin(domain);
  if (!registrarPin) {
    console.log('L1 (Anchored) at most -- no pinned registrar key for this domain yet; run "did-guardian resolve" at least once to get one before a log-head statement can reach L2.');
    return;
  }
  if (statement.registrar !== registrarPin.registrarDid) {
    console.log(`L1 (Anchored) at most -- the log-head statement claims registrar ${statement.registrar}, but the pinned registrar for ${domain} is ${registrarPin.registrarDid}.`);
    return;
  }
  const resolve = (did2: Did) => (did2 === registrarPin.registrarDid ? [registrarPin.registrarKey] : undefined);
  const result = await verifyLogHeadStatement(statement, resolve);
  if (!result.valid) {
    console.log(`L1 (Anchored) at most -- the log-head statement's signature doesn't verify: ${result.reason}`);
    return;
  }
  const ageMs = statementAgeMs(statement);
  if (ageMs < 0) {
    console.log(`L1 (Anchored) at most -- the log-head statement claims a timestamp in the future (${statement.timestamp}). Treating as suspect, not fresh.`);
    return;
  }
  if (ageMs > maxAgeSeconds * 1000) {
    console.log(`L1 (Anchored) at most -- the log-head statement is ${Math.round(ageMs / 1000)}s old, older than the ${maxAgeSeconds}s max age requested.`);
    return;
  }
  console.log(`L2 (Fresh as of ${statement.timestamp}) -- registrar-signed, ${Math.round(ageMs / 1000)}s old, seq ${statement.seq}.`);
}

function levelFromPin(anchor: string, pin: ReturnType<typeof getPin>): string {
  if (!pin) return 'L0 (Consistent) -- verified from the log alone; no pin on file for this DID yet. First resolve it live with "did-guardian resolve" to establish one.';
  if (pin.anchor !== anchor) return `L0 (Consistent) -- ANCHOR MISMATCH: pinned ${pin.anchor}, this log has ${anchor}. Do not trust this log.`;
  return "L1 (Anchored) -- verified, and matches the pinned anchor from an earlier live resolution.";
}

/**
 * WS-2.3: pins only after verifyLog has already succeeded -- `resolve`
 * never reported L3 or saved anything on an unverified result before
 * this. ANCHOR MISMATCH is reported, never silently overwritten: the
 * whole point of a pin is that it doesn't change just because a later
 * resolution disagrees with it.
 */
function printLevelLine(did: Did, anchor: string, registrarDid: Did | undefined, registrarKey: { did: Did; publicKey: string } | undefined, level: string): void {
  const pin = getPin(did);
  if (!pin) {
    savePin(did, { anchor });
    console.log(`${level}. First resolution of ${did} -- pinned anchor ${anchor}.`);
  } else if (pin.anchor !== anchor) {
    console.log(`${level}. ANCHOR MISMATCH: pinned ${pin.anchor}, this resolution has ${anchor} -- this is not the identity previously seen under this DID.`);
    return;
  } else {
    console.log(`${level}. Anchor matches the pin from ${pin.pinnedAt}.`);
  }
  if (registrarDid && registrarKey) {
    const { domain } = parseDid(did);
    saveRegistrarKeyPin(domain, { registrarDid, registrarKey: registrarKey.publicKey });
  }
}
