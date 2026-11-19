import { readFileSync, writeFileSync } from "node:fs";
import { Command } from "commander";
import { cidFor, parseDid, replay, verifyLogHeadStatement, statementAgeMs } from "@did-guardian/lib";
import type { Did, LogEntry, LogHeadStatement } from "@did-guardian/lib";
import { resolveDid, fetchLog, fetchLogHead, resolveRegistrarKey } from "../registrar-client.js";
import { getPin, savePin } from "../state.js";

export function registerResolveCommand(program: Command): void {
  program
    .command("resolve <did>")
    .description("fetch a did:guardian identity's current DID document live (L3) and pin its anchor and registrar key")
    .option("--log", "fetch the full signed operation log instead of the current document")
    .option("--save-log-head <file>", "also fetch a signed log-head statement (REQ-12-1's L2) and save it to this file, for later offline freshness checks")
    .option("--json", "skip the level/pinning line, print only the raw response")
    .action(async (did: Did, opts: { log?: boolean; saveLogHead?: string; json?: boolean }) => {
      if (opts.log) {
        console.log(JSON.stringify(await fetchLog(did), null, 2));
        return;
      }
      const log = await fetchLog(did);
      const anchor = await cidFor(log[0].op);
      const { domain } = parseDid(did);
      const registrarKey = await resolveRegistrarKey(domain);
      const document = await resolveDid(did);
      if (!opts.json) printLevelLine(did, anchor, registrarKey, "L3 (Live)");
      console.log(JSON.stringify(document, null, 2));
      if (opts.saveLogHead) {
        const statement = await fetchLogHead(did);
        writeFileSync(opts.saveLogHead, JSON.stringify(statement, null, 2));
        if (!opts.json) console.log(`Saved a signed log-head statement to ${opts.saveLogHead} (seq ${statement.seq}, ${statement.timestamp}).`);
      }
    });

  program
    .command("verify <did>")
    .description("check a log you already have offline -- reports the highest level reached (L0/L1, or L2 with --log-head), never a bare \"valid\"")
    .requiredOption("--log <file>", "a local JSON file containing the operation log (as returned by \"resolve --log\")")
    .option("--log-head <file>", "a signed log-head statement (as saved by \"resolve --save-log-head\") -- checked against the pinned registrar key for L2")
    .option("--max-age <seconds>", "the oldest a log-head statement may be and still count as L2 (default: 300)", "300")
    .action(async (did: Did, opts: { log: string; logHead?: string; maxAge: string }) => {
      const log = JSON.parse(readFileSync(opts.log, "utf8")) as LogEntry[];
      try {
        replay(did, log);
      } catch (err) {
        console.log(`L-: not even consistent -- ${(err as Error).message}`);
        process.exitCode = 1;
        return;
      }
      const anchor = await cidFor(log[0].op);
      const pin = getPin(did);

      if (opts.logHead) {
        const statement = JSON.parse(readFileSync(opts.logHead, "utf8")) as LogHeadStatement;
        await checkLogHead(did, anchor, statement, pin, Number(opts.maxAge));
        return;
      }
      printLevelLine(did, anchor, undefined, levelFromPin(anchor, pin));
    });
}

async function checkLogHead(did: Did, anchor: string, statement: LogHeadStatement, pin: ReturnType<typeof getPin>, maxAgeSeconds: number): Promise<void> {
  if (statement.did !== did) {
    console.log(`L0 (Consistent) only -- the log-head statement is for ${statement.did}, not ${did}.`);
    return;
  }
  if (statement.anchor !== anchor) {
    console.log(`L0 (Consistent) only -- ANCHOR MISMATCH between the log and the log-head statement (${statement.anchor} vs ${anchor}). Do not trust either.`);
    return;
  }
  if (!pin?.registrarKey || !pin.registrarDid) {
    console.log('L1 (Anchored) at most -- no pinned registrar key for this DID yet; run "did-guardian resolve" at least once to get one before a log-head statement can reach L2.');
    return;
  }
  if (statement.registrar !== pin.registrarDid) {
    console.log(`L1 (Anchored) at most -- the log-head statement claims registrar ${statement.registrar}, but the pinned registrar for this DID is ${pin.registrarDid}.`);
    return;
  }
  const resolve = (did2: Did) => (did2 === pin.registrarDid ? [pin.registrarKey!] : undefined);
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
  if (!pin) return "L0 (Consistent) -- no pin on file for this DID yet; first resolve it live with \"did-guardian resolve\" to establish one";
  if (pin.anchor !== anchor) return `L0 (Consistent) -- ANCHOR MISMATCH: pinned ${pin.anchor}, this log has ${anchor}. Do not trust this log.`;
  return "L1 (Anchored) -- matches the pinned anchor from an earlier live resolution";
}

function printLevelLine(did: Did, anchor: string, registrarKey: { did: Did; publicKey: string } | undefined, level: string): void {
  const pin = getPin(did);
  if (!pin) {
    savePin(did, { anchor, registrarDid: registrarKey?.did, registrarKey: registrarKey?.publicKey });
    console.log(`${level}. Pinned anchor ${anchor}${registrarKey ? ` and registrar key for ${registrarKey.did}` : ""} for ${did} (first resolution).`);
  } else if (pin.anchor !== anchor) {
    console.log(`${level}. ANCHOR MISMATCH: pinned ${pin.anchor}, this resolution has ${anchor} -- this is not the identity previously seen under this DID.`);
  } else {
    if (registrarKey && !pin.registrarKey) savePin(did, { ...pin, registrarDid: registrarKey.did, registrarKey: registrarKey.publicKey });
    console.log(`${level}. Anchor matches the pin from ${pin.pinnedAt}.`);
  }
}
