import { readFileSync } from "node:fs";
import { Command } from "commander";
import { cidFor, replay } from "@did-guardian/lib";
import type { Did, LogEntry } from "@did-guardian/lib";
import { resolveDid, fetchLog } from "../registrar-client.js";
import { getPin, savePin } from "../state.js";

export function registerResolveCommand(program: Command): void {
  program
    .command("resolve <did>")
    .description("fetch a did:guardian identity's current DID document live (L3) and pin its anchor")
    .option("--log", "fetch the full signed operation log instead of the current document")
    .option("--json", "skip the level/pinning line, print only the raw response")
    .action(async (did: Did, opts: { log?: boolean; json?: boolean }) => {
      if (opts.log) {
        console.log(JSON.stringify(await fetchLog(did), null, 2));
        return;
      }
      const log = await fetchLog(did);
      const anchor = await cidFor(log[0].op);
      const document = await resolveDid(did);
      if (!opts.json) printLevelLine(did, anchor, "L3 (Live)");
      console.log(JSON.stringify(document, null, 2));
    });

  program
    .command("verify <did>")
    .description("replay a log you already have, offline -- reports the highest level reached (L0/L1), never a bare \"valid\"")
    .requiredOption("--log <file>", "a local JSON file containing the operation log (as returned by \"resolve --log\")")
    .action(async (did: Did, opts: { log: string }) => {
      const log = JSON.parse(readFileSync(opts.log, "utf8")) as LogEntry[];
      try {
        replay(did, log);
      } catch (err) {
        console.log(`L-: not even consistent -- ${(err as Error).message}`);
        process.exitCode = 1;
        return;
      }
      const anchor = await cidFor(log[0].op);
      printLevelLine(did, anchor, levelFromPin(did, anchor));
    });
}

function levelFromPin(did: Did, anchor: string): string {
  const pin = getPin(did);
  if (!pin) return "L0 (Consistent) -- no pin on file for this DID yet; first resolve it live with \"did-guardian resolve\" to establish one";
  if (pin.anchor !== anchor) return `L0 (Consistent) -- ANCHOR MISMATCH: pinned ${pin.anchor}, this log has ${anchor}. Do not trust this log.`;
  return "L1 (Anchored) -- matches the pinned anchor from an earlier live resolution";
}

function printLevelLine(did: Did, anchor: string, level: string): void {
  const pin = getPin(did);
  if (!pin) {
    savePin(did, { anchor });
    console.log(`${level}. Pinned anchor ${anchor} for ${did} (first resolution).`);
  } else if (pin.anchor !== anchor) {
    console.log(`${level}. ANCHOR MISMATCH: pinned ${pin.anchor}, this resolution has ${anchor} -- this is not the identity previously seen under this DID.`);
  } else {
    console.log(`${level}. Anchor matches the pin from ${pin.pinnedAt}.`);
  }
}
