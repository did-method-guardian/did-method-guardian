import { readFileSync } from "node:fs";
import { Command } from "commander";
import { checkMutuality, checkWardReport, resolve, verifyLog } from "@did-guardian/lib";
import type { Did, Log } from "@did-guardian/lib";
import { fetchLog, makeLiveResolver } from "../registrar-client.js";
import { getPin, savePin } from "../state.js";

/**
 * REQ-5-7's anchor, pinned trust-on-first-use (SSH known_hosts style):
 * the first anchor ever seen for a DID is saved, and a later resolution
 * reporting a DIFFERENT anchor for the same DID is a loud mismatch, not
 * a silent overwrite -- that's the one thing a name-reuse attack (or a
 * registrar error) would actually change.
 */
function checkPin(did: Did, anchor: string): void {
  const pin = getPin(did);
  if (!pin) {
    savePin(did, { anchor });
    console.log(`First resolution of ${did} -- pinned anchor ${anchor}.`);
  } else if (pin.anchor !== anchor) {
    console.log(`ANCHOR MISMATCH: pinned ${pin.anchor} (from ${pin.pinnedAt}), this resolution has ${anchor} -- this is not the identity previously seen under this DID.`);
  } else {
    console.log(`Anchor matches the pin from ${pin.pinnedAt}.`);
  }
}

export function registerResolveCommand(program: Command): void {
  program
    .command("resolve <did>")
    .description("fetch a did:guardian identity's current log live, verify and resolve it (§11), and report on its guardians' and wards' own mutuality")
    .option("--log", "print the full verified operation log instead of the current document")
    .option("--json", "skip the report lines, print only the raw document or log")
    .action(async (did: Did, opts: { log?: boolean; json?: boolean }) => {
      const log = await fetchLog(did);
      const resolveLog = makeLiveResolver();
      const result = await resolve(did, log, resolveLog);
      if (result.result !== "valid") {
        console.log(`${result.result.toUpperCase()}${result.reason ? ` -- ${result.reason}` : ""}`);
        process.exitCode = 1;
        return;
      }

      if (!opts.json) checkPin(did, result.metadata!.anchor);
      console.log(JSON.stringify(opts.log ? log : result.document, null, 2));
      if (opts.json) return;

      const verified = await verifyLog(did, log);
      const state = verified.state!;

      console.log("");
      if (state.guardians.length === 0 && !state.successor) {
        console.log("No guardians or successor -- fully self-governing.");
      }
      for (const g of state.guardians) {
        const m = await checkMutuality(did, result.metadata!.anchor, g, resolveLog);
        console.log(`Guardian ${g.did}: ${m}`);
      }
      if (state.successor) {
        const m = await checkMutuality(did, result.metadata!.anchor, state.successor, resolveLog);
        console.log(`Successor ${state.successor.did}: ${m}`);
      }
      for (const record of state.wards) {
        const w = await checkWardReport(did, record, resolveLog);
        console.log(`Ward ${record.did}: ${w}`);
      }
    });

  program
    .command("verify <did>")
    .description("check a log you already have offline, from scratch (signatures and all), with no cross-log resolution -- reports only valid/invalid/unsupported (§8)")
    .requiredOption("--log <file>", "a local JSON file containing the operation log (as returned by \"resolve --log\")")
    .action(async (did: Did, opts: { log: string }) => {
      const log = JSON.parse(readFileSync(opts.log, "utf8")) as Log;
      const result = await verifyLog(did, log);
      if (result.result !== "valid") {
        console.log(`${result.result.toUpperCase()}${result.reason ? ` -- ${result.reason}` : ""}`);
        process.exitCode = 1;
        return;
      }
      console.log(`VALID (§8 only -- no cross-log or attestation check; use "resolve" for that).`);
    });
}
