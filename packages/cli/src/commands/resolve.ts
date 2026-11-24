import { readFileSync } from "node:fs";
import { Command } from "commander";
import { checkMutuality, checkPin, checkWardReport, resolve, verifyLog } from "@did-guardian/lib";
import type { Did, Log, LogResolver, PinStore } from "@did-guardian/lib";
import { fetchLog, makeLiveResolver } from "../registrar-client.js";
import { filePinStore } from "../state.js";

/**
 * REQ-11-3/REQ-11-4 (audit F-14/#5/#6): the CLI used to pin only the
 * anchor, so a registrar serving a shorter log (a rollback) or a
 * different, incompatible tail (a fork) resolved as an ordinary
 * "anchor matches" with exit 0 -- the lib's own checkPin is what
 * actually distinguishes those from an honest, growing log. Reports
 * the outcome and returns true if this was a failure a caller should
 * treat as fatal (different identity, or rolled back/forked);
 * advances the pin itself on anything else.
 */
async function reportPin(did: Did, log: Log, store: PinStore): Promise<boolean> {
  const result = await checkPin(did, log, store);
  switch (result.status) {
    case "new":
      console.log(`First resolution of ${did} -- pinned anchor ${result.current.anchor}, version ${result.current.version}.`);
      await result.advance();
      return false;
    case "same-identity":
      console.log(`${did}: matches the pin from the anchor seen before.`);
      await result.advance();
      return false;
    case "different-identity":
      console.log(
        `${did}: DIFFERENT IDENTITY -- pinned anchor ${result.recorded!.anchor}, this resolution has ${result.current.anchor}. This is not the identity previously seen under this DID.`,
      );
      return true;
    case "rolled-back-or-forked":
      console.log(
        `${did}: ROLLED BACK OR FORKED -- the previously recorded version (${result.recorded!.version}) is no longer present in this log. Do not trust this resolution without investigating.`,
      );
      return true;
  }
}

/** Wraps a LogResolver so every cross-log fetch it makes (guardians, successor, the attestation's root) is pinned too, not only the target DID resolve() is called with directly. */
function pinningResolver(base: LogResolver, store: PinStore, sawFailure: { value: boolean }): LogResolver {
  return async (did: Did) => {
    const log = await base(did);
    if (!log) return undefined;
    if (await reportPin(did, log, store)) sawFailure.value = true;
    return log;
  };
}

export function registerResolveCommand(program: Command): void {
  program
    .command("resolve <did>")
    .description("fetch a did:guardian identity's current log live, verify and resolve it (§11), and report on its guardians' and wards' own mutuality")
    .option("--log", "print the full verified operation log instead of the current document")
    .option("--json", "skip the report lines, print only the raw document or log")
    .option("--version-id <hash>", "resolve as of a past operation (REQ-9-5) instead of the log's own current end")
    .action(async (did: Did, opts: { log?: boolean; json?: boolean; versionId?: string }) => {
      const log = await fetchLog(did);
      const store = filePinStore();
      const sawFailure = { value: false };
      // REQ-11-3/11-4: pin the target DID's own log directly (it was
      // fetched here, not through resolveLog below) -- every OTHER log
      // this resolution touches (guardians, successor, the
      // attestation's root) goes through the wrapped resolver instead,
      // so it's pinned too, in every mode, including --json.
      if (await reportPin(did, log, store)) sawFailure.value = true;
      const resolveLog = pinningResolver(makeLiveResolver(), store, sawFailure);

      // REQ-11-9: passing this DID's own recorded pin into resolve()
      // itself (rather than only reportPin's separate, parallel check
      // above) means a rollback/fork/different-identity on the TARGET
      // DID makes resolve() itself report invalid, with no document --
      // not merely a logged warning alongside a document this command
      // still printed anyway.
      const recordedPin = await store.get(did);
      const result = await resolve(did, log, resolveLog, undefined, opts.versionId, recordedPin);
      if (result.result !== "valid") {
        console.log(`${result.result.toUpperCase()}${result.reason ? ` -- ${result.reason}` : ""}`);
        process.exitCode = 1;
        return;
      }

      console.log(JSON.stringify(opts.log ? log : result.document, null, 2));
      if (!opts.json) {
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
      }

      // REQ-11-4: a different identity or a rollback/fork is reported
      // above regardless of mode, but it must also make the command
      // fail -- an anchor mismatch silently exiting 0 is exactly the
      // audit's own finding (#6).
      if (sawFailure.value) process.exitCode = 1;
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
