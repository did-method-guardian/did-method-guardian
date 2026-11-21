import { createInterface } from "node:readline/promises";
import { Command } from "commander";
import { generateKeypair, replay, corePayload, signPayload, spkiToMultikey } from "@did-guardian/lib";
import type { Did } from "@did-guardian/lib";
import { saveKey, loadKey, listLocalKeys } from "../keystore.js";
import { loadSession } from "../state.js";
import { takeCustody, fetchLog } from "../registrar-client.js";

export function registerKeyCommand(program: Command): void {
  const key = program.command("key").description("generate and inspect local keypairs");

  key
    .command("generate <label>")
    .description("generate a P-256 keypair and save it under <label>")
    .option("--keychain", "save to the OS keychain instead of a local file")
    .action(async (label: string, opts: { keychain?: boolean }) => {
      const pair = await generateKeypair();
      await saveKey(label, pair, opts);
      console.log(`Saved key "${label}"${opts.keychain ? " to the OS keychain" : ` to ${label}.json in your did-guardian config directory`}.`);
      console.log(`Public key (Multikey): ${spkiToMultikey(pair.publicKey)}`);
    });

  key
    .command("show <label>")
    .description("print a saved key's public Multikey (never the private key)")
    .option("--keychain", "look up in the OS keychain instead of a local file")
    .action(async (label: string, opts: { keychain?: boolean }) => {
      const stored = await loadKey(label, opts);
      console.log(spkiToMultikey(stored.publicKey));
    });

  key
    .command("list")
    .description("list locally-saved key labels (keychain-stored keys aren't listed here)")
    .action(() => {
      const labels = listLocalKeys();
      if (labels.length === 0) {
        console.log("No local keys saved yet. Run \"did-guardian key generate <label>\".");
        return;
      }
      for (const label of labels) console.log(label);
    });

  key
    .command("take-custody <ward-did>")
    .description("end a registrar's custody of a ward's key -- irreversible; requires \"did-guardian login\" first")
    .option("--new-key <label>", "an existing saved key to install (default: generate and save a fresh one under \"<ward-did>-self-held\")")
    .option("--keychain", "save the new key to the OS keychain instead of a local file")
    .option("-f, --force", "proceed even if the ward has no guardian, or a registrar-held guardian alone satisfies recovery_threshold")
    .option("-y, --yes", "skip the confirmation prompt")
    .action(async (wardDid: Did, opts: { newKey?: string; keychain?: boolean; force?: boolean; yes?: boolean }) => {
      const session = loadSession();
      if (session.did !== wardDid) {
        throw new Error(`logged in as ${session.did}, not ${wardDid} -- run "did-guardian login ${wardDid} --login-secret <secret>" first.`);
      }
      if (!opts.yes) {
        const rl = createInterface({ input: process.stdin, output: process.stdout });
        const answer = await rl.question(`This permanently ends ${wardDid}'s registrar custody. There is no way back once this succeeds. Continue? [y/N] `);
        rl.close();
        if (answer.trim().toLowerCase() !== "y") {
          console.log("Cancelled.");
          return;
        }
      }
      let newKey;
      let label: string;
      if (opts.newKey) {
        label = opts.newKey;
        newKey = await loadKey(label, opts);
      } else {
        label = `${wardDid}-self-held`;
        newKey = await generateKeypair();
      }
      // REQ-7.2-12: this registrar will never hold newKey's private half,
      // so it can't prove possession of it the way it does for a
      // server-generated rotation -- that proof has to come from here,
      // over the identical content the server independently reconstructs
      // (same operationalKeys/verificationMethods/services/prev shape
      // signCustodialRotate would build). A stale prev by the time this
      // reaches the server just fails like any other prev mismatch.
      const log = await fetchLog(wardDid);
      if (log.length === 0) throw new Error(`no operations found for ${wardDid} -- is it registered?`);
      const state = replay(wardDid, log);
      const rotationPartial = {
        type: "custodial_rotate" as const,
        operationalKeys: [newKey.publicKey],
        verificationMethods: { "key-1": newKey.publicKey },
        services: state.services,
        prev: log[log.length - 1].cid,
      };
      const keySig = await signPayload(corePayload(rotationPartial as any), newKey.privateKey);
      const result = await takeCustody(wardDid, session.cookie, newKey.publicKey, keySig, opts.force);
      if (!result.accepted) throw new Error(result.reason);
      if (!opts.newKey) await saveKey(label, newKey, opts);
      console.log(`${wardDid} now holds its key${opts.newKey ? "" : ` (saved as "${label}")`}. This registrar can no longer sign on its behalf.`);
      for (const warning of result.warnings) console.log(`Warning: ${warning}`);
    });
}
