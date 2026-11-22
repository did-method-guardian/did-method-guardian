import { createInterface } from "node:readline/promises";
import { Command } from "commander";
import { createProof, generateKeypair, operationHash, verifyLog } from "@did-guardian/lib";
import type { Did, UpdateOp } from "@did-guardian/lib";
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
      console.log(`Public key (Multikey): ${pair.publicKey}`);
    });

  key
    .command("show <label>")
    .description("print a saved key's public Multikey (never the private key)")
    .option("--keychain", "look up in the OS keychain instead of a local file")
    .action(async (label: string, opts: { keychain?: boolean }) => {
      const stored = await loadKey(label, opts);
      console.log(stored.publicKey);
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
    .option("-y, --yes", "skip the confirmation prompt")
    .action(async (wardDid: Did, opts: { newKey?: string; keychain?: boolean; yes?: boolean }) => {
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
        // Saved BEFORE submitting, not after -- once the server accepts
        // this, this registrar can no longer sign on wardDid's behalf at
        // all (that's take-custody's entire point), so if the process
        // died between a successful submission and saving the key, this
        // identity would be permanently locked out with no copy of its
        // own new key anywhere. An unused generated key left on disk
        // because the submission below never happens or gets rejected
        // is harmless by comparison.
        await saveKey(label, newKey, opts);
      }
      const log = await fetchLog(wardDid);
      if (log.length === 0) throw new Error(`no operations found for ${wardDid} -- is it registered?`);
      const verified = await verifyLog(wardDid, log);
      if (verified.result !== "valid") throw new Error(`${wardDid}'s own log does not verify: ${verified.reason}`);
      const state = verified.state!;
      // An `update` replaces keys/services/alsoKnownAs wholesale -- carry
      // the existing services/alsoKnownAs over unchanged, only the keys
      // actually change here.
      const op: Omit<UpdateOp, "proof"> = {
        type: "update",
        keys: [newKey.publicKey],
        services: state.services,
        alsoKnownAs: state.alsoKnownAs,
        prev: await operationHash(log[log.length - 1]),
      };
      // REQ-7-6: the registrar will never hold newKey's private half, so
      // it can't prove possession of it the way it does for a
      // server-generated rotation -- that proof of possession has to
      // come from here.
      const proof = await createProof(op, newKey.publicKey, newKey.privateKey);
      const result = await takeCustody(wardDid, session.cookie, op, proof);
      if (!result.accepted) throw new Error(result.reason);
      console.log(`${wardDid} now holds its key${opts.newKey ? "" : ` (saved as "${label}")`}. This registrar can no longer sign on its behalf.`);
    });
}
