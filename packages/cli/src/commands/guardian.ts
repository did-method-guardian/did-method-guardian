import { createInterface } from "node:readline/promises";
import { Command } from "commander";
import {
  generateKeypair,
  replay,
  signCustodialRotateByGuardians,
  signCustodialTombstone,
  signGuardianAdd,
  spkiToMultikey,
} from "@did-guardian/lib";
import type { Did, GuardianAddOp, CustodialRotateOp, CustodialTombstoneOp } from "@did-guardian/lib";
import { adopt, fetchLog, submitOperation } from "../registrar-client.js";
import { loadKey, saveKey, type StoredKey } from "../keystore.js";
import { loadSession } from "../state.js";

async function currentHead(did: Did): Promise<{ headCid: string; guardianCount: number }> {
  const log = await fetchLog(did);
  if (log.length === 0) throw new Error(`no operations found for ${did} -- is it registered?`);
  const state = replay(did, log);
  return { headCid: log[log.length - 1].cid, guardianCount: state.guardians.length };
}

/** REQ-12-4: an incoming guardian's genesis CID, fetched live if resolvable. Never throws -- a guardian that's still a draft (created offline, not yet accepted anywhere) just doesn't get an anchor recorded, same as the spec's SHOULD rather than MUST. */
async function bestEffortAnchor(did: Did): Promise<string | undefined> {
  try {
    const log = await fetchLog(did);
    return log[0]?.cid;
  } catch {
    return undefined;
  }
}

async function confirm(prompt: string, assumeYes?: boolean): Promise<boolean> {
  if (assumeYes) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await rl.question(`${prompt} [y/N] `);
  rl.close();
  return answer.trim().toLowerCase() === "y";
}

async function printOrSubmit(did: Did, op: GuardianAddOp | CustodialRotateOp | CustodialTombstoneOp, submit?: boolean): Promise<void> {
  console.log(JSON.stringify(op, null, 2));
  if (!submit) {
    console.log("");
    console.log("Not submitted -- pass --submit to send this to the registrar.");
    return;
  }
  const result = await submitOperation(did, op);
  console.log("");
  console.log(result.accepted ? "Submitted and accepted." : `Rejected: ${result.reason}`);
}

export function registerGuardianCommand(program: Command): void {
  const guardian = program.command("guardian").description("add, recover with, or tombstone via a guardian relationship");

  guardian
    .command("adopt <ward-did>")
    .description("session-based zero-to-one guardian_add for a still registrar-held ward -- log in as the incoming guardian first (\"did-guardian login\"), the registrar signs both halves")
    .action(async (wardDid: Did) => {
      const session = loadSession();
      const result = await adopt(wardDid, session.cookie);
      console.log(result.accepted ? `${session.did} is now a guardian of ${wardDid}.` : `Rejected: ${result.reason}`);
    });

  guardian
    .command("add <ward-did> <guardian-did>")
    .description("add the first guardian to a guardian-less ward (REQ-7.2-5) via local signing -- needs both parties to hold a key directly (see \"create\"/\"key take-custody\"); for a still registrar-held ward, use \"guardian adopt\" instead")
    .requiredOption("--ward-key <label>", "the ward's saved key")
    .requiredOption("--guardian-key <label>", "the incoming guardian's saved key")
    .option("--keychain", "look up both keys in the OS keychain instead of local files")
    .option("--guardian-anchor <cid>", "the incoming guardian's genesis CID (REQ-12-4) -- fetched automatically if the guardian is live-resolvable, otherwise omitted")
    .option("--submit", "actually submit the signed operation to the registrar (default: print it only)")
    .action(async (wardDid: Did, guardianDid: Did, opts: { wardKey: string; guardianKey: string; keychain?: boolean; guardianAnchor?: string; submit?: boolean }) => {
      const { headCid, guardianCount } = await currentHead(wardDid);
      if (guardianCount > 0) {
        throw new Error(
          `${wardDid} already has ${guardianCount} guardian(s) -- this command only handles the zero-to-one case (REQ-7.2-5). Adding to a non-empty guardian set needs the asynchronous proposal flow: see https://guardianspec.org/docs/registrar/.`,
        );
      }
      const wardKey = await loadKey(opts.wardKey, opts);
      const guardianKey = await loadKey(opts.guardianKey, opts);
      const anchor = opts.guardianAnchor ?? (await bestEffortAnchor(guardianDid));
      const op = await signGuardianAdd(
        { type: "guardian_add", incoming: guardianDid, prev: headCid, anchor },
        { [guardianDid]: guardianKey.privateKey, [wardDid]: wardKey.privateKey },
        [guardianDid, wardDid],
      );
      await printOrSubmit(wardDid, op, opts.submit);
    });

  guardian
    .command("recover <ward-did> <guardian-did>")
    .description("guardian-initiated key rotation (REQ-7.2-1b) -- replaces the ward's operational key, never needs the ward's key")
    .requiredOption("--guardian-key <label>", "the signing guardian's saved key")
    .option("--keychain", "look up the guardian key in the OS keychain instead of a local file")
    .option("--new-key <label>", "an existing saved key to install as the ward's new operational key (default: generate and save a fresh one under \"<ward-did>-recovered\")")
    .option("--prev <cid>", "nullification (REQ-6-8) -- name a cid earlier than the current head to roll back a fraudulent rotation accepted less than 72h ago, instead of just rotating forward from it (default: the current head)")
    .option("--submit", "actually submit the signed operation to the registrar (default: print it only)")
    .action(async (wardDid: Did, guardianDid: Did, opts: { guardianKey: string; keychain?: boolean; newKey?: string; prev?: string; submit?: boolean }) => {
      const prev = opts.prev ?? (await currentHead(wardDid)).headCid;
      const guardianKey = await loadKey(opts.guardianKey, opts);
      let newKey: StoredKey;
      if (opts.newKey) {
        newKey = await loadKey(opts.newKey, opts);
      } else {
        const label = `${wardDid}-recovered`;
        newKey = await generateKeypair();
        await saveKey(label, newKey, opts);
        console.log(`Generated and saved a new operational key as "${label}".`);
        console.log(`Public key (Multikey): ${spkiToMultikey(newKey.publicKey)}`);
        console.log("");
      }
      const op = await signCustodialRotateByGuardians(
        {
          type: "custodial_rotate",
          operationalKeys: [newKey.publicKey],
          verificationMethods: { "key-1": newKey.publicKey },
          services: {},
          prev,
        },
        { [guardianDid]: guardianKey.privateKey },
        [guardianDid],
        { [newKey.publicKey]: newKey.privateKey },
      );
      await printOrSubmit(wardDid, op, opts.submit);
    });

  guardian
    .command("tombstone <ward-did> <guardian-did>")
    .description("guardian-signed deactivation (REQ-7.3-1) -- permanent, never reversible")
    .requiredOption("--guardian-key <label>", "the signing guardian's saved key")
    .option("--keychain", "look up the guardian key in the OS keychain instead of a local file")
    .option("--submit", "actually submit the signed operation to the registrar (default: print it only)")
    .option("-y, --yes", "skip the confirmation prompt when submitting")
    .action(async (wardDid: Did, guardianDid: Did, opts: { guardianKey: string; keychain?: boolean; submit?: boolean; yes?: boolean }) => {
      const { headCid } = await currentHead(wardDid);
      const guardianKey = await loadKey(opts.guardianKey, opts);
      const op = await signCustodialTombstone(
        { type: "custodial_tombstone", prev: headCid },
        { [guardianDid]: guardianKey.privateKey },
        [guardianDid],
      );
      if (opts.submit) {
        const proceed = await confirm(`This permanently deactivates ${wardDid}. Continue?`, opts.yes);
        if (!proceed) {
          console.log("Cancelled -- nothing was submitted.");
          return;
        }
      }
      await printOrSubmit(wardDid, op, opts.submit);
    });
}
