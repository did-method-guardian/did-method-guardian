import { Command } from "commander";
import { anchorOf, createProof, generateKeypair, operationHash, parseDid, sortProofs, verifyLog } from "@did-guardian/lib";
import type { AcceptWardOp, AddGuardianOp, CreateOp, DeactivateOp, Did, Entry, UpdateOp } from "@did-guardian/lib";
import { confirmAdopt, confirmKeyIsCurrent, fetchLog, fetchPendingStatus, proposeAdopt, submitOperation } from "../registrar-client.js";
import { loadKey, saveKey, type StoredKey } from "../keystore.js";
import { loadSession } from "../state.js";
import { confirmYesNo as confirm } from "../confirm.js";

async function currentState(did: Did) {
  const log = await fetchLog(did);
  if (log.length === 0) throw new Error(`no operations found for ${did} -- is it registered?`);
  const verified = await verifyLog(did, log);
  if (verified.result !== "valid") throw new Error(`${did}'s own log does not verify: ${verified.reason}`);
  return { log, state: verified.state! };
}

async function printOrSubmit(did: Did, op: UpdateOp | DeactivateOp, submit?: boolean): Promise<void> {
  console.log(JSON.stringify(op, null, 2));
  if (!submit) {
    console.log("");
    console.log("Not submitted -- pass --submit to send this to the registrar.");
    return;
  }
  const result = await submitOperation(did, op);
  console.log("");
  if (result.accepted) {
    console.log("Submitted and accepted.");
  } else {
    console.log(`Rejected: ${result.reason}`);
    console.log('If this needs more than one guardian\'s approval, build and sign it the same way, then use "did-guardian operation propose"/"did-guardian operation sign" to collect every required proof.');
  }
}

export function registerGuardianCommand(program: Command): void {
  const guardian = program.command("guardian").description("add, recover with, or deactivate via a guardian relationship");

  guardian
    .command("adopt <ward-did>")
    .description("step 1 of adopt: log in as the incoming guardian first (\"did-guardian login\"), then accept a still registrar-held ward -- the ward must separately confirm with \"guardian confirm-adopt\"")
    .action(async (wardDid: Did) => {
      const session = loadSession();
      const { pendingId } = await proposeAdopt(wardDid, session.cookie);
      console.log(`${session.did} has accepted ${wardDid} as its own ward.`);
      console.log("");
      console.log(`Waiting on ${wardDid}'s own approval to finish adding ${session.did} as its guardian -- whoever controls ${wardDid} should now log in as it and run:`);
      console.log(`  did-guardian guardian confirm-adopt ${wardDid} ${pendingId}`);
    });

  guardian
    .command("confirm-adopt <ward-did> <pending-id>")
    .description("step 2 of adopt: log in as the ward first, then finish adding the guardian that already accepted it in step 1")
    .option("-y, --yes", "confirm without asking")
    .action(async (wardDid: Did, pendingId: string, opts: { yes?: boolean }) => {
      const session = loadSession();
      if (session.did !== wardDid) {
        throw new Error(`logged in as ${session.did}, not ${wardDid} -- run "did-guardian login ${wardDid} --login-secret <secret>" first.`);
      }

      // F2 (confused deputy), corrected per review: /propose has no
      // auth gate, so a pending id someone hands you could be anything
      // targeting your own DID. The server itself already refuses to
      // sign anything here but a genuine addGuardian for a real,
      // mutual guardian -- but a genuine guardian request can still be
      // from a guardian you never meant to pick (acceptWard is
      // one-sided: anyone can genuinely consent to guard you without
      // your cooperation, then propose themselves this way). So the
      // one thing that actually matters here is showing WHICH
      // guardian this adds, explicitly, not just dumping the raw
      // operation -- and confirming against the server's own current
      // digest for it, so a stale confirmation can't slip through.
      const { domain } = parseDid(wardDid);
      const status = await fetchPendingStatus(domain, pendingId);
      const op = status.operation as unknown as { type?: string; entry?: { did?: string } };
      if (op.type !== "addGuardian" || !op.entry?.did) {
        throw new Error(`this pending operation is a "${op.type}", not a guardian request -- confirm-adopt only ever confirms an addGuardian. Refusing to confirm it.`);
      }
      console.log(`This will add ${op.entry.did} as a guardian of ${wardDid}.`);
      console.log("");
      console.log("Full operation:");
      console.log(JSON.stringify(status.operation, null, 2));
      console.log("");
      if (!(await confirm(`Add ${op.entry.did} as your guardian?`, opts.yes))) {
        console.log("Not confirmed.");
        process.exitCode = 1;
        return;
      }

      const result = await confirmAdopt(wardDid, session.cookie, pendingId, status.digest);
      if (!result.accepted) process.exitCode = 1;
      console.log(result.accepted ? `Done -- ${wardDid} now has ${op.entry.did} as a guardian.` : `Rejected: ${result.reason}`);
    });

  guardian
    .command("add <ward-did> <guardian-did>")
    .description("add the first guardian to a guardian-less, self-held ward -- needs both parties' keys locally (see \"create\"/\"key take-custody\"); for a still registrar-held ward, use \"guardian adopt\"/\"guardian confirm-adopt\" instead")
    .requiredOption("--ward-key <label>", "the ward's saved key")
    .requiredOption("--guardian-key <label>", "the incoming guardian's saved key")
    .option("--keychain", "look up both keys in the OS keychain instead of local files")
    .action(async (wardDid: Did, guardianDid: Did, opts: { wardKey: string; guardianKey: string; keychain?: boolean }) => {
      const { state: wardState } = await currentState(wardDid);
      if (wardState.guardians.length > 0) {
        throw new Error(
          `${wardDid} already has ${wardState.guardians.length} guardian(s) -- this command only handles the zero-to-one case. Adding to a non-empty guardian set needs every current guardian's own approval too -- see "did-guardian operation propose".`,
        );
      }
      const wardKey = await loadKey(opts.wardKey, opts);
      const guardianKey = await loadKey(opts.guardianKey, opts);
      await confirmKeyIsCurrent(wardDid, wardKey.publicKey);
      await confirmKeyIsCurrent(guardianDid, guardianKey.publicKey);

      // Step 1: the guardian accepts the ward into its own log first --
      // REQ-7-6's addGuardian approval needs this to already be durable
      // (its hash becomes `entry.consent`) before the ward's own log can
      // reference it.
      const { log: guardianLog, state: guardianState } = await currentState(guardianDid);
      const guardianAnchor = await anchorOf(guardianLog[0] as CreateOp);
      const wardAnchor = await anchorOf((await currentState(wardDid)).log[0] as CreateOp);
      const acceptWardBase: Omit<AcceptWardOp, "proof"> = {
        type: "acceptWard",
        ward: { did: wardDid, anchor: wardAnchor },
        prev: await operationHash(guardianLog[guardianLog.length - 1]),
      };
      const acceptProof = await createProof(acceptWardBase, guardianKey.publicKey, guardianKey.privateKey);
      const acceptResult = await submitOperation(guardianDid, { ...acceptWardBase, proof: [acceptProof] });
      if (!acceptResult.accepted) throw new Error(`${guardianDid} could not accept ${wardDid} as a ward: ${acceptResult.reason}`);
      const consent = await operationHash(acceptResult.operation!);

      // Step 2: the ward adds the guardian's entry, needing both the
      // guardian's own key (proof of possession) and the ward's own
      // current key.
      const entry: Entry = { did: guardianDid, anchor: guardianAnchor, keys: guardianState.keys, consent };
      const { log: wardLog } = await currentState(wardDid);
      const addGuardianBase: Omit<AddGuardianOp, "proof"> = { type: "addGuardian", entry, prev: await operationHash(wardLog[wardLog.length - 1]) };
      const entryProof = await createProof(addGuardianBase, guardianKey.publicKey, guardianKey.privateKey);
      const wardProof = await createProof(addGuardianBase, wardKey.publicKey, wardKey.privateKey);
      const op = { ...addGuardianBase, proof: sortProofs([entryProof, wardProof]) };
      const result = await submitOperation(wardDid, op);
      console.log(result.accepted ? `${guardianDid} is now a guardian of ${wardDid}.` : `Rejected: ${result.reason}`);
    });

  guardian
    .command("recover <ward-did> <guardian-did>")
    .description("guardian-initiated key rotation (an update, approved via policy.recovery) -- replaces the ward's key, never needs the ward's own key")
    .requiredOption("--guardian-key <label>", "the signing guardian's saved key")
    .option("--keychain", "look up the guardian key in the OS keychain instead of a local file")
    .option("--new-key <label>", "an existing saved key to install as the ward's new key (default: generate and save a fresh one under \"<ward-did>-recovered-<timestamp>\")")
    .option("--submit", "actually submit the signed operation to the registrar (default: print it only)")
    .option("--force", "overwrite an existing saved key under the generated default label, if one is somehow already there")
    .action(async (wardDid: Did, guardianDid: Did, opts: { guardianKey: string; keychain?: boolean; newKey?: string; submit?: boolean; force?: boolean }) => {
      const { log, state } = await currentState(wardDid);
      const guardianKey = await loadKey(opts.guardianKey, opts);
      await confirmKeyIsCurrent(guardianDid, guardianKey.publicKey);
      let newKey: StoredKey;
      if (opts.newKey) {
        newKey = await loadKey(opts.newKey, opts);
      } else if (opts.submit) {
        // C-1 (audit): generating AND SAVING a new key only happens
        // when this is actually about to be submitted -- a print-only
        // preview used to do both unconditionally, so re-running it
        // (to look at the draft again, say) silently replaced whatever
        // key an earlier run had already saved under the same label.
        const label = `${wardDid}-recovered-${Date.now().toString(36)}`;
        newKey = await generateKeypair();
        await saveKey(label, newKey, opts);
        console.log(`Generated and saved a new key as "${label}".`);
        console.log(`Public key (Multikey): ${newKey.publicKey}`);
        console.log("");
      } else {
        newKey = await generateKeypair();
        console.log("Generated a throwaway key for this preview only -- it was NOT saved. Re-run with --submit to generate and save a real one, or pass --new-key to use one you already have.");
        console.log("");
      }
      // An `update` replaces keys/services/alsoKnownAs wholesale --
      // services/alsoKnownAs carry over from the ward's own current
      // state unchanged.
      const base: Omit<UpdateOp, "proof"> = {
        type: "update",
        keys: [newKey.publicKey],
        services: state.services,
        alsoKnownAs: state.alsoKnownAs,
        prev: await operationHash(log[log.length - 1]),
      };
      // REQ-7-6: update requires a proof of possession for every key in
      // the new `keys`, as well as the guardian's own approval -- the
      // new key signs for itself here, same as take-custody.
      const guardianProof = await createProof(base, guardianKey.publicKey, guardianKey.privateKey);
      const newKeyProof = await createProof(base, newKey.publicKey, newKey.privateKey);
      await printOrSubmit(wardDid, { ...base, proof: sortProofs([guardianProof, newKeyProof]) }, opts.submit);
    });

  guardian
    .command("deactivate <ward-did> <guardian-did>")
    .description("guardian-signed deactivation (approved via policy.deactivation) -- permanent, never reversible")
    .requiredOption("--guardian-key <label>", "the signing guardian's saved key")
    .option("--keychain", "look up the guardian key in the OS keychain instead of a local file")
    .option("--submit", "actually submit the signed operation to the registrar (default: print it only)")
    .option("-y, --yes", "skip the confirmation prompt when submitting")
    .action(async (wardDid: Did, guardianDid: Did, opts: { guardianKey: string; keychain?: boolean; submit?: boolean; yes?: boolean }) => {
      const { log } = await currentState(wardDid);
      const guardianKey = await loadKey(opts.guardianKey, opts);
      await confirmKeyIsCurrent(guardianDid, guardianKey.publicKey);
      const base: Omit<DeactivateOp, "proof"> = { type: "deactivate", prev: await operationHash(log[log.length - 1]) };
      const proof = await createProof(base, guardianKey.publicKey, guardianKey.privateKey);
      if (opts.submit) {
        const proceed = await confirm(`This permanently deactivates ${wardDid}. Continue?`, opts.yes);
        if (!proceed) {
          console.log("Cancelled -- nothing was submitted.");
          return;
        }
      }
      await printOrSubmit(wardDid, { ...base, proof: [proof] }, opts.submit);
    });
}
