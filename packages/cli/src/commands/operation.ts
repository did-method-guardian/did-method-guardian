// The generic multi-signer path, for any operation whose required
// approvals a single local signature can't satisfy (e.g. removeGuardian
// by vote of the other guardians, setPolicy, updateGuardian, or any
// operation under a policy requiring more than one guardian). Build and
// sign the operation yourself (the same shape the dedicated "guardian"
// commands build with --submit omitted), then propose it; every other
// required signer runs "operation sign" against the same pending id.
import { readFileSync } from "node:fs";
import { Command } from "commander";
import { createProof, operationHash, parseDid, verifyLog } from "@did-guardian/lib";
import type { Did, Operation } from "@did-guardian/lib";
import { loadKey } from "../keystore.js";
import { confirmYesNo } from "../confirm.js";
import { contributeProof, fetchLog, fetchPendingStatus, proposeOperation } from "../registrar-client.js";

function reportOutcome(outcome: { status: string; id?: string; operation?: Operation; reason?: string }): void {
  if (outcome.status === "finalized") {
    console.log("Finalized and accepted.");
    return;
  }
  console.log(`Collecting -- not yet enough approvals (${outcome.reason ?? "waiting on more signers"}).`);
  if (outcome.id) {
    console.log(`Pending id: ${outcome.id}`);
    console.log(`Every other required signer runs: did-guardian operation sign ${outcome.id} --registrar <domain> --key <label>`);
  }
}

export function registerOperationCommand(program: Command): void {
  const operation = program.command("operation").description("the generic multi-signer path for an operation one signature alone can't satisfy");

  operation
    .command("propose <did>")
    .description("sign and propose an operation (read from a JSON file, without its own proof) -- finalizes immediately if your signature alone is already enough")
    .requiredOption("--file <path>", "a JSON file with the operation's own fields, without `proof`")
    .requiredOption("--key <label>", "your own saved key to sign with")
    .option("--keychain", "look up the key in the OS keychain instead of a local file")
    .action(async (did: Did, opts: { file: string; key: string; keychain?: boolean }) => {
      const body = JSON.parse(readFileSync(opts.file, "utf8")) as Omit<Operation, "proof">;
      const key = await loadKey(opts.key, opts);
      const proof = await createProof(body, key.publicKey, key.privateKey);
      const outcome = await proposeOperation(did, body, proof);
      reportOutcome(outcome);
    });

  operation
    .command("sign <pending-id>")
    .description("add your own signature to a proposal already collecting on some registrar")
    .requiredOption("--registrar <domain>", "the registrar's domain the proposal lives on")
    .requiredOption("--key <label>", "your own saved key to sign with")
    .option("--keychain", "look up the key in the OS keychain instead of a local file")
    .option("-y, --yes", "sign without asking for confirmation")
    .action(async (pendingId: string, opts: { registrar: string; key: string; keychain?: boolean; yes?: boolean }) => {
      const status = await fetchPendingStatus(opts.registrar, pendingId);

      // F2 (confused deputy): nothing stops whoever proposed this from
      // disguising its true effect -- a committer trusts what it SEES,
      // never a type label alone, so this always shows the DID and the
      // full operation before producing a signature for it.
      const targetDomain = parseDid(status.did).domain;
      if (targetDomain !== opts.registrar) {
        throw new Error(`this proposal's own DID (${status.did}) is on ${targetDomain}, not ${opts.registrar} -- refusing to sign a proposal that doesn't match the registrar you asked for`);
      }
      // REQ-5-17 (r7d, audit r4): a hostile pending-op server can label
      // ANY operation with ANY did it likes -- a bare prev-hash
      // comparison against whatever that same server serves back for
      // "the DID's log" proves nothing, since the attacker controls
      // that response too (it can simply echo back an operation that
      // happens to hash to the right value, with no real log behind
      // it at all). Fetching the log from the DID's own domain and
      // running verifyLog against it is what actually catches that:
      // a forged DID's log can never genuinely verify with someone
      // else's operation grafted onto its end, since verifyLog's own
      // first-operation check requires `did` to match exactly. A
      // mismatch here is a hard refusal, not a warning -- and never
      // skippable by -y, which only ever skips the confirmation
      // prompt below, not this check. `create` is exempt (REQ-5-17
      // itself only applies to every other operation type): there is
      // no prior log to verify yet.
      if (status.operation.type !== "create") {
        const log = await fetchLog(status.did);
        const verified = await verifyLog(status.did, log);
        const currentHead = log.length > 0 ? await operationHash(log[log.length - 1]) : null;
        const prevField = (status.operation as { prev?: string | null }).prev;
        if (verified.result !== "valid" || prevField !== currentHead) {
          throw new Error(
            `REQ-5-17: refusing to sign -- ${status.did}'s own log ${verified.result !== "valid" ? `does not verify (${verified.reason})` : "does not end where this proposal's own prev claims"} (prev: ${prevField}, current head: ${currentHead ?? "no log yet"})`,
          );
        }
      }

      console.log(`This will sign, as you, the following operation for ${status.did}:`);
      console.log("");
      console.log(JSON.stringify(status.operation, null, 2));
      console.log("");
      if (!(await confirmYesNo("Sign this exact operation?", opts.yes))) {
        console.log("Not signed.");
        process.exitCode = 1;
        return;
      }

      const key = await loadKey(opts.key, opts);
      const proof = await createProof(status.operation, key.publicKey, key.privateKey);
      const outcome = await contributeProof(opts.registrar, pendingId, proof);
      reportOutcome(outcome);
    });

  operation
    .command("status <pending-id>")
    .description("show a proposal's own operation and how many proofs it's collected so far")
    .requiredOption("--registrar <domain>", "the registrar's domain the proposal lives on")
    .action(async (pendingId: string, opts: { registrar: string }) => {
      const status = await fetchPendingStatus(opts.registrar, pendingId);
      console.log(`For: ${status.did}`);
      console.log(`Proofs collected so far: ${status.proofsCollected}`);
      console.log(`Expires: ${status.expiresAt}`);
      console.log("");
      console.log(JSON.stringify(status.operation, null, 2));
    });
}
