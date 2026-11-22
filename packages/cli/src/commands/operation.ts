// The generic multi-signer path, for any operation whose required
// approvals a single local signature can't satisfy (e.g. removeGuardian
// by vote of the other guardians, setPolicy, updateGuardian, or any
// operation under a policy requiring more than one guardian). Build and
// sign the operation yourself (the same shape the dedicated "guardian"
// commands build with --submit omitted), then propose it; every other
// required signer runs "operation sign" against the same pending id.
import { readFileSync } from "node:fs";
import { Command } from "commander";
import { createProof } from "@did-guardian/lib";
import type { Did, Operation } from "@did-guardian/lib";
import { loadKey } from "../keystore.js";
import { contributeProof, fetchPendingStatus, proposeOperation } from "../registrar-client.js";

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
    .action(async (pendingId: string, opts: { registrar: string; key: string; keychain?: boolean }) => {
      const status = await fetchPendingStatus(opts.registrar, pendingId);
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
      console.log(`Proofs collected so far: ${status.proofs.length}`);
      console.log(`Expires: ${status.expiresAt}`);
      console.log("");
      console.log(JSON.stringify(status.operation, null, 2));
    });
}
