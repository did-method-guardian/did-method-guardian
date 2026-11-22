import { Command } from "commander";
import { anchorOf, createProof, DEFAULT_POLICY, generateKeypair } from "@did-guardian/lib";
import type { CreateOp } from "@did-guardian/lib";
import { saveKey, loadKey } from "../keystore.js";
import { submitOperation } from "../registrar-client.js";

export function registerCreateCommand(program: Command): void {
  program
    .command("create <name>")
    .description("build a self-held create operation -- with --registrar, publishes it for real; with --domain alone, stays fully offline, no network at all")
    .option("--domain <domain>", "build offline only -- the domain this identity would live under once something accepts it, with no network call made here")
    .option("--registrar <domain>", "actually submit the signed create to this domain's .../operations -- this identity is live the moment it's accepted, no further step needed")
    .option("--key <label>", "an existing saved key to use (default: generate and save a fresh one under <name>)")
    .option("--keychain", "save the new key to the OS keychain instead of a local file")
    .action(async (name: string, opts: { domain?: string; registrar?: string; key?: string; keychain?: boolean }) => {
      const domain = opts.registrar ?? opts.domain;
      if (!domain) throw new Error("one of --domain (offline draft) or --registrar <domain> (publish) is required");
      if (opts.registrar && opts.domain && opts.registrar !== opts.domain) throw new Error("--domain and --registrar name different domains -- this identity can only live under one");

      const label = opts.key ?? name;
      const key = opts.key ? await loadKey(label, opts) : await generateKeypair();
      if (!opts.key) await saveKey(label, key, opts);

      const did = `did:guardian:${domain}:${name}` as const;
      // No initial guardian here, deliberately: REQ-7-6 requires every
      // guardian's own key to co-sign a create that names it, which
      // means that guardian must already have durably accepted this
      // ward in its own log first (an acceptWard naming this create's
      // own anchor) -- not something a single offline command can do
      // for a guardian it doesn't already control. Add one afterward
      // with "guardian add" (both keys held locally) or "guardian
      // adopt"/"guardian confirm-adopt" (a registrar-held ward).
      const createOp: Omit<CreateOp, "proof" | "attestation"> = {
        type: "create",
        did,
        keys: [key.publicKey],
        guardians: [],
        successor: null,
        policy: DEFAULT_POLICY,
        services: [],
        alsoKnownAs: [],
        prev: null,
      };
      const proof = await createProof(createOp, key.publicKey, key.privateKey);
      const signed: CreateOp = { ...createOp, proof: [proof] };

      if (opts.registrar) {
        const result = await submitOperation(did, signed);
        if (!result.accepted) throw new Error(`"${name}" was not accepted by ${domain}: ${result.reason}`);
        console.log(`${did} is live.`);
        console.log(`Public key (Multikey): ${key.publicKey}`);
        return;
      }

      const anchor = await anchorOf(signed);
      console.log(`DRAFT -- ${did}`);
      console.log(`Anchor (REQ-5-7): ${anchor}`);
      console.log(`Public key (Multikey): ${key.publicKey}`);
      console.log("");
      console.log("This create operation carries no registrar attestation (REQ-7-7), so no conformant registrar will accept it as-is:");
      console.log(JSON.stringify(signed, null, 2));
      console.log("");
      console.log(`Re-run with --registrar ${domain} to actually publish it -- this identity doesn't exist anywhere until some registrar accepts it.`);
    });
}
