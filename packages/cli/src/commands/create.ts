import { Command } from "commander";
import { generateKeypair, signCustodialCreate, cidFor, spkiToMultikey } from "@did-guardian/lib";
import { saveKey, loadKey } from "../keystore.js";
import { submitOperation } from "../registrar-client.js";

export function registerCreateCommand(program: Command): void {
  program
    .command("create <name>")
    .description("build a self-held genesis operation (v0.3, REQ-8-2: genesis is part of the method now, not a registrar convenience) -- with --registrar, publishes it for real; with --domain alone, stays fully offline, no network at all")
    .option("--domain <domain>", "build offline only -- the domain this identity would live under once something accepts it, with no network call made here")
    .option("--registrar <domain>", "actually submit the signed genesis to this domain's .../operations -- this identity is live the moment it's accepted, no further step needed")
    .option("--key <label>", "an existing saved key to use (default: generate and save a fresh one under <name>)")
    .option("--keychain", "save the new key to the OS keychain instead of a local file")
    .action(async (name: string, opts: { domain?: string; registrar?: string; key?: string; keychain?: boolean }) => {
      const domain = opts.registrar ?? opts.domain;
      if (!domain) throw new Error("one of --domain (offline draft) or --registrar <domain> (publish) is required");
      if (opts.registrar && opts.domain && opts.registrar !== opts.domain) throw new Error("--domain and --registrar name different domains -- this identity can only live under one");

      const label = opts.key ?? name;
      const key = opts.key ? await loadKey(label, opts) : await generateKeypair();
      if (!opts.key) await saveKey(label, key, opts);

      const did = `did:guardian:${domain}:${name}`;
      const genesis = await signCustodialCreate(
        {
          type: "custodial_create",
          name,
          operationalKeys: [key.publicKey],
          verificationMethods: { "key-1": key.publicKey },
          services: {},
          outgoing: [],
          incoming: [],
          prev: null,
          creator: did, // self-initiated -- nobody else is party to a bring-your-own-key genesis built entirely offline
        },
        {},
        { [key.publicKey]: key.privateKey },
      );
      if (opts.registrar) {
        const result = await submitOperation(did, genesis);
        if (!result.accepted) throw new Error(`"${name}" was not accepted by ${domain}: ${result.reason}`);
        console.log(`${did} is live.`);
        // The registrar's reported cid, not one computed here -- its added
        // attestation is part of the signed content, so the anchor only
        // exists once that's attached (see submitOperation's comment in
        // registrar-client.ts).
        console.log(`Anchor (genesis CID): ${result.cid}`);
        console.log(`Public key (Multikey): ${spkiToMultikey(key.publicKey)}`);
        return;
      }

      // No registrar attestation yet, so this draft's cid will change the
      // moment one accepts it -- shown only to let this draft be inspected
      // or diffed locally, never to be pinned as a real anchor.
      const anchor = await cidFor(genesis);
      console.log(`DRAFT -- ${did}`);
      console.log(`Draft CID (changes once a registrar attests it): ${anchor}`);
      console.log(`Public key (Multikey): ${spkiToMultikey(key.publicKey)}`);
      console.log("");
      console.log("This genesis operation carries no registrar attestation (REQ-7.1-5), so no conformant registrar will accept it as-is:");
      console.log(JSON.stringify({ cid: anchor, op: genesis }, null, 2));
      console.log("");
      console.log(`Re-run with --registrar ${domain} to actually publish it -- this identity doesn't exist anywhere until some registrar accepts it.`);
    });
}
