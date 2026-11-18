import { Command } from "commander";
import { generateKeypair, signCustodialCreate, cidFor, spkiToMultikey } from "@did-guardian/lib";
import { saveKey, loadKey } from "../keystore.js";

export function registerCreateCommand(program: Command): void {
  program
    .command("create <name>")
    .description("build a self-held genesis operation offline -- no network, no registrar involved. The result is a DRAFT: nothing makes \"did:guardian:<domain>:<name>\" real until some registrar actually accepts it (see issue #4 -- no registrar accepts a bring-your-own-key genesis yet)")
    .requiredOption("--domain <domain>", "the domain this identity would live under once a registrar accepts it")
    .option("--key <label>", "an existing saved key to use (default: generate and save a fresh one under <name>)")
    .option("--keychain", "save the new key to the OS keychain instead of a local file")
    .action(async (name: string, opts: { domain: string; key?: string; keychain?: boolean }) => {
      const label = opts.key ?? name;
      const key = opts.key ? await loadKey(label, opts) : await generateKeypair();
      if (!opts.key) await saveKey(label, key, opts);

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
        },
        {},
      );
      const anchor = await cidFor(genesis);
      const did = `did:guardian:${opts.domain}:${name}`;

      console.log(`DRAFT -- ${did}`);
      console.log(`Anchor (genesis CID): ${anchor}`);
      console.log(`Public key (Multikey): ${spkiToMultikey(key.publicKey)}`);
      console.log("");
      console.log("This genesis operation carries no registrar attestation (REQ-7.1-5), so no conformant registrar will accept it as-is:");
      console.log(JSON.stringify({ cid: anchor, op: genesis }, null, 2));
      console.log("");
      console.log(`This identity doesn't exist anywhere yet -- it's a draft until a registrar attests it. See https://guardianspec.org/docs/how-to/ and issue #4 for the current state of self-held-key genesis.`);
    });
}
