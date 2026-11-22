import { Command } from "commander";
import { generateKeypair, signCustodialCreate, cidFor } from "@did-guardian/lib";
import { saveKey, loadKey } from "../keystore.js";
import { submitOperation, confirmKeyIsCurrent } from "../registrar-client.js";

export function registerCreateCommand(program: Command): void {
  program
    .command("create <name>")
    .description("build a self-held genesis operation (v0.3, REQ-8-2: genesis is part of the method now, not a registrar convenience) -- with --registrar, publishes it for real; with --domain alone, stays fully offline, no network at all")
    .option("--domain <domain>", "build offline only -- the domain this identity would live under once something accepts it, with no network call made here")
    .option("--registrar <domain>", "actually submit the signed genesis to this domain's .../operations -- this identity is live the moment it's accepted, no further step needed")
    .option("--key <label>", "an existing saved key to use (default: generate and save a fresh one under <name>)")
    .option("--guardian <did>", "establish this DID as a guardian directly at genesis (REQ-7.1-1, v0.3) -- requires --guardian-key, since a guardian MUST co-sign genesis")
    .option("--guardian-key <label>", "a saved key for --guardian's DID -- only works when this is the same operator, holding both keys locally; otherwise add a guardian afterward with \"guardian add\" or \"guardian adopt\" instead")
    .option("--keychain", "save the new key to the OS keychain instead of a local file")
    .action(async (name: string, opts: { domain?: string; registrar?: string; key?: string; guardian?: string; guardianKey?: string; keychain?: boolean }) => {
      const domain = opts.registrar ?? opts.domain;
      if (!domain) throw new Error("one of --domain (offline draft) or --registrar <domain> (publish) is required");
      if (opts.registrar && opts.domain && opts.registrar !== opts.domain) throw new Error("--domain and --registrar name different domains -- this identity can only live under one");
      if (opts.guardian && !opts.guardianKey) throw new Error("--guardian requires --guardian-key -- a guardian established at genesis MUST co-sign it (REQ-7.1-1)");

      const label = opts.key ?? name;
      const key = opts.key ? await loadKey(label, opts) : await generateKeypair();
      if (!opts.key) await saveKey(label, key, opts);

      const did = `did:guardian:${domain}:${name}`;
      const incoming = opts.guardian ? [opts.guardian] : [];
      let incomingKeys: Record<string, string> = {};
      if (opts.guardian && opts.guardianKey) {
        const guardianKey = await loadKey(opts.guardianKey, opts);
        // WS-2.5 (audit): best-effort only (never throws if --guardian
        // isn't resolvable at all -- the ordinary case for a guardian
        // that's itself still an unpublished draft), but if it IS
        // resolvable, a stale local key for it should be caught here
        // rather than surfacing as a confusing rejection later.
        await confirmKeyIsCurrent(opts.guardian, guardianKey.publicKey);
        incomingKeys = { [opts.guardian]: guardianKey.privateKey };
      }
      const genesis = await signCustodialCreate(
        {
          type: "custodial_create",
          did,
          name,
          operationalKeys: [key.publicKey],
          services: {},
          outgoing: [],
          incoming,
          prev: null,
          creator: did, // self-initiated -- nobody else is party to a bring-your-own-key genesis built entirely offline
        },
        incomingKeys,
        { [key.publicKey]: key.privateKey },
      );
      if (opts.registrar) {
        const result = await submitOperation(did, genesis);
        if (!result.accepted) throw new Error(`"${name}" was not accepted by ${domain}: ${result.reason}`);
        console.log(`${did} is live.`);
        // WS-3.7 (audit): the registrar's reported cid -- which, per
        // REQ-6-4, is identical to what computing it locally from
        // `genesis` would already give, since every proof (the just-
        // added registrar attestation included) is stripped before
        // hashing. Reported here as the final, confirmed value rather
        // than recomputed locally purely as a convenience, not because
        // the attestation changes it -- it never does.
        console.log(`Anchor (final; computed without proofs, REQ-6-4): ${result.cid}`);
        console.log(`Public key (Multikey): ${key.publicKey}`);
        return;
      }

      // WS-3.7 (audit): per REQ-6-4 this cid is already final -- every
      // proof (a future registrar attestation included) is stripped
      // before hashing, so accepting this exact content elsewhere would
      // report this same value, not a different one. Still labeled DRAFT
      // because the identity itself isn't real until some registrar
      // actually accepts it (no attestation yet means no conformant
      // registrar will take it as-is), never because this cid itself is
      // provisional.
      const anchor = await cidFor(genesis);
      console.log(`DRAFT -- ${did}`);
      console.log(`Anchor (final; computed without proofs, REQ-6-4): ${anchor}`);
      console.log(`Public key (Multikey): ${key.publicKey}`);
      console.log("");
      console.log("This genesis operation carries no registrar attestation (REQ-7.1-5), so no conformant registrar will accept it as-is:");
      console.log(JSON.stringify({ cid: anchor, op: genesis }, null, 2));
      console.log("");
      console.log(`Re-run with --registrar ${domain} to actually publish it -- this identity doesn't exist anywhere until some registrar accepts it.`);
    });
}
