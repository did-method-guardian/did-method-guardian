import { Command } from "commander";
import { anchorOf, createProof, DEFAULT_POLICY, generateKeypair, operationHash, sortProofs, verifyLog } from "@did-guardian/lib";
import type { AcceptWardOp, CreateOp, Entry } from "@did-guardian/lib";
import { saveKey, loadKey } from "../keystore.js";
import { fetchLog, submitOperation } from "../registrar-client.js";

export function registerCreateCommand(program: Command): void {
  program
    .command("create <name>")
    .description("build a self-held create operation -- with --registrar, publishes it for real; with --domain alone, stays fully offline, no network at all")
    .option("--domain <domain>", "build offline only -- the domain this identity would live under once something accepts it, with no network call made here")
    .option("--registrar <domain>", "actually submit the signed create to this domain's .../operations -- this identity is live the moment it's accepted, no further step needed")
    .option("--key <label>", "an existing saved key to use (default: generate and save a fresh one under <domain>:<name>)")
    .option("--keychain", "save the new key to the OS keychain instead of a local file")
    .option("--force", "overwrite an existing saved key under the generated default label, if this name was already used locally")
    .option(
      "--guardian <did>",
      "name an already-existing, single-key guardian at creation (D3, spec r7/r7b) -- needs --registrar and --guardian-key, both keys held locally; a multi-key guardian or a brand-new one needs \"guardian add\" afterward instead",
    )
    .option("--guardian-key <label>", "the guardian's own saved key label, for --guardian")
    .action(
      async (
        name: string,
        opts: { domain?: string; registrar?: string; key?: string; keychain?: boolean; force?: boolean; guardian?: string; guardianKey?: string },
      ) => {
        const domain = opts.registrar ?? opts.domain;
        if (!domain) throw new Error("one of --domain (offline draft) or --registrar <domain> (publish) is required");
        if (opts.registrar && opts.domain && opts.registrar !== opts.domain) throw new Error("--domain and --registrar name different domains -- this identity can only live under one");
        if (opts.guardian && !opts.registrar) {
          throw new Error("--guardian needs --registrar -- its own acceptWard must be durably submitted (REQ-10-7's standing check) before this create can reference it");
        }
        if (opts.guardian && !opts.guardianKey) throw new Error("--guardian needs --guardian-key (the guardian's own saved key label)");

        // C-1 (audit): the default label used to be the bare name alone,
        // so `create alice --domain other.test` could silently replace
        // an unrelated, already-live `alice` key saved under a different
        // domain. Qualifying it by domain doesn't fully prevent a
        // collision (the same name really can be re-created under the
        // same domain by mistake) -- saveKey's own overwrite check is
        // what actually prevents that; this just makes an accidental
        // collision far less likely in the first place.
        const label = opts.key ?? `${domain}:${name}`;
        const key = opts.key ? await loadKey(label, opts) : await generateKeypair();
        if (!opts.key) await saveKey(label, key, opts);

        const did = `did:guardian:${domain}:${name}` as const;

        // D3 (spec r7/r7b): naming a guardian at creation is now
        // possible when the caller holds BOTH keys -- but it's still a
        // two-step dance under the hood (REQ-10-7's own standing check
        // needs the guardian's acceptWard already durable before this
        // create can reference its hash), same shape as guardian.ts's
        // own addFirstGuardian, just against a create instead of an
        // addGuardian. REQ-5-7's anchor excludes guardians/proof/
        // attestation, so it's computable from createBase alone, before
        // guardians is ever filled in.
        let guardianEntry: Entry | undefined;
        if (opts.guardian && opts.guardianKey) {
          const guardianDid = opts.guardian as `did:guardian:${string}`;
          const guardianKey = await loadKey(opts.guardianKey, {});
          const guardianLog = await fetchLog(guardianDid);
          if (guardianLog.length === 0) throw new Error(`no such guardian identity: ${guardianDid}`);
          const guardianVerified = await verifyLog(guardianDid, guardianLog);
          if (guardianVerified.result !== "valid") throw new Error(`${guardianDid}'s own log does not verify: ${guardianVerified.reason}`);
          const guardianState = guardianVerified.state!;
          if (guardianState.keys.length !== 1 || guardianState.keys[0] !== guardianKey.publicKey) {
            throw new Error(`${guardianDid} currently holds ${guardianState.keys.length} key(s), not exactly the one key given here -- use "guardian add" after creating instead, with every one of its current keys.`);
          }
          const guardianAnchor = await anchorOf(guardianLog[0] as CreateOp);

          const createBaseForAnchor: Omit<CreateOp, "proof" | "attestation" | "guardians"> = {
            type: "create",
            did,
            keys: [key.publicKey],
            successor: null,
            policy: DEFAULT_POLICY,
            services: [],
            alsoKnownAs: [],
            prev: null,
          };
          const wardAnchor = await anchorOf(createBaseForAnchor as unknown as CreateOp);

          const acceptWardBase: Omit<AcceptWardOp, "proof"> = {
            type: "acceptWard",
            ward: { did, anchor: wardAnchor },
            prev: await operationHash(guardianLog[guardianLog.length - 1]),
          };
          const acceptProof = await createProof(acceptWardBase, guardianKey.publicKey, guardianKey.privateKey);
          const acceptResult = await submitOperation(guardianDid, { ...acceptWardBase, proof: [acceptProof] });
          if (!acceptResult.accepted) throw new Error(`${guardianDid} could not accept ${did} as a ward: ${acceptResult.reason}`);
          const consent = await operationHash(acceptResult.operation!);

          guardianEntry = { did: guardianDid, anchor: guardianAnchor, keys: guardianState.keys, consent };
        }

        // No initial guardian, unless --guardian/--guardian-key built
        // one above -- otherwise add one afterward with "guardian add"
        // (both keys held locally) or "guardian adopt"/"guardian
        // confirm-adopt" (a registrar-held ward).
        const createOp: Omit<CreateOp, "proof" | "attestation"> = {
          type: "create",
          did,
          keys: [key.publicKey],
          guardians: guardianEntry ? [guardianEntry] : [],
          successor: null,
          policy: DEFAULT_POLICY,
          services: [],
          alsoKnownAs: [],
          prev: null,
        };
        const wardProof = await createProof(createOp, key.publicKey, key.privateKey);
        const proofs = [wardProof];
        if (opts.guardian && opts.guardianKey) {
          const guardianKey = await loadKey(opts.guardianKey, {});
          proofs.push(await createProof(createOp, guardianKey.publicKey, guardianKey.privateKey));
        }
        const signed: CreateOp = { ...createOp, proof: sortProofs(proofs) };

        if (opts.registrar) {
          const result = await submitOperation(did, signed);
          if (!result.accepted) throw new Error(`"${name}" was not accepted by ${domain}: ${result.reason}`);
          console.log(`${did} is live.`);
          console.log(`Public key (Multikey): ${key.publicKey}`);
          if (guardianEntry) console.log(`Guardian: ${guardianEntry.did}`);
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
      },
    );
}
