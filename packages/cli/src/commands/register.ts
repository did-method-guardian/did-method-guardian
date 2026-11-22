import { Command } from "commander";
import { registerWard } from "../registrar-client.js";

export function registerRegisterCommand(program: Command): void {
  program
    .command("register <name>")
    .description("create a new, guardian-less identity on a registrar")
    .requiredOption("--registrar <domain>", "the registrar's domain, e.g. guardianspec.org")
    .option("--json", "print the raw response as JSON")
    .action(async (name: string, opts: { registrar: string; json?: boolean }) => {
      const result = await registerWard(opts.registrar, name);
      if (opts.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }
      console.log(`Created ${result.did}`);
      if (result.login_secret) {
        console.log("");
        console.log(`Login secret (shown once -- save it now, there's no recovery path if you lose it):`);
        console.log(result.login_secret);
      }
      console.log("");
      console.log(`This identity has no guardian yet -- register a guardian the same way, log in as them, and run "did-guardian guardian adopt ${result.did}" (this registrar still holds both keys, so that's the one step a bare key can't do). See "did-guardian guardian adopt --help", or https://guardianspec.org/docs/how-to/ for the full walkthrough.`);
    });
}
