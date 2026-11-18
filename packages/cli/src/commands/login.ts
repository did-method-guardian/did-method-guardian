import { Command } from "commander";
import { parseDid } from "@did-guardian/lib";
import type { Did } from "@did-guardian/lib";
import { login } from "../registrar-client.js";
import { saveSession } from "../state.js";

export function registerLoginCommand(program: Command): void {
  program
    .command("login <did>")
    .description("start a session for a registrar-held identity -- needed for \"guardian adopt\" and \"key take-custody\"")
    .requiredOption("--login-secret <secret>", "the secret shown once at registration, or a password set afterward")
    .action(async (did: Did, opts: { loginSecret: string }) => {
      const { domain, name } = parseDid(did);
      const cookie = await login(domain, name ?? "", opts.loginSecret);
      saveSession(did, domain, cookie);
      console.log(`Logged in as ${did}.`);
    });
}
