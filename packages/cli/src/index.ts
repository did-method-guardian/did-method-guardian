#!/usr/bin/env node
import { Command } from "commander";
import { registerKeyCommand } from "./commands/key.js";
import { registerRegisterCommand } from "./commands/register.js";
import { registerResolveCommand } from "./commands/resolve.js";
import { registerGuardianCommand } from "./commands/guardian.js";
import { registerLoginCommand } from "./commands/login.js";
import { registerCreateCommand } from "./commands/create.js";

const program = new Command();

program
  .name("did-guardian")
  .description("Generate keys, create and register did:guardian identities, resolve and verify them, and manage guardianship.")
  .version("0.1.0");

registerKeyCommand(program);
registerCreateCommand(program);
registerRegisterCommand(program);
registerResolveCommand(program);
registerLoginCommand(program);
registerGuardianCommand(program);

program.parseAsync(process.argv).catch((err: Error) => {
  console.error(`Error: ${err.message}`);
  process.exitCode = 1;
});
