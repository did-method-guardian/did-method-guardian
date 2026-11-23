// A real y/N prompt for any command about to produce a signature on the
// caller's behalf for an operation it didn't build itself (F2 audit
// finding: blind-signing whatever a registrar hands back let a pending
// proposal disguise its true effect). `-y`/`--yes` skips it for
// scripted use, same convention as apt/npm.
import { createInterface } from "node:readline/promises";

export async function confirmYesNo(promptText: string, skip?: boolean): Promise<boolean> {
  if (skip) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(`${promptText} [y/N] `);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}
