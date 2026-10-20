import type { Env } from "./env.js";

// Full email-proxying implementation lands in a follow-up pass -- stubbed
// for now so the registrar core builds and deploys independently first.
export async function handleEmail(message: ForwardableEmailMessage, _env: Env): Promise<void> {
  message.setReject("email proxying not implemented yet");
}
