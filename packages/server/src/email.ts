import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { getWardByName, upsertEmailForwarding, getEmailForwardingByToken, markEmailForwardingVerified, getVerifiedForwardingByDid } from "./db.js";
import { randomSecret } from "./secretBox.js";
import { sendEmail } from "./mailchannels.js";

/**
 * Inbound mail for this registrar's own domain, via Cloudflare Email
 * Routing's `email` binding -- receive-and-forward only (spec: no mailbox
 * storage, no IMAP, this isn't a mail provider). Unknown or unverified
 * recipients are rejected, not silently dropped, so the sending MTA gets a
 * real bounce rather than mail disappearing without a trace.
 */
export async function handleEmail(message: ForwardableEmailMessage, env: Env): Promise<void> {
  const localPart = message.to.split("@")[0];
  const ward = await getWardByName(env, localPart);
  if (!ward) {
    message.setReject(`no such identity "${localPart}" at this registrar`);
    return;
  }
  const forwarding = await getVerifiedForwardingByDid(env, ward.did);
  if (!forwarding) {
    message.setReject(`"${localPart}" has not set up (or verified) mail forwarding`);
    return;
  }
  await message.forward(forwarding.forward_to);
}

/**
 * Starts (or restarts) the double-opt-in verification flow for forwarding
 * `name`'s mail to `forwardTo` -- forwarding stays inactive until the
 * destination address itself confirms it via the emailed link.
 */
export async function requestEmailForwarding(env: Env, name: string, forwardTo: string): Promise<{ ok: true } | { ok: false; reason: string }> {
  const ward = await getWardByName(env, name);
  if (!ward) return { ok: false, reason: `no such identity "${name}"` };

  const token = randomSecret();
  await upsertEmailForwarding(env, { did: ward.did, forward_to: forwardTo, verification_token: token, created_at: new Date().toISOString() });

  const verifyUrl = `https://${env.REGISTRAR_DOMAIN}/verify-email?token=${token}`;
  const result = await sendEmail({
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwardTo,
    subject: `Confirm mail forwarding for ${didFor(name, env.REGISTRAR_DOMAIN)}`,
    text: `Someone (hopefully you) asked to forward mail sent to ${name}@${env.REGISTRAR_DOMAIN} to this address.\n\nConfirm: ${verifyUrl}\n\nIf this wasn't you, ignore this message -- forwarding stays off until this link is clicked.`,
  });
  if (!result.ok) return { ok: false, reason: `failed to send verification email (status ${result.status})` };
  return { ok: true };
}

/**
 * Best-effort notification that a pending multi-signer operation needs
 * `signerDid`'s own signature -- reuses the same verified-forwarding
 * infrastructure as everything else above, rather than a separate
 * notification channel. Silently a no-op if that DID isn't a ward this
 * registrar hosts, or hasn't set up (or verified) forwarding yet: this is a
 * convenience for discovery, never the thing that actually gates whether a
 * signature counts (rules.ts's own isSatisfied is that).
 */
export async function notifyRequiredSigner(env: Env, signerDid: string, pendingOpId: string, opType: string): Promise<void> {
  const forwarding = await getVerifiedForwardingByDid(env, signerDid);
  if (!forwarding) return;
  await sendEmail({
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwarding.forward_to,
    subject: `Your signature is requested: ${opType}`,
    text: `A ${opType} operation is waiting on your signature as ${signerDid}.\n\nPending operation id: ${pendingOpId}\n\nUse your client to review and either contribute your signature or decline it. If you don't recognize this request, you can safely ignore it -- it expires on its own if nobody completes it.`,
  });
}

export async function confirmEmailForwarding(env: Env, token: string): Promise<{ ok: true; did: string } | { ok: false; reason: string }> {
  const row = await getEmailForwardingByToken(env, token);
  if (!row) return { ok: false, reason: "invalid or already-used verification token" };
  await markEmailForwardingVerified(env, row.did);
  return { ok: true, did: row.did };
}
