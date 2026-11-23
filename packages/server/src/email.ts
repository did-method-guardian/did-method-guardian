import type { Env } from "./env.js";
import { didFor } from "./env.js";
import { getNameEntry, upsertEmailForwarding, getEmailForwardingByToken, markEmailForwardingVerified, getVerifiedForwardingByDid } from "./db.js";
import { randomSecret } from "./secretBox.js";
import { sendEmail } from "./emailProviders.js";

/**
 * Inbound mail for this registrar's own domain, via Cloudflare Email
 * Routing's `email` binding -- receive-and-forward only (spec: no mailbox
 * storage, no IMAP, this isn't a mail provider). Unknown or unverified
 * recipients are rejected, not silently dropped, so the sending MTA gets a
 * real bounce rather than mail disappearing without a trace.
 */
export async function handleEmail(message: ForwardableEmailMessage, env: Env): Promise<void> {
  const localPart = message.to.split("@")[0];
  // "_" is the same reserved local part login already uses for the
  // bare-domain root identity (wards.name's own "" sentinel) -- root can
  // never be found by looking up a ward literally named "_", since
  // assertValidName already forbids any real ward from ever being named
  // that.
  const ward = await getNameEntry(env, env.REGISTRAR_DOMAIN, localPart === "_" ? "" : localPart);
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
  const ward = await getNameEntry(env, env.REGISTRAR_DOMAIN, name);
  if (!ward) return { ok: false, reason: `no such identity "${name}"` };

  const token = randomSecret();
  await upsertEmailForwarding(env, { did: ward.did, forward_to: forwardTo, verification_token: token, created_at: new Date().toISOString() });

  const verifyUrl = `https://${env.REGISTRAR_DOMAIN}/verify-email?token=${token}`;
  // The actual addressable local part -- "_" for the bare-domain root
  // (wards.name's own "" sentinel, same reserved convention login already
  // uses), the ward's own name otherwise. didFor itself already handles ""
  // correctly (falsy, produces the bare root DID), so only the literal
  // mail-address text below needs this.
  const addressableName = name || "_";
  const result = await sendEmail(env, {
    from: `postmaster@${env.REGISTRAR_DOMAIN}`,
    fromName: "did:guardian",
    to: forwardTo,
    subject: `Confirm mail forwarding for ${didFor(name, env.REGISTRAR_DOMAIN)}`,
    text: `Someone (hopefully you) asked to forward mail sent to ${addressableName}@${env.REGISTRAR_DOMAIN} to this address.\n\nConfirm: ${verifyUrl}\n\nIf this wasn't you, ignore this message -- forwarding stays off until this link is clicked.`,
  });
  if (!result.ok) {
    return {
      ok: false,
      reason:
        result.status === 0
          ? "this registrar has no email provider configured -- see the registrar operator"
          : `failed to send verification email (status ${result.status})`,
    };
  }
  return { ok: true };
}

export async function confirmEmailForwarding(env: Env, token: string): Promise<{ ok: true; did: string } | { ok: false; reason: string }> {
  const row = await getEmailForwardingByToken(env, token);
  if (!row) return { ok: false, reason: "invalid or already-used verification token" };
  await markEmailForwardingVerified(env, row.did);
  return { ok: true, did: row.did };
}
