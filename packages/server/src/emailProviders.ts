// Outbound transactional email -- a reference registrar shouldn't lock a
// self-hoster into one vendor's own API, any more than it should lock them
// into a specific database or runtime. Every provider implementation below
// is a plain function of (apiKey, opts) -> Response, using only `fetch` --
// no Workers-specific types, so the exact same function runs unmodified on
// any other JS runtime with a global fetch (Node 18+, Deno, Bun, browsers).
// `sendEmail`, just below, is the one place that reads `Env` at all -- it
// picks which provider to call and which secret to hand it, nothing more.
//
// Adding a new provider is one more small function in this same shape,
// registered in EMAIL_PROVIDERS -- never a reason to touch any call site.

import type { Env } from "./env.js";

export interface SendEmailOptions {
  from: string;
  fromName?: string;
  to: string;
  subject: string;
  text: string;
  /** Raw headers, e.g. References/In-Reply-To for client-side threading -- see email.ts's own header comment on threadHeaders. */
  headers?: Record<string, string>;
}

export type EmailProviderFn = (apiKey: string, opts: SendEmailOptions) => Promise<{ ok: boolean; status: number }>;

/** MailChannels' current Email API (the old free, keyless Workers-only integration was shut down in 2024 -- this is the paid successor, X-Api-Key auth, same /tx/v1/send shape). */
async function sendViaMailChannels(apiKey: string, opts: SendEmailOptions): Promise<{ ok: boolean; status: number }> {
  const resp = await fetch("https://api.mailchannels.net/tx/v1/send", {
    method: "POST",
    headers: { "content-type": "application/json", "X-Api-Key": apiKey },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: opts.to }] }],
      from: { email: opts.from, name: opts.fromName ?? opts.from },
      subject: opts.subject,
      content: [{ type: "text/plain", value: opts.text }],
      ...(opts.headers ? { headers: opts.headers } : {}),
    }),
  });
  return { ok: resp.ok, status: resp.status };
}

/** Resend (resend.com) -- a second, equally simple option; which one an operator picks is just which account they'd rather hold. */
async function sendViaResend(apiKey: string, opts: SendEmailOptions): Promise<{ ok: boolean; status: number }> {
  const resp = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      from: opts.fromName ? `${opts.fromName} <${opts.from}>` : opts.from,
      to: [opts.to],
      subject: opts.subject,
      text: opts.text,
      headers: opts.headers,
    }),
  });
  return { ok: resp.ok, status: resp.status };
}

/** Dev-only: prints the email to this Worker's own logs instead of sending anything. Never a production provider -- there is no real delivery behind it. */
async function sendViaLog(_apiKey: string, opts: SendEmailOptions): Promise<{ ok: boolean; status: number }> {
  console.log(`[email:log-provider] to=${opts.to} from=${opts.from} subject=${JSON.stringify(opts.subject)}\n${opts.text}`);
  return { ok: true, status: 200 };
}

const EMAIL_PROVIDERS: Record<string, EmailProviderFn> = {
  mailchannels: sendViaMailChannels,
  resend: sendViaResend,
  log: sendViaLog,
};

/**
 * The only function here that touches `Env` -- reads which provider this
 * deployment is configured for (`EMAIL_PROVIDER`, a plain var, since it
 * isn't a secret) and that provider's own API key (named per-provider,
 * e.g. `MAILCHANNELS_API_KEY`/`RESEND_API_KEY`, each a real Worker secret).
 * An unconfigured or unrecognized provider is a clear configuration error,
 * not a mysterious 401 from a vendor-specific endpoint nobody told the
 * caller it was even calling.
 */
export async function sendEmail(env: Env, opts: SendEmailOptions): Promise<{ ok: boolean; status: number }> {
  const provider = env.EMAIL_PROVIDER;
  if (!provider) {
    console.error("sendEmail: EMAIL_PROVIDER is not configured for this registrar -- see the registrar API spec's own email-provider section.");
    return { ok: false, status: 0 };
  }
  const fn = EMAIL_PROVIDERS[provider];
  if (!fn) {
    console.error(`sendEmail: EMAIL_PROVIDER "${provider}" is not one of: ${Object.keys(EMAIL_PROVIDERS).join(", ")}.`);
    return { ok: false, status: 0 };
  }
  const apiKeyField = `${provider.toUpperCase()}_API_KEY` as keyof Env;
  const apiKey = (env[apiKeyField] as string | undefined) ?? "";
  if (provider !== "log" && !apiKey) {
    console.error(`sendEmail: EMAIL_PROVIDER is "${provider}" but ${String(apiKeyField)} is not set.`);
    return { ok: false, status: 0 };
  }
  return fn(apiKey, opts);
}
