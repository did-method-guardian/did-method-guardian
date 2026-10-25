// Outbound transactional send via MailChannels -- native to Cloudflare
// Workers, no separate account needed, but the registrar operator's domain
// needs its own SPF/DKIM setup for this to actually deliver (not something
// this code can do for them; see README.md). A per-domain operator setup
// step, not a per-identity one -- matches the design's own stated split
// between "receive-and-forward" (native Workers primitive) and "send-as"
// (needs real domain authentication, same as any transactional sender).

export interface SendEmailOptions {
  from: string;
  fromName?: string;
  to: string;
  subject: string;
  text: string;
  /**
   * Raw headers, e.g. References/In-Reply-To for client-side threading
   * (Gmail et al. group by these plus subject, even when -- as here, since
   * the Send API reserves Message-ID for itself -- the referenced value
   * isn't a real prior message's own Message-ID, just a stable value every
   * email in the same logical thread shares).
   */
  headers?: Record<string, string>;
}

export async function sendEmail(opts: SendEmailOptions): Promise<{ ok: boolean; status: number }> {
  const resp = await fetch("https://api.mailchannels.net/tx/v1/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
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
