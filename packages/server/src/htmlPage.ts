// Shared HTML rendering helpers for this registrar's own small set of
// first-party pages (the OIDC login form, and the voting UI below) --
// everything else this registrar serves is JSON, consumed by a relying
// party's own code, never looked at directly by a person.

export function html(body: string, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", ...extraHeaders } });
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/**
 * Kept deliberately generic/neutral (not any one relying party's own
 * branding) since this is a self-hostable component -- any operator's
 * users land on these pages.
 */
export function pageStyles(): string {
  return `<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; max-width: 480px; margin: 8vh auto 0; padding: 0 1.25rem; line-height: 1.5; }
  h1 { font-size: 1.25rem; margin-bottom: .25rem; }
  p.hint { color: #767676; font-size: .9rem; margin-top: 0; }
  label { display: block; font-size: .85rem; font-weight: 600; margin: 1rem 0 .3rem; }
  label small { font-weight: 400; color: #767676; }
  input { display: block; width: 100%; box-sizing: border-box; padding: .6rem .7rem; font-size: 1rem; border: 1px solid #888; border-radius: 6px; background: Canvas; color: CanvasText; }
  button { display: block; width: 100%; margin-top: 1.25rem; padding: .7rem; font-size: 1rem; border: none; border-radius: 6px; background: #2962ff; color: white; cursor: pointer; }
  button:hover { background: #1e4fd6; }
  button.danger { background: #c0392b; }
  button.danger:hover { background: #962d22; }
  button.neutral { background: #666; }
  button.neutral:hover { background: #4d4d4d; }
  p.error { color: #c0392b; font-size: .9rem; }
  dl { margin: 1rem 0; }
  dt { font-size: .8rem; color: #767676; margin-top: .6rem; }
  dd { margin: 0; font-size: .95rem; }
  ul.signers { list-style: none; padding: 0; margin: .25rem 0; }
  ul.signers li { padding: .15rem 0; font-size: .9rem; }
  .badge { display: inline-block; font-size: .75rem; padding: .1rem .4rem; border-radius: 4px; margin-left: .4rem; }
  .badge.yes { background: #2a7a2a; color: white; }
  .badge.no { background: #999; color: white; }
  .state { display: inline-block; font-size: .8rem; padding: .15rem .5rem; border-radius: 4px; background: #eee; color: #333; }
  .secret-box { display: flex; align-items: center; gap: .5rem; border: 1px solid #888; border-radius: 6px; padding: .6rem .7rem; background: Canvas; margin: .4rem 0; }
  .secret-box code { flex: 1; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9rem; overflow-wrap: break-word; word-break: break-all; }
  .secret-box button { flex-shrink: 0; width: auto; margin-top: 0; padding: .35rem .6rem; font-size: .8rem; background: #666; }
  .secret-box button:hover { background: #4d4d4d; }
  table.policy { width: 100%; border-collapse: collapse; margin: .25rem 0; font-size: .9rem; }
  table.policy td { padding: .3rem 0; border-top: 1px solid #ddd; vertical-align: top; }
  table.policy td.label { padding-right: .75rem; color: #767676; white-space: nowrap; }
  table.policy td.label a { color: inherit; }
</style>`;
}

export function pageShell(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>${pageStyles()}</head><body>${body}</body></html>`;
}

/**
 * A one-time (or any other) secret shown in a bordered, monospace box with
 * a copy button inside it at the right -- the one script every page using
 * this needs (navigator.clipboard has no non-JS equivalent). Scoped to
 * this one element via its own id, never a page-wide handler, so multiple
 * boxes on one page (unlikely today, but cheap to keep safe) don't collide.
 */
export function secretBox(value: string): string {
  const id = `secret-${Math.random().toString(36).slice(2, 10)}`;
  return `<div class="secret-box">
    <code id="${id}">${escapeHtml(value)}</code>
    <button type="button" onclick="navigator.clipboard.writeText(document.getElementById('${id}').textContent).then(() => { this.textContent = 'Copied!'; setTimeout(() => { this.textContent = 'Copy'; }, 1500); })">Copy</button>
  </div>`;
}

type ThresholdValue = "any" | "majority" | "unanimous" | { at_least: number };

/** The formal spec's own threshold shape (REQ-5-1), rendered as something a person reads rather than parses. */
export function formatThreshold(value: ThresholdValue): string {
  if (typeof value === "string") return value === "any" ? "any one guardian" : value;
  return `at least ${value.at_least}`;
}

export interface PolicyField {
  label: string;
  value: string;
  /** Anchor fragment into the formal spec, e.g. "req-5-2" -- rendered as a link on the label so a person can go straight to what this setting actually governs. */
  reqAnchor: string;
}

/** Structured policy display (REQ-5) -- a table of plain-language labels, each linking to the exact formal-spec requirement it governs, instead of a bare JSON dump nobody but this codebase's own authors could read. */
export function policyTable(fields: PolicyField[], specBaseUrl: string): string {
  const rows = fields
    .map(
      (f) =>
        `<tr><td class="label"><a href="${specBaseUrl}#${f.reqAnchor}" target="_blank" rel="noopener">${escapeHtml(f.label)}</a></td><td>${escapeHtml(f.value)}</td></tr>`,
    )
    .join("");
  return `<table class="policy">${rows}</table>`;
}
