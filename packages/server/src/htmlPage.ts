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
 * The "Hearth" theme (website/design_handoff_guardian_theme/) lifted into
 * this package's own shared stylesheet -- same tokens/component shapes as
 * the static site's site.css, kept as a separate copy since this is a
 * fully independent codebase (a Cloudflare Worker rendering plain HTML
 * strings, no shared build or asset pipeline with the website). This is
 * NOT re-branded for any one relying party -- still generic/neutral in
 * the sense that matters (this is the did:guardian *method's* own look,
 * not a relying party's), since this is a self-hostable component any
 * operator's users land on.
 */
export function pageStyles(): string {
  return `<style>
  :root {
    --bg: #f2e3c3; --surface: #eadbb8; --paper: #fcf5e6; --input-bg: #f6ebd3; --cream: #fbf0dc;
    --text: #26201a; --ink-warm: #3a2216; --muted-400: #574634; --muted-500: #6f5b45; --muted-600: #9c8569;
    --clay: #c9502c; --clay-deep: #8f3218; --blue: #1f62c4; --blue-hover: #2a74dd; --sage: #6f8f58; --head-warm: #45693a;
    --font-body: "Inter", system-ui, sans-serif; --font-mono: ui-monospace, "SF Mono", Menlo, monospace;
    --radius: 8px; --shadow-lift: 0 2px 0 rgba(60,30,10,.08), 0 24px 48px rgba(60,25,10,.30);
  }
  body { background: var(--bg); color: var(--text); font: 400 15px/1.55 var(--font-body); margin: 0; }
  a { color: var(--clay-deep); }
  a:hover { color: var(--blue); }
  :focus-visible { outline: 2px solid var(--blue); outline-offset: 2px; }
  .hl { color: var(--head-warm); background: linear-gradient(transparent 58%, #ffd65c 58% 92%, transparent 92%); padding: 0 .06em; }
  .page-nav { display: flex; align-items: center; justify-content: space-between; padding: 20px 32px; }
  .page-nav .brand { display: flex; align-items: center; gap: 10px; text-decoration: none; color: var(--text); font: 500 17px var(--font-body); }
  .page-nav .brand .dim { color: var(--muted-500); }
  .page-nav .links { display: flex; align-items: center; gap: 24px; font-size: 14px; }
  .page-nav .links a { color: var(--text); text-decoration: none; }
  main.center-page { max-width: 480px; margin: 8vh auto 0; padding: 0 1.25rem; line-height: 1.5; }
  h1 { font-size: 1.25rem; margin-bottom: .25rem; font-weight: 500; }
  p.hint { color: var(--muted-500); font-size: .9rem; margin-top: 0; }
  label { display: block; font-size: .85rem; font-weight: 500; color: var(--muted-400); margin: 1rem 0 .3rem; }
  label small { font-weight: 400; color: var(--muted-500); }
  input { display: block; width: 100%; box-sizing: border-box; min-height: 44px; padding: .6rem .7rem; font-size: 1rem; font-family: var(--font-mono); border: 1px solid var(--muted-600); border-radius: var(--radius); background: var(--input-bg); color: var(--text); }
  button { display: block; width: 100%; min-height: 44px; margin-top: 1.25rem; padding: .7rem; font: 500 1rem var(--font-body); border: 1px solid var(--blue); border-radius: var(--radius); background: var(--blue); color: var(--cream); cursor: pointer; }
  button:hover { background: var(--blue-hover); border-color: var(--blue-hover); }
  button.danger { background: var(--clay); border-color: var(--clay); }
  button.danger:hover { background: var(--clay-deep); border-color: var(--clay-deep); }
  button.neutral { background: transparent; border-color: var(--muted-600); color: var(--text); }
  button.neutral:hover { background: color-mix(in srgb, var(--text) 8%, transparent); }
  p.error { color: var(--clay-deep); font-size: .9rem; }
  dl { margin: 1rem 0; }
  dt { font-size: .8rem; color: var(--muted-500); margin-top: .6rem; }
  dd { margin: 0; font-size: .95rem; }
  ul.signers { list-style: none; padding: 0; margin: .25rem 0; }
  ul.signers li { padding: .15rem 0; font-size: .9rem; }
  .badge { display: inline-block; font-size: .75rem; padding: .1rem .4rem; border-radius: 4px; margin-left: .4rem; }
  .badge.yes { background: var(--sage); color: var(--cream); }
  .badge.no { background: var(--muted-600); color: var(--cream); }
  .state { display: inline-block; font-size: .8rem; padding: .15rem .5rem; border-radius: 4px; background: var(--surface); color: var(--text); }
  .secret-box { display: flex; align-items: center; gap: .5rem; border: 1px solid var(--muted-600); border-radius: var(--radius); padding: .6rem .7rem; background: var(--input-bg); margin: .4rem 0; }
  .secret-box code { flex: 1; font-family: var(--font-mono); font-size: .9rem; overflow-wrap: break-word; word-break: break-all; background: none; }
  .secret-box button { flex-shrink: 0; width: auto; min-height: auto; margin-top: 0; padding: .35rem .6rem; font-size: .8rem; background: var(--muted-500); border-color: var(--muted-500); }
  .secret-box button:hover { background: var(--muted-400); border-color: var(--muted-400); }
  table.policy { width: 100%; border-collapse: collapse; margin: .25rem 0; font-size: .9rem; }
  table.policy td { padding: .3rem 0; border-top: 1px solid var(--surface); vertical-align: top; }
  table.policy td.label { padding-right: .75rem; color: var(--muted-500); white-space: nowrap; }
  table.policy td.label a { color: inherit; }

  /* Sign-in's own full-bleed two-column hero (authPageShell only). */
  .signin-hero {
    background:
      radial-gradient(ellipse 55% 80% at 6% 4%, #ffd65c, transparent 70%),
      radial-gradient(ellipse 30% 40% at 70% 0%, color-mix(in srgb, #f0a91a 55%, transparent), transparent 70%),
      radial-gradient(ellipse 45% 60% at 100% 100%, color-mix(in srgb, #6fa8ef 60%, transparent), transparent 72%),
      radial-gradient(ellipse 35% 45% at 45% 115%, color-mix(in srgb, #6f8f58 50%, transparent), transparent 70%),
      #efb999;
    min-height: calc(100vh - 68px);
    display: flex;
    align-items: center;
    padding: 56px 32px;
  }
  .signin-grid { max-width: 1000px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 340px), 1fr)); gap: 56px; align-items: center; width: 100%; }
  .signin-copy h1 { color: var(--cream); font: 500 clamp(32px, 5vw, 48px)/1.1 var(--font-body); letter-spacing: -0.03em; margin: 0 0 16px; }
  .signin-copy p { color: var(--ink-warm); font-size: 16px; line-height: 1.6; margin: 0; max-width: 46ch; }
  .signin-card { background: var(--paper); border-radius: var(--radius); box-shadow: var(--shadow-lift); padding: 32px; max-width: 440px; }
  .signin-card h1, .signin-card p.hint { display: none; }
  .field-eye { position: relative; }
  .field-eye input { padding-right: 2.4rem; }
  .field-eye button { position: absolute; right: 4px; top: 4px; width: 34px; height: 34px; min-height: 0; margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; background: transparent; border: 0; color: var(--muted-500); }
  .field-eye button:hover { background: color-mix(in srgb, var(--text) 8%, transparent); }
</style>`;
}

/** The brand lockup + Spec/Docs/GitHub links, no Log in button -- used standalone on pages (like sign-in) that shouldn't invite signing in again while already mid-auth-flow. The Lens mark is inlined (this package has no static-asset pipeline of its own for a separate SVG file). */
function pageNav(): string {
  return `<nav class="page-nav">
    <a class="brand" href="https://guardianspec.org/">
      <svg width="28" height="28" viewBox="0 0 48 48" aria-hidden="true"><circle cx="17.5" cy="24" r="12.5" fill="#1f62c4" fill-opacity="0.6"/><circle cx="30.5" cy="24" r="12.5" fill="#f0a91a" fill-opacity="0.6"/><path d="M24 13.32A12.5 12.5 0 0 1 24 34.68A12.5 12.5 0 0 1 24 13.32Z" fill="#c9502c"/></svg><span class="wordmark"><span class="dim">did:</span>guardian</span>
    </a>
    <div class="links">
      <a href="https://guardianspec.org/docs/did-guardian-spec-v0.2.0/">Spec</a>
      <a href="https://guardianspec.org/docs/">Docs</a>
      <a href="https://github.com/did-method-guardian/did-method-guardian">GitHub</a>
    </div>
  </nav>`;
}

function headAssets(title: string): string {
  return `<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500&display=swap"><script src="https://unpkg.com/@phosphor-icons/web@2.1.1"></script>${pageStyles()}`;
}

export function pageShell(title: string, body: string): string {
  return `<!doctype html><html lang="en" data-theme="light"><head>${headAssets(title)}</head><body>${pageNav()}<main class="center-page">${body}</main></body></html>`;
}

/**
 * A wider shell with no narrow center-page constraint -- for a page with
 * its own full-bleed hero layout (today, just sign-in's own two-column
 * treatment) rather than the plain narrow card every other page here
 * uses. Still gets the same nav/tokens/fonts via headAssets/pageNav.
 */
export function authPageShell(title: string, body: string): string {
  return `<!doctype html><html lang="en" data-theme="light"><head>${headAssets(title)}</head><body>${pageNav()}${body}</body></html>`;
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
