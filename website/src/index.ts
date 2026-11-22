export interface Env {
  ASSETS: Fetcher;
}

// Pages that have a raw Markdown twin served as a static asset at the same
// path with a .md extension (see scripts/sync-md-twins.py). A request for
// one of these whose own Accept header prefers text/markdown over
// text/html gets the .md asset instead of the rendered page -- real
// content negotiation, not just a predictable .md path to fetch directly
// (which already works without this, as a plain static asset).
//
// WS-6.2 (audit): this list is generated FROM content/docs/**/index.md by
// scripts/sync-md-twins.py every time it runs -- never hand-edit the set
// below; a page added under content/docs without rerunning that script is
// the exact silent-drift bug this generation closes.
const MARKDOWN_TWIN_PATHS = new Set([
  // MARKDOWN_TWIN_PATHS:BEGIN
  "/docs/",
  "/docs/did-guardian-spec-v0.2.0/",
  "/docs/how-to/",
  "/docs/how-to/ai-agent-identity/",
  "/docs/how-to/custom-oidc-login/",
  "/docs/how-to/recover-lost-key/",
  "/docs/how-to/self-host/",
  "/docs/prior-art/",
  "/docs/registrar/",
  // MARKDOWN_TWIN_PATHS:END
]);

function prefersMarkdown(acceptHeader: string | null): boolean {
  if (!acceptHeader) return false;
  // Parse each media range's own q value (default 1); markdown wins only if
  // it's explicitly named with a higher q than text/html. No "text/markdown"
  // token at all (a plain browser's Accept, or curl's bare "*/*") always
  // leaves markdownQ at -1, so the common case never triggers this.
  let htmlQ = -1;
  let markdownQ = -1;
  for (const part of acceptHeader.split(",")) {
    const [rawType, ...params] = part.trim().split(";");
    const type = rawType.trim();
    let q = 1;
    for (const p of params) {
      const [k, v] = p.trim().split("=");
      if (k === "q") q = parseFloat(v) || 0;
    }
    if (type === "text/html") htmlQ = Math.max(htmlQ, q);
    if (type === "text/markdown") markdownQ = Math.max(markdownQ, q);
  }
  return markdownQ > -1 && markdownQ > htmlQ;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (MARKDOWN_TWIN_PATHS.has(url.pathname) && prefersMarkdown(request.headers.get("accept"))) {
      const mdUrl = new URL(url.pathname + "index.md", url);
      const mdResponse = await env.ASSETS.fetch(new Request(mdUrl, request));
      if (mdResponse.ok) {
        return new Response(mdResponse.body, {
          status: mdResponse.status,
          headers: { ...Object.fromEntries(mdResponse.headers), vary: "Accept" },
        });
      }
    }
    const response = await env.ASSETS.fetch(request);
    // Vary on every path this Worker could have redirected based on Accept,
    // so a cache never serves one client's negotiated response to another.
    if (MARKDOWN_TWIN_PATHS.has(url.pathname)) {
      const headers = new Headers(response.headers);
      headers.set("vary", "Accept");
      return new Response(response.body, { status: response.status, headers });
    }
    return response;
  },
};
