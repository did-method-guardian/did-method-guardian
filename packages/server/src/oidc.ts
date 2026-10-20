import type { Env } from "./env.js";

// Full OIDC provider implementation lands in a follow-up pass -- stubbed for
// now so the registrar core builds and deploys independently first.
export async function handleOidcRequest(_request: Request, _env: Env): Promise<Response> {
  return new Response(JSON.stringify({ error: "not implemented yet" }), { status: 501, headers: { "content-type": "application/json" } });
}
