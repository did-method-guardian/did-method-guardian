// A2A (Agent2Agent) interop -- Agent Cards and the WebFinger discovery
// profile that resolves one to a *specific* identity under a multi-tenant
// domain. Investigated before any of this was written (B3's own first
// step, per the plan): A2A's own fixed well-known path
// (/.well-known/agent-card.json) is one-per-origin by construction, which
// doesn't fit this registrar's own multi-tenant /.well-known/guardian/
// <name> shape -- many identities under one domain. The answer, confirmed
// against the current A2A spec and a very recent (August 2026), still
// individual-draft WebFinger profile for exactly this problem
// (draft-zhao-a2a-webfinger-00): WebFinger is the *discovery* layer
// (resolves acct:<name>@<domain> to wherever that identity's own card
// actually lives), and the card itself is free to live at any URL the
// WebFinger response points to -- it doesn't have to be the fixed
// domain-root path. This registrar publishes one Agent Card per ward, at
// a path consistent with its own existing resolution scheme
// (/.well-known/guardian/<name>/agent-card.json), and still serves the
// fixed /.well-known/agent-card.json path too, for the one identity A2A's
// own single-agent-origin convention already expects there: this
// domain's own bare-domain root (spec §2.1) -- the same "_" convention
// did:guardian already uses everywhere else.
//
// Deliberately unsigned in this first pass -- A2A's own AgentCardSignature
// (JWS, canonicalized) is optional, not required, and real HTTPS already
// gives a verifier a weaker but real binding to this domain. Signing with
// the ward's own operational key (already custodied here, already
// published in its own DID Document) is a natural fit for later, not
// something this pass needs to block on.

import type { Env } from "./env.js";
import { resolveState } from "./registrar.js";
import { getWardByName } from "./db.js";

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

/** A minimal, honest AgentCard -- only fields this registrar actually has real data for. No skills/capabilities: those are application-level facts about what a ward's own operator does with it, never something the method or this registrar knows. */
function buildAgentCard(did: string, name: string, env: Env): unknown {
  const base = `https://${env.REGISTRAR_DOMAIN}`;
  return {
    id: did,
    name,
    description: `A did:guardian identity at ${env.REGISTRAR_DOMAIN} -- recoverable, revocable, and transferable via configurable group guardianship, never by impersonation.`,
    securitySchemes: {
      oidc: { type: "openIdConnect", openIdConnectUrl: `${base}/.well-known/openid-configuration` },
    },
    security: [{ oidc: [] }],
  };
}

/** GET /.well-known/guardian/<name>/agent-card.json, and GET /.well-known/agent-card.json for the bare-domain root (A2A's own fixed-path convention, which this registrar satisfies for that one identity specifically). */
export async function handleAgentCard(env: Env, name: string | null): Promise<Response> {
  const resolved = await resolveState(env, name);
  if (!resolved) return json({ error: "not found" }, 404);
  const displayName = name ?? env.REGISTRAR_DOMAIN;
  return json(buildAgentCard(resolved.did, displayName, env));
}

/**
 * GET /.well-known/webfinger?resource=acct:<name>@<domain> (RFC 7033 shape,
 * draft-zhao-a2a-webfinger-00's own profile of it) -- resolves a named
 * ward to its own Agent Card's real URL, the multi-tenant discovery step
 * the fixed well-known path alone can't provide. rel: "self" is the
 * draft's own choice (no new link relation defined); type:
 * "application/a2a+json" per the same draft, pending any future IANA
 * registration.
 */
export async function handleWebfinger(env: Env, url: URL): Promise<Response> {
  const resource = url.searchParams.get("resource");
  if (!resource) return json({ error: "resource parameter is required" }, 400);
  const m = resource.match(/^acct:([^@]+)@(.+)$/);
  if (!m) return json({ error: 'resource must be an "acct:" URI, e.g. acct:alice@acme.com' }, 400);
  const [, name, domain] = m;
  if (domain !== env.REGISTRAR_DOMAIN) return json({ error: `this registrar only resolves resources at ${env.REGISTRAR_DOMAIN}` }, 404);

  const ward = await getWardByName(env, name);
  if (!ward) return json({ error: "not found" }, 404);

  return json({
    subject: resource,
    links: [
      {
        rel: "self",
        type: "application/a2a+json",
        href: `https://${env.REGISTRAR_DOMAIN}/.well-known/guardian/${name}/agent-card.json`,
      },
    ],
  });
}
