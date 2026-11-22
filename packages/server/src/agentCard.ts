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
import { didForSegment } from "./registrar.js";
import { getLog, getNameEntry } from "./db.js";

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
  const did = didForSegment(env, name ?? "_");
  const log = await getLog(env, did);
  if (log.length === 0) return json({ error: "not found" }, 404);
  const displayName = name ?? env.REGISTRAR_DOMAIN;
  return json(buildAgentCard(did, displayName, env));
}

const OIDC_ISSUER_REL = "http://openid.net/specs/connect/1.0/issuer";
const A2A_SELF_REL = "self";

/**
 * GET /.well-known/webfinger?resource=acct:<name>@<domain>[&rel=...] (RFC
 * 7033 shape) -- serves two independent discovery profiles over the same
 * endpoint, since both resolve the same "is this identifier real on this
 * registrar" question and RFC 7033 itself is rel-filtered, not single-
 * purpose:
 *
 * - draft-zhao-a2a-webfinger-00's own profile (rel: "self", the draft's
 *   choice -- no new link relation defined): resolves to the ward's own
 *   Agent Card, the multi-tenant discovery step the fixed well-known path
 *   alone can't provide.
 * - OpenID Connect Discovery 1.0's own WebFinger usage (rel:
 *   "http://openid.net/specs/connect/1.0/issuer"): what a relying party
 *   that only has a user's identifier (e.g. Tailscale's own "log in with
 *   your identity provider" flow, given "alice@guardianspec.org") actually
 *   calls first, before ever fetching /.well-known/openid-configuration.
 *   Every identity on this registrar shares the same issuer (there's one
 *   OIDC provider per registrar, not per ward) -- this step is purely
 *   "does this identifier exist here at all," not a per-ward value.
 *
 * `rel` filters per RFC 7033: zero or more `rel` params given means return
 * only matching links; none given means return every link this registrar
 * knows for the resource.
 */
export async function handleWebfinger(env: Env, url: URL): Promise<Response> {
  const resource = url.searchParams.get("resource");
  if (!resource) return json({ error: "resource parameter is required" }, 400);
  const m = resource.match(/^acct:([^@]+)@(.+)$/);
  if (!m) return json({ error: 'resource must be an "acct:" URI, e.g. acct:alice@acme.com' }, 400);
  const [, rawName, domain] = m;
  if (domain !== env.REGISTRAR_DOMAIN) return json({ error: `this registrar only resolves resources at ${env.REGISTRAR_DOMAIN}` }, 404);

  // "_" is the bare-domain root identity's own reserved local part
  // everywhere else (login, email) -- WebFinger resolution never applied
  // that same translation, so acct:_@domain silently 404'd instead of
  // resolving root. The stored name for root is "", never the literal "_".
  const name = rawName === "_" ? "" : rawName;
  const ward = await getNameEntry(env, env.REGISTRAR_DOMAIN, name);
  if (!ward) return json({ error: "not found" }, 404);

  const requestedRels = url.searchParams.getAll("rel");
  const wantsRel = (rel: string) => requestedRels.length === 0 || requestedRels.includes(rel);

  const links: Array<{ rel: string; type?: string; href: string }> = [];
  if (wantsRel(A2A_SELF_REL)) {
    links.push({
      rel: A2A_SELF_REL,
      type: "application/a2a+json",
      href: `https://${env.REGISTRAR_DOMAIN}/.well-known/guardian/${name || "_"}/agent-card.json`,
    });
  }
  if (wantsRel(OIDC_ISSUER_REL)) {
    links.push({ rel: OIDC_ISSUER_REL, href: `https://${env.REGISTRAR_DOMAIN}` });
  }

  return json({ subject: resource, links });
}
