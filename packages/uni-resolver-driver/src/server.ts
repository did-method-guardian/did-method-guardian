// Universal Resolver driver for did:guardian -- GET /1.0/identifiers/<did>,
// per decentralized-identity/universal-resolver's own driver contract. See
// resolveDriver.ts for the actual resolution logic.
import { createServer } from "node:http";
import { resolveDid } from "./resolveDriver.js";

const PORT = Number(process.env.PORT ?? 8080);

createServer(async (req, res) => {
  const match = /^\/1\.0\/identifiers\/(.+)$/.exec(req.url ?? "");
  if (!match) {
    res.writeHead(404, { "content-type": "application/json" }).end(JSON.stringify({ error: "not found" }));
    return;
  }
  const { status, body } = await resolveDid(decodeURIComponent(match[1]));
  res.writeHead(status, { "content-type": "application/did-resolution+json" }).end(JSON.stringify(body));
}).listen(PORT, () => console.log(`did:guardian universal resolver driver listening on :${PORT}`));
