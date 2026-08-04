/**
 * tokenCliSnippets.ts — builds the copy-paste command-line snippets shown in
 * TokensPage.vue's "Use from the command line" section (issue #122): mint a
 * token with curl, then mint + connect with a minimal fastmcp Python client.
 *
 * Pure string builders (no DOM, no fetch) so they're unit-testable
 * independent of how the caller obtained `brokerOrigin` at runtime — see
 * auth.ts's getBrokerOrigin() for that part — matching the
 * linkedBanner.ts/tokenDisplay.ts pattern of keeping derivation logic in a
 * dependency-free leaf module.
 *
 * The Python snippet's imports and Client/transport construction deliberately
 * mirror scripts/verify-mcp-flow.py's actual usage so the two can't drift out
 * of sync with each other or with a future fastmcp API change.
 */

/** Strips trailing slashes so "<origin>/v1/tokens" never doubles up a slash
 * regardless of whether the caller's brokerOrigin already ends in one. */
function normalizeOrigin(brokerOrigin: string): string {
  return brokerOrigin.replace(/\/+$/, '');
}

export function curlMintSnippet(brokerOrigin: string): string {
  const origin = normalizeOrigin(brokerOrigin);
  return `# Read the token into an env var -- never as a CLI argument (it would
# land in your shell history and in \`ps\` output).
read -s -p "Bearer token: " MCP_BEARER_TOKEN
export MCP_BEARER_TOKEN

curl -sS -X POST "${origin}/v1/tokens" \\
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"name": "my-laptop", "note": "optional free-text note"}'
# The response's "token" field is shown ONLY here -- copy it now.
# GET /v1/tokens never echoes a token value again.`;
}

export function pythonMintAndConnectSnippet(brokerOrigin: string): string {
  const origin = normalizeOrigin(brokerOrigin);
  return `import asyncio
import os

import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

bearer = os.environ["MCP_BEARER_TOKEN"]  # read -s'd into the env, never a CLI arg

# 1. Mint a static broker token -- shown once, in this response only.
resp = httpx.post(
    "${origin}/v1/tokens",
    headers={"Authorization": f"Bearer {bearer}"},
    json={"name": "my-script", "note": "optional free-text note"},
)
resp.raise_for_status()
token = resp.json()["token"]  # save this now -- it is never returned again

# 2. Use the minted token against the MCP aggregator (mirrors
#    scripts/verify-mcp-flow.py's Client/transport usage).
transport = StreamableHttpTransport(
    "${origin}/mcp/",
    headers={"Authorization": f"Bearer {token}"},
)


async def main() -> None:
    async with Client(transport) as client:
        tools = await client.list_tools()
        print([t.name for t in tools])


asyncio.run(main())`;
}
