import { describe, expect, it } from 'vitest';
import { curlMintSnippet, pythonMintAndConnectSnippet } from '../tokenCliSnippets';

describe('curlMintSnippet', () => {
  it('POSTs to <brokerOrigin>/v1/tokens with a Bearer header and a JSON body', () => {
    const snippet = curlMintSnippet('https://mcp.af.uchicago.edu');
    expect(snippet).toContain('curl -sS -X POST "https://mcp.af.uchicago.edu/v1/tokens"');
    expect(snippet).toContain('-H "Authorization: Bearer $MCP_BEARER_TOKEN"');
    expect(snippet).toContain('"name"');
    expect(snippet).toContain('"note"');
  });

  it('reads the caller bearer via read -s rather than a CLI argument', () => {
    const snippet = curlMintSnippet('https://mcp.af.uchicago.edu');
    expect(snippet).toContain('read -s -p');
  });

  it('notes the token is only ever shown once', () => {
    const snippet = curlMintSnippet('https://mcp.af.uchicago.edu');
    expect(snippet.toLowerCase()).toContain('shown');
  });

  it('strips a trailing slash from brokerOrigin before building the URL', () => {
    const snippet = curlMintSnippet('https://mcp.af.uchicago.edu/');
    expect(snippet).toContain('"https://mcp.af.uchicago.edu/v1/tokens"');
    expect(snippet).not.toContain('.edu//v1/tokens');
  });
});

describe('pythonMintAndConnectSnippet', () => {
  it('mints against <brokerOrigin>/v1/tokens and connects to <brokerOrigin>/mcp/', () => {
    const snippet = pythonMintAndConnectSnippet('https://mcp.af.uchicago.edu');
    expect(snippet).toContain('"https://mcp.af.uchicago.edu/v1/tokens"');
    expect(snippet).toContain('"https://mcp.af.uchicago.edu/mcp/"');
  });

  it('reuses the exact fastmcp Client/transport shape scripts/verify-mcp-flow.py uses', () => {
    const snippet = pythonMintAndConnectSnippet('https://mcp.af.uchicago.edu');
    expect(snippet).toContain('from fastmcp import Client');
    expect(snippet).toContain('from fastmcp.client.transports import StreamableHttpTransport');
    expect(snippet).toContain('StreamableHttpTransport(');
    expect(snippet).toContain('async with Client(transport) as client:');
    expect(snippet).toContain('await client.list_tools()');
  });

  it('reads the bearer from the environment, never a literal token', () => {
    const snippet = pythonMintAndConnectSnippet('https://mcp.af.uchicago.edu');
    expect(snippet).toContain('os.environ["MCP_BEARER_TOKEN"]');
  });

  it('strips a trailing slash from brokerOrigin before building URLs', () => {
    const snippet = pythonMintAndConnectSnippet('https://mcp.af.uchicago.edu/');
    expect(snippet).toContain('"https://mcp.af.uchicago.edu/v1/tokens"');
    expect(snippet).toContain('"https://mcp.af.uchicago.edu/mcp/"');
    expect(snippet).not.toContain('.edu//');
  });
});
