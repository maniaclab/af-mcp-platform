import { describe, expect, it } from 'vitest';
import { parseToolDescription } from '../toolDescription';

// Real docstrings captured from ami-mcp's catalog listing (mcp_html_example.html),
// the exact shape this parser exists to handle.

const AMI_EXECUTE = `Execute an arbitrary AMI command string and return the results.

Use this when no specialized tool covers your query. Read the
ami://query-language resource to learn how to construct command strings.

Args:
    command: AMI command string (see ami://query-language resource).`;

const AMI_GET_DATASET_INFO = `Get metadata for an ATLAS dataset (LDN) from AMI.

Returns key fields: nFiles, nEvents, totalSize, crossSection, genFiltEff,
amiStatus, and related metadata registered in AMI for this dataset.

Args:
    dataset: Full Logical Dataset Name (LDN), e.g.
        "mc20_13TeV.700320.Sh_2211_Zee_maxHTpTV2_BFilter.deriv.DAOD_PHYS.e8351".`;

const AMI_GET_DATASET_PROV = `Get the provenance (parent/child chain) for an ATLAS dataset.

Use this to trace a DAOD back to its EVNT.

Args:
    dataset: Full Logical Dataset Name (LDN).
    data_types: Filter by data types, comma-separated (e.g. "EVNT,AOD,DAOD_PHYS").
        Defaults to physics-relevant types and excludes LOG/TXT noise.

Returns:
    Formatted string with lineage summary, node table, and optional edges.`;

const NO_SECTIONS = `List available PMG cross-section database files.

Scans the configured directory for PMGxsecDB_*.txt files.`;

describe('parseToolDescription', () => {
  it('splits summary from a single Args section', () => {
    const result = parseToolDescription(AMI_EXECUTE);
    expect(result.summary).toBe(
      'Execute an arbitrary AMI command string and return the results.\n\n' +
        'Use this when no specialized tool covers your query. Read the\n' +
        'ami://query-language resource to learn how to construct command strings.',
    );
    expect(result.args).toEqual([
      { name: 'command', desc: 'AMI command string (see ami://query-language resource).' },
    ]);
    expect(result.returns).toBeNull();
  });

  it('joins a wrapped continuation line onto the previous arg', () => {
    const result = parseToolDescription(AMI_GET_DATASET_INFO);
    expect(result.args).toEqual([
      {
        name: 'dataset',
        desc:
          'Full Logical Dataset Name (LDN), e.g. ' +
          '"mc20_13TeV.700320.Sh_2211_Zee_maxHTpTV2_BFilter.deriv.DAOD_PHYS.e8351".',
      },
    ]);
  });

  it('parses multiple args and a trailing Returns section', () => {
    const result = parseToolDescription(AMI_GET_DATASET_PROV);
    expect(result.args).toEqual([
      { name: 'dataset', desc: 'Full Logical Dataset Name (LDN).' },
      {
        name: 'data_types',
        desc:
          'Filter by data types, comma-separated (e.g. "EVNT,AOD,DAOD_PHYS"). ' +
          'Defaults to physics-relevant types and excludes LOG/TXT noise.',
      },
    ]);
    expect(result.returns).toBe(
      'Formatted string with lineage summary, node table, and optional edges.',
    );
  });

  it('falls back to the whole text as summary when there is no Args/Returns section', () => {
    const result = parseToolDescription(NO_SECTIONS);
    expect(result.summary).toBe(NO_SECTIONS);
    expect(result.args).toEqual([]);
    expect(result.returns).toBeNull();
  });

  it('handles an empty description without throwing', () => {
    const result = parseToolDescription('');
    expect(result).toEqual({ summary: '', args: [], returns: null });
  });
});
