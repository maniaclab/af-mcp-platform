/**
 * toolDescription.ts — best-effort structuring of a tool's raw Python
 * docstring (Google-style: free prose, then an "Args:"/"Returns:"/"Notes:"
 * block) for display in ToolTable.vue, instead of dumping the whole
 * docstring as one collapsed-whitespace blob.
 *
 * Deliberately conservative: if a docstring doesn't look like this shape at
 * all, everything lands in `summary` unchanged rather than being mangled.
 */

export interface ToolArg {
  name: string;
  desc: string;
}

export interface ParsedToolDescription {
  /** Free-form prose before any recognized section header, rendered with
   * `white-space: pre-wrap` by the caller to preserve authored paragraph
   * breaks and indented example blocks (e.g. a "Common command patterns:"
   * list) as written, rather than re-flowing them. */
  summary: string;
  args: ToolArg[];
  returns: string | null;
}

const SECTION_HEADERS = ['Args:', 'Returns:', 'Notes:', 'Note:'] as const;

/** A parameter line at the args block's own base indent: `name: desc` or
 * `name (type): desc`. Continuation lines are indented further than this. */
const ARG_LINE = /^(\w+)\s*(?:\([^)]*\))?:\s?(.*)$/;

function leadingSpaces(line: string): number {
  const match = /^ */.exec(line);
  return match ? match[0].length : 0;
}

function parseArgsBlock(lines: string[]): ToolArg[] {
  const nonBlank = lines.filter((l) => l.trim() !== '');
  if (nonBlank.length === 0) return [];
  const baseIndent = Math.min(...nonBlank.map(leadingSpaces));

  const args: ToolArg[] = [];
  for (const line of lines) {
    if (line.trim() === '') continue;
    const indent = leadingSpaces(line);
    const trimmed = line.trim();
    if (indent <= baseIndent) {
      const m = ARG_LINE.exec(trimmed);
      if (m) {
        args.push({ name: m[1], desc: m[2] });
        continue;
      }
    }
    // Continuation of the previous arg's description, or an unparseable
    // base-indent line -- either way, append to the last arg if one
    // exists rather than dropping the text.
    const last = args[args.length - 1];
    if (last) {
      last.desc = last.desc ? `${last.desc} ${trimmed}` : trimmed;
    }
  }
  return args;
}

function dedentJoin(lines: string[]): string {
  const nonBlank = lines.filter((l) => l.trim() !== '');
  if (nonBlank.length === 0) return '';
  const baseIndent = Math.min(...nonBlank.map(leadingSpaces));
  const paragraphs: string[] = [];
  let current: string[] = [];
  for (const line of lines) {
    if (line.trim() === '') {
      if (current.length > 0) {
        paragraphs.push(current.join(' '));
        current = [];
      }
      continue;
    }
    current.push(line.slice(baseIndent).trim());
  }
  if (current.length > 0) paragraphs.push(current.join(' '));
  return paragraphs.join('\n\n');
}

export function parseToolDescription(raw: string): ParsedToolDescription {
  const lines = raw.split('\n');
  const headerIdx = lines.findIndex((l) =>
    (SECTION_HEADERS as readonly string[]).includes(l.trim()) && leadingSpaces(l) === 0,
  );

  if (headerIdx === -1) {
    return { summary: raw.trim(), args: [], returns: null };
  }

  const summary = lines.slice(0, headerIdx).join('\n').trim();

  let args: ToolArg[] = [];
  let returns: string | null = null;
  let i = headerIdx;
  while (i < lines.length) {
    const header = lines[i].trim();
    const sectionStart = i + 1;
    let sectionEnd = lines.length;
    for (let j = sectionStart; j < lines.length; j++) {
      if ((SECTION_HEADERS as readonly string[]).includes(lines[j].trim()) && leadingSpaces(lines[j]) === 0) {
        sectionEnd = j;
        break;
      }
    }
    const body = lines.slice(sectionStart, sectionEnd);
    if (header === 'Args:') {
      args = parseArgsBlock(body);
    } else if (header === 'Returns:') {
      returns = dedentJoin(body) || null;
    }
    // Notes/Note sections aren't surfaced separately (no UI slot for them
    // yet) -- their text is simply omitted rather than guessed at.
    i = sectionEnd;
  }

  return { summary, args, returns };
}
