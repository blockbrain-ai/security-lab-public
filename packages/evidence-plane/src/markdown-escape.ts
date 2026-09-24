/**
 * Markdown escaping helpers for untrusted, target-controlled content.
 *
 * Investigation evidence is attacker-influenced: finding descriptions, titles,
 * URLs, file paths and assessment prose can all be shaped by the scanned
 * target. Interpolating that text into Markdown unescaped lets a hostile
 * target forge report sections (a newline followed by `## ...`) or plant
 * stored XSS (`<img src=x onerror=...>`) in Markdown viewers.
 *
 * The helpers are deliberately narrow: they escape only what can change
 * document structure (raw HTML angle brackets, line-leading block markers,
 * table pipes and backticks) and leave ordinary prose untouched. Content the
 * renderer itself produces (headings, table frames, list bullets, bold
 * markers) must never be passed through these helpers.
 */

/**
 * Characters escaped everywhere inside untrusted text:
 * - `\` first, so an attacker cannot neutralise the escaping below.
 * - `<` / `>` so raw HTML (and autolinks) stay inert.
 * - backticks so a value cannot close an enclosing code span.
 * - `|` so a value cannot open a new table cell.
 * - `[` / `]` so a value cannot forge a Markdown link or image.
 */
function escapeInlineCharacters(value: string): string {
  return value
    .replace(/\\/g, '\\\\')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/`/g, '\\`')
    .replace(/\|/g, '\\|')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]');
}

/**
 * Block-level constructs that are only dangerous at the start of a line:
 * ATX headings, list bullets, ordered-list markers, setext underlines and
 * fenced-code fences.
 */
const LINE_START_STRUCTURE = /^([ \t]*)(#{1,6}(?=\s|$)|[-+*](?=\s|$)|[-=]{2,}[ \t]*$|~{3,})/;

/** `1.` / `2)` — the escape belongs before the punctuation, not the digit. */
const ORDERED_LIST_MARKER = /^([ \t]*)(\d+)([.)])(?=\s|$)/;

function escapeLineStart(line: string): string {
  if (ORDERED_LIST_MARKER.test(line)) {
    return line.replace(ORDERED_LIST_MARKER, '$1$2\\$3');
  }
  return line.replace(
    LINE_START_STRUCTURE,
    (_match: string, indent: string, marker: string) => `${indent}\\${marker}`,
  );
}

/**
 * Escape untrusted text that is rendered as a block (descriptions, summaries,
 * remediation text, telemetry prose). Line breaks are preserved, but every
 * line is prevented from opening a new block-level construct.
 */
export function escapeMarkdownBlock(value: string): string {
  return value
    .split('\n')
    .map((line) => escapeLineStart(escapeInlineCharacters(line)))
    .join('\n');
}

/**
 * Escape untrusted text that must stay on a single line — headings, table
 * cells and inline labels. Embedded line breaks (which would otherwise split
 * a table row or terminate a heading) collapse to spaces.
 */
export function escapeMarkdownLine(value: string): string {
  return escapeLineStart(escapeInlineCharacters(value.replace(/\s*[\r\n]+\s*/g, ' ')));
}

/** Longest run of consecutive backticks in a value (0 when there is none). */
function longestBacktickRun(value: string): number {
  let longest = 0;
  for (const match of value.matchAll(/`+/g)) {
    longest = Math.max(longest, match[0].length);
  }
  return longest;
}

/**
 * Render a code span whose content is untrusted.
 *
 * Backslash escapes are not processed inside code spans, so a backtick cannot
 * be escaped — it must be contained by growing the fence instead. Pipes are
 * escaped because GFM parses table cells before inline code (the backslash is
 * removed again when the table is parsed).
 */
export function renderCodeSpan(value: string): string {
  const fence = '`'.repeat(longestBacktickRun(value) + 1);
  const needsPadding =
    value !== '' &&
    (value.startsWith('`') || value.endsWith('`') || value.startsWith(' ') || value.endsWith(' '));
  const body = needsPadding ? ` ${value} ` : value;
  return `${fence}${body.replace(/\|/g, '\\|')}${fence}`;
}
