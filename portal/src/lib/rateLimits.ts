/**
 * rateLimits.ts — plain-language wording for GET /v1/rate-limits (broker/src/af_mcp_broker/api/rate_limits.py), the rules
 * RateLimitsSection.vue renders. Pure data-in/data-out, like serverTools.ts.
 *
 * Action types are worded as the permission matrix words them ("read",
 * "state-changing"); tools are "methods", as everywhere else in the portal.
 */
import type { RateLimitStatus } from './api';

const ACTION_ADJECTIVE = { read: 'Read', state_change: 'State-changing' } as const;

// fnmatch's special characters; a tool name without them is matched exactly.
const GLOB_CHARS = /[*?[]/;

export interface RuleDescription {
  /** Who the rule covers, e.g. "State-changing methods matching". */
  subject: string;
  /** The tool name or glob, set in mono by the page; null with no tool selector. */
  pattern: string | null;
  /** What it allows, e.g. "60 calls per 5 minutes". */
  budget: string;
}

/** "5 minutes", "minute", "30 seconds": the window as the text after "per". */
export function windowLabel(seconds: number): string {
  const units: [number, string][] = [
    [86400, 'day'],
    [3600, 'hour'],
    [60, 'minute'],
    [1, 'second'],
  ];
  for (const [size, unit] of units) {
    // A window like 90 s reads better in seconds than as a fraction of a minute.
    if (seconds % size === 0 && (size > 1 || seconds < 60)) {
      const count = seconds / size;
      return count === 1 ? unit : `${count} ${unit}s`;
    }
  }
  return `${seconds} seconds`;
}

export function describeRule(rule: RateLimitStatus): RuleDescription {
  const adjective = rule.action_type ? ACTION_ADJECTIVE[rule.action_type] : null;
  const isGlob = rule.tool !== null && GLOB_CHARS.test(rule.tool);
  const noun = rule.tool !== null && !isGlob ? 'method' : 'methods';
  const base = adjective ? `${adjective} ${noun}` : `${noun[0].toUpperCase()}${noun.slice(1)}`;
  return {
    subject: isGlob ? `${base} matching` : base,
    pattern: rule.tool,
    budget: `${rule.limit} ${rule.limit === 1 ? 'call' : 'calls'} per ${windowLabel(rule.window_seconds)}`,
  };
}

/** The whole rule as one sentence: "State-changing methods: 60 calls per 5 minutes". */
export function ruleSentence(rule: RateLimitStatus): string {
  const { subject, pattern, budget } = describeRule(rule);
  return `${pattern === null ? subject : `${subject} ${pattern}`}: ${budget}`;
}

/** "45 sec", "3 min", "1 h 5 min": a wait, rounded up to the unit shown. */
export function formatDuration(seconds: number): string {
  if (seconds <= 0) return 'under a second';
  if (seconds < 60) return `${Math.ceil(seconds)} sec`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} min`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.ceil((seconds % 3600) / 60);
  return minutes > 0 ? `${hours} h ${minutes} min` : `${hours} h`;
}

function atLimit(rule: RateLimitStatus): boolean {
  // `used` counts refused calls too, so it can pass `limit`.
  return rule.used !== null && rule.used >= rule.limit;
}

/** "12 of 60 used, resets in 3 min" — or why there is no such figure. */
export function usageLabel(rule: RateLimitStatus): string {
  if (rule.used === null) return 'Usage unavailable';
  const resets =
    rule.resets_in_seconds === null ? '' : `, resets in ${formatDuration(rule.resets_in_seconds)}`;
  if (atLimit(rule)) return `Limit reached${resets}`;
  return `${rule.used} of ${rule.limit} used${resets}`;
}

/** The status shape for a usage figure: off when unknown, warn from 80% of the limit, bad at it. */
export function usageTone(rule: RateLimitStatus): 'ok' | 'warn' | 'bad' | 'off' {
  if (rule.used === null) return 'off';
  if (atLimit(rule)) return 'bad';
  return rule.used >= rule.limit * 0.8 ? 'warn' : 'ok';
}
