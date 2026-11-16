import { describe, expect, it } from 'vitest';
import type { RateLimitStatus } from '../api';
import {
  describeRule,
  formatDuration,
  ruleSentence,
  usageLabel,
  usageTone,
  windowLabel,
} from '../rateLimits';

function rule(overrides: Partial<RateLimitStatus> = {}): RateLimitStatus {
  return {
    action_type: null,
    tool: null,
    limit: 60,
    window_seconds: 300,
    used: 0,
    resets_in_seconds: null,
    tools: [],
    ...overrides,
  };
}

describe('windowLabel', () => {
  it.each([
    [1, 'second'],
    [30, '30 seconds'],
    [60, 'minute'],
    [300, '5 minutes'],
    [90, '90 seconds'],
    [3600, 'hour'],
    [7200, '2 hours'],
    [86400, 'day'],
  ])('%i seconds reads as %s', (seconds, label) => {
    expect(windowLabel(seconds)).toBe(label);
  });
});

describe('ruleSentence', () => {
  it('names an action type the way the permission matrix does', () => {
    expect(ruleSentence(rule({ action_type: 'state_change' }))).toBe(
      'State-changing methods: 60 calls per 5 minutes',
    );
    expect(ruleSentence(rule({ action_type: 'read', limit: 1, window_seconds: 60 }))).toBe(
      'Read methods: 1 call per minute',
    );
  });

  it('names a tool glob and an exact tool differently', () => {
    expect(ruleSentence(rule({ tool: 'condor_submit_*', limit: 30 }))).toBe(
      'Methods matching condor_submit_*: 30 calls per 5 minutes',
    );
    expect(ruleSentence(rule({ tool: 'jhub_create_jupyter_server', limit: 5 }))).toBe(
      'Method jhub_create_jupyter_server: 5 calls per 5 minutes',
    );
  });

  it('combines both selectors', () => {
    expect(ruleSentence(rule({ action_type: 'state_change', tool: 'rucio_*' }))).toBe(
      'State-changing methods matching rucio_*: 60 calls per 5 minutes',
    );
  });
});

describe('describeRule', () => {
  it('splits the tool pattern out so the page can set it in mono', () => {
    expect(describeRule(rule({ tool: 'condor_submit_*' }))).toEqual({
      subject: 'Methods matching',
      pattern: 'condor_submit_*',
      budget: '60 calls per 5 minutes',
    });
  });
});

describe('formatDuration', () => {
  it.each([
    [0, 'under a second'],
    [1, '1 sec'],
    [45, '45 sec'],
    [60, '1 min'],
    [180, '3 min'],
    [181, '4 min'],
    [3600, '1 h'],
    [3900, '1 h 5 min'],
  ])('%i seconds is %s', (seconds, text) => {
    expect(formatDuration(seconds)).toBe(text);
  });
});

describe('usageLabel', () => {
  it('shows used of limit and the time to reset', () => {
    expect(usageLabel(rule({ used: 12, resets_in_seconds: 180 }))).toBe(
      '12 of 60 used, resets in 3 min',
    );
  });

  it('shows an untouched budget without a reset time', () => {
    expect(usageLabel(rule({ used: 0, resets_in_seconds: null }))).toBe('0 of 60 used');
  });

  it('says the limit is reached, capping a count that includes refused calls', () => {
    expect(usageLabel(rule({ used: 75, resets_in_seconds: 90 }))).toBe(
      'Limit reached, resets in 2 min',
    );
  });

  it('says usage is unknown when the broker could not read it', () => {
    expect(usageLabel(rule({ used: null }))).toBe('Usage unavailable');
  });
});

describe('usageTone', () => {
  it.each([
    [null, 'off'],
    [0, 'ok'],
    [47, 'ok'],
    [48, 'warn'],
    [59, 'warn'],
    [60, 'bad'],
    [75, 'bad'],
  ] as const)('%s of 60 used is %s', (used, tone) => {
    expect(usageTone(rule({ used }))).toBe(tone);
  });
});
