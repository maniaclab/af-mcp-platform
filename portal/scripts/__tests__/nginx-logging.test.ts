import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// Read relative to cwd (vitest runs with cwd `portal/`), as the CSP fence in
// sync-csp-hashes.test.ts does.
const template = readFileSync('nginx.conf.template', 'utf8');

describe('nginx.conf.template log noise fences', () => {
  it('serves a missing favicon as a quiet 404, not an [error] line per page load', () => {
    const block = template.match(/location = \/favicon\.ico \{[^}]*\}/)?.[0];
    expect(block).toBeDefined();
    expect(block).toContain('log_not_found off;');
    // Only the not-found error line is silenced; the response stays a 404, so a
    // client still learns there is no icon.
    expect(block).not.toMatch(/return\s+2\d\d/);
  });

  it('keeps successful kube-probe requests out of the access log but logs failing ones', () => {
    // `$loggable` is 0 only for a kube-probe request whose status is 2xx/3xx.
    const map = template.match(/map "\$http_user_agent \$status" \$loggable \{[^}]*\}/)?.[0];
    expect(map).toBeDefined();
    expect(map).toContain('~^kube-probe/');
    expect(map).toMatch(/default\s+1;/);
    expect(template).toMatch(/access_log\s+\S+\s+combined\s+if=\$loggable;/);
  });
});
