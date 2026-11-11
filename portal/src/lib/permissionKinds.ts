/**
 * permissionKinds.ts — how the portal classifies a permission as read or
 * state-changing, shared by the Entitlements matrix and the token dialog's
 * permission picker so both group the same permission the same way.
 */
import type { ActionType } from './api';

export type PermissionKind = 'read' | 'write';

export interface KnownPermission {
  name: string;
  kind: PermissionKind;
  description: string;
}

// Column order/coloring/description mirrors authorization/base.py's
// PERMISSIONS dict (action_type classification and description text)
// purely for display -- cosmetic only, not an enforcement decision. A
// permission the broker adds later that isn't in this list still renders
// correctly: it's appended alphabetically at the end, styled as "read", with
// no tooltip (there's no description to show for it here).
export const KNOWN_PERMISSION_ORDER: KnownPermission[] = [
  { name: 'read_data', kind: 'read', description: 'Read datasets from data stores.' },
  { name: 'read_metadata', kind: 'read', description: 'Read metadata catalogs.' },
  {
    name: 'read_monitoring',
    kind: 'read',
    description: 'Read monitoring dashboards and metrics.',
  },
  {
    name: 'read_gitlab',
    kind: 'read',
    description: 'Browse GitLab repos, issues, MRs, and pipelines.',
  },
  {
    name: 'read_files',
    kind: 'read',
    description: 'Browse and read files in a POSIX home directory.',
  },
  { name: 'submit_jobs', kind: 'write', description: 'Submit compute jobs.' },
  { name: 'manage_jobs', kind: 'write', description: 'Cancel or modify compute jobs.' },
  {
    name: 'launch_compute',
    kind: 'write',
    description: 'Launch interactive compute sessions.',
  },
  {
    name: 'manage_jupyter',
    kind: 'write',
    description: 'Start, stop, and configure Jupyter servers.',
  },
  { name: 'manage_gitlab', kind: 'write', description: 'Create MRs, open issues, retry CI.' },
  { name: 'manage_data', kind: 'write', description: 'Write or delete data (gated).' },
  { name: 'admin', kind: 'write', description: 'Platform administration.' },
];

/**
 * Whether a permission is read-only or state-changing. A permission in
 * KNOWN_PERMISSION_ORDER keeps that list's classification; any other one is
 * state-changing when the broker reports a state-changing action type for it
 * (GET /v1/permissions), and read otherwise.
 */
export function permissionKind(name: string, actionTypes: ActionType[] = []): PermissionKind {
  const known = KNOWN_PERMISSION_ORDER.find((p) => p.name === name);
  if (known) return known.kind;
  return actionTypes.includes('state_change') ? 'write' : 'read';
}
