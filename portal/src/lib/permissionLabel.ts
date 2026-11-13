/**
 * permissionLabel.ts — the human-readable form of a permission identifier.
 *
 * Identifiers (`read_metadata`) are what policy.yaml and the API use; people
 * read the label (`Read metadata`). Display only: never send a label back to
 * the API, and show the identifier wherever an administrator needs to match it.
 */
export function permissionLabel(name: string): string {
  const spaced = name.replaceAll('_', ' ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}
