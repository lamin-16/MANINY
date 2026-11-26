// MANINY DIGITAL — Deterministic deduplication utilities.

/**
 * Return only the first occurrence of each item with a unique `id` field.
 * Preserves original insertion order. Runs in O(n) time and space.
 *
 * @example
 *   uniqueById([{ id: 'a', val: 1 }, { id: 'a', val: 2 }, { id: 'b', val: 3 }])
 *   // => [{ id: 'a', val: 1 }, { id: 'b', val: 3 }]
 */
export function uniqueById<T extends { id: string }>(items: T[]): T[] {
  const seen = new Set<string>();
  const result: T[] = [];

  for (const item of items) {
    if (!seen.has(item.id)) {
      seen.add(item.id);
      result.push(item);
    }
  }

  return result;
}

/**
 * Generate a deterministic, collision-resistant finding ID from the
 * combination of host, path, category, and title.
 *
 * Uses DJB2-XOR with 32-bit unsigned promotion — no external crypto dep
 * required, deterministic across Node.js versions.
 */
export function generateFindingId(
  host: string,
  path: string,
  category: string,
  title: string
): string {
  const raw = `${host}\x00${path}\x00${category}\x00${title}`;
  let h = 5381;

  for (let i = 0; i < raw.length; i++) {
    // h = ((h << 5) + h) ^ char  — DJB2-XOR
    h = Math.imul(h, 33) ^ raw.charCodeAt(i);
    h = h >>> 0; // force unsigned 32-bit
  }

  return `finding-${h.toString(16).padStart(8, '0')}`;
}

/**
 * Generate a unique scan ID from the current wall-clock time and a
 * short random suffix. Not a UUID — optimised for readability in logs.
 */
export function generateScanId(): string {
  const ts = Date.now().toString(36);
  const rnd = Math.random().toString(36).slice(2, 7);
  return `scan-${ts}-${rnd}`;
}
