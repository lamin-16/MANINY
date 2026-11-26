// MANINY DIGITAL — Host/URL allow-list boundary enforcement.
// Every outbound request must pass this gate before dispatch.

import { URL } from 'node:url';

/**
 * Parse a comma-separated allow-hosts string into a cleaned list.
 * Wildcard entries like "*.example.com" are supported.
 */
export function parseAllowedHosts(raw: string): string[] {
  return raw
    .split(',')
    .map(h => h.trim().toLowerCase())
    .filter(h => h.length > 0);
}

/**
 * Extract the hostname from a URL string.
 * Returns an empty string if the URL is unparseable.
 */
export function extractHost(urlStr: string): string {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * Check whether a resolved host is covered by the allow list.
 *
 * Rules:
 * - Exact match  : "example.com"  → matches only "example.com"
 * - Wildcard     : "*.example.com" → matches "sub.example.com" and "example.com"
 * - Catch-all    : "*"            → matches any host (not recommended)
 *
 * An empty allow list always returns false (deny-by-default).
 */
export function isHostAllowed(
  host: string,
  allowedHosts: readonly string[]
): boolean {
  if (allowedHosts.length === 0) return false;

  const lh = host.toLowerCase();

  return allowedHosts.some(allowed => {
    if (allowed === '*') return true;

    if (allowed.startsWith('*.')) {
      const domain = allowed.slice(2);
      return lh === domain || lh.endsWith(`.${domain}`);
    }

    return lh === allowed;
  });
}

export interface FilterResult {
  allowed: string[];
  rejected: string[];
}

/**
 * Partition a URL list into allowed and rejected groups.
 * URLs that cannot be parsed are always rejected.
 */
export function filterAllowedUrls(
  urls: string[],
  allowedHosts: readonly string[]
): FilterResult {
  const allowed: string[] = [];
  const rejected: string[] = [];

  for (const url of urls) {
    const host = extractHost(url);
    if (host && isHostAllowed(host, allowedHosts)) {
      allowed.push(url);
    } else {
      rejected.push(url);
    }
  }

  return { allowed, rejected };
}
