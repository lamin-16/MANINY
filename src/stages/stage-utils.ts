// MANINY DIGITAL — Shared utilities for static analysis stages.

import { URL } from 'node:url';
import { generateFindingId } from '../utils/deduplicator.js';
import type { Finding, Severity, FindingSource } from '../types.js';

// ---------------------------------------------------------------------------
// Finding builder
// ---------------------------------------------------------------------------

export interface FindingParams {
  host: string;
  path: string;
  url: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  evidence: string;
  exploitability: number;
  reproductionSteps?: string[];
  remediationHint?: string;
  source?: FindingSource;
  verified?: boolean;
}

/** Build a fully-formed Finding with a deterministic ID and ISO timestamp. */
export function buildFinding(params: FindingParams): Finding {
  const {
    host,
    path,
    url,
    severity,
    category,
    title,
    description,
    evidence,
    exploitability,
    reproductionSteps = [],
    remediationHint = '',
    source = 'static',
    verified = false,
  } = params;

  return {
    id: generateFindingId(host, path, category, title),
    host,
    path,
    url,
    severity,
    category,
    title,
    description,
    evidence,
    status: verified ? 'verified_exploitable' : 'potential',
    exploitability: Math.max(0, Math.min(100, Math.round(exploitability))),
    reproductionSteps,
    remediationHint,
    source,
    timestamp: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// URL parsing helpers
// ---------------------------------------------------------------------------

/** Safely parse a URL, returning null on failure. */
export function safeParseUrl(urlStr: string): URL | null {
  try {
    return new URL(urlStr);
  } catch {
    return null;
  }
}

/**
 * Return all query parameter names from a URL.
 * Returns an empty array if the URL cannot be parsed.
 */
export function getQueryParamNames(urlStr: string): string[] {
  const parsed = safeParseUrl(urlStr);
  if (!parsed) return [];
  return [...parsed.searchParams.keys()];
}

/**
 * Return path segments from a URL path string.
 * "/api/v1/users" → ["api", "v1", "users"]
 */
export function getPathSegments(pathname: string): string[] {
  return pathname.split('/').filter(s => s.length > 0);
}

// ---------------------------------------------------------------------------
// Severity → exploitability default mapping
// ---------------------------------------------------------------------------

const SEVERITY_EXPLOITABILITY: Record<Severity, number> = {
  critical: 85,
  high: 65,
  medium: 40,
  low: 20,
  info: 5,
};

export function defaultExploitability(severity: Severity): number {
  return SEVERITY_EXPLOITABILITY[severity];
}

// ---------------------------------------------------------------------------
// Pattern matchers
// ---------------------------------------------------------------------------

/** Known injection-prone query parameter names (case-insensitive). */
const INJECTION_PARAM_PATTERNS = [
  'id', 'q', 'query', 'search', 'keyword', 'term',
  'file', 'path', 'page', 'url', 'redirect', 'next', 'return',
  'cmd', 'exec', 'command', 'input', 'data', 'load',
  'name', 'user', 'username', 'email', 'phone',
  'sort', 'order', 'by', 'dir', 'column',
];

export function isInjectionProne(paramName: string): boolean {
  return INJECTION_PARAM_PATTERNS.includes(paramName.toLowerCase());
}

/** Sensitive path segments that often indicate privileged endpoints. */
const AUTH_PATH_SEGMENTS = [
  'admin', 'login', 'signin', 'signup', 'register',
  'dashboard', 'panel', 'console', 'manage', 'management',
  'account', 'profile', 'settings', 'config', 'configuration',
  'auth', 'authenticate', 'token', 'jwt', 'oauth',
  'api', 'graphql', 'rest',
];

export function containsAuthPath(segments: string[]): boolean {
  return segments.some(s => AUTH_PATH_SEGMENTS.includes(s.toLowerCase()));
}

/** File extensions that often indicate sensitive exposed files. */
const SENSITIVE_EXTENSIONS = [
  '.bak', '.sql', '.env', '.conf', '.config',
  '.log', '.old', '.orig', '.backup', '.dump',
  '.key', '.pem', '.crt', '.p12', '.pfx',
];

export function hasSensitiveExtension(pathname: string): boolean {
  const lower = pathname.toLowerCase();
  return SENSITIVE_EXTENSIONS.some(ext => lower.endsWith(ext));
}

/** Check if the URL uses plain HTTP (not HTTPS). */
export function isPlainHttp(urlStr: string): boolean {
  const parsed = safeParseUrl(urlStr);
  return parsed?.protocol === 'http:';
}
