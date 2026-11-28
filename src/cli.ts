#!/usr/bin/env node
// MANINY DIGITAL — CLI entry point v0.3.0.
// Parses argv, validates boundaries, delegates to runner, writes JSON to stdout.

import { parseAllowedHosts } from './utils/host-validator.js';
import {
  printJson, errorOut, warn,
  formatAttackReport, formatTopRank, formatEliteMatrix, formatDefault,
} from './utils/json-output.js';
import { runScan } from './runner.js';
import type { ScanConfig, SessionConfig } from './types.js';

// ---------------------------------------------------------------------------
// Argument parser (zero deps)
// ---------------------------------------------------------------------------

interface Args {
  allowHosts:    string | null;
  targetUrls:    string | null;
  topRank:       boolean;
  attackReport:  boolean;
  eliteMatrix:   boolean;
  timeoutMs:     number;
  cookies:       string[];       // --cookie "name=value"
  bearerToken:   string | null;  // --bearer-token <token>
  headers:       string[];       // --header "Name: Value"
  rateLimitMs:   number;         // --rate-limit <ms>
  concurrency:   number;         // --concurrency <n>
  fromHttpxPipe: boolean;
  checkSsrf:     boolean;         // --check-ssrf
  checkTakeover: boolean;         // --check-takeover
  help:          boolean;
}

function parseArgs(argv: string[]): Args {
  const args = argv.slice(2);
  const result: Args = {
    allowHosts: null, targetUrls: null,
    topRank: false, attackReport: false, eliteMatrix: false,
    timeoutMs: 7_000, cookies: [], bearerToken: null, headers: [],
    rateLimitMs: 300, concurrency: 3,
    fromHttpxPipe: false, checkSsrf: false, checkTakeover: false, help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';

    if (arg === '-h' || arg === '--help')              { result.help          = true;  continue; }
    if (arg === '--attack-report')                      { result.attackReport  = true;  continue; }
    if (arg === '--top-exploitability-rank')            { result.topRank       = true;  continue; }
    if (arg === '--elite-matrix')                       { result.eliteMatrix   = true;  continue; }
    if (arg === '--from-httpx-pipe')                    { result.fromHttpxPipe = true;  continue; }
    if (arg === '--check-ssrf')                           { result.checkSsrf     = true;  continue; }
    if (arg === '--check-takeover')                       { result.checkTakeover = true;  continue; }

    // --key=value and --key value forms
    const eqIdx = arg.indexOf('=');
    const hasEq = arg.startsWith('--') && eqIdx !== -1;
    const key   = hasEq ? arg.slice(2, eqIdx) : arg.slice(2);
    const valInline = hasEq ? arg.slice(eqIdx + 1) : null;

    if (!arg.startsWith('--')) continue;

    const nextArg = args[i + 1];
    const val = valInline ?? (nextArg && !nextArg.startsWith('--') ? nextArg : null);
    if (val === null && !hasEq) continue;
    if (!hasEq && val !== null) i++;

    switch (key) {
      case 'allow-hosts':    result.allowHosts  = val;                    break;
      case 'target-urls':    result.targetUrls  = val;                    break;
      case 'timeout':        result.timeoutMs   = clampNum(val, 500, 60_000, 7_000);  break;
      case 'rate-limit':     result.rateLimitMs = clampNum(val, 0, 10_000, 300);      break;
      case 'concurrency':    result.concurrency = clampNum(val, 1, 20, 3);            break;
      case 'cookie':         if (val) result.cookies.push(val);           break;
      case 'bearer-token':   result.bearerToken = val;                    break;
      case 'header':         if (val) result.headers.push(val);           break;
      default:               warn(`Unknown flag: --${key}`);
    }
  }

  return result;
}

function clampNum(raw: string | null, min: number, max: number, def: number): number {
  if (!raw) return def;
  const n = parseInt(raw, 10);
  return isNaN(n) ? def : Math.max(min, Math.min(max, n));
}

// ---------------------------------------------------------------------------
// Session builder
// ---------------------------------------------------------------------------

function buildSessionConfig(args: Args): SessionConfig {
  const cookies: Record<string, string> = {};

  for (const raw of args.cookies) {
    for (const pair of raw.split(';')) {
      const eqIdx = pair.indexOf('=');
      if (eqIdx === -1) continue;
      const name  = pair.slice(0, eqIdx).trim();
      const value = pair.slice(eqIdx + 1).trim();
      if (name) cookies[name] = value;
    }
  }

  const customHeaders: Record<string, string> = {};
  for (const raw of args.headers) {
    const colonIdx = raw.indexOf(':');
    if (colonIdx === -1) continue;
    const name  = raw.slice(0, colonIdx).trim();
    const value = raw.slice(colonIdx + 1).trim();
    if (name) customHeaders[name] = value;
  }

  return {
    cookies,
    ...(args.bearerToken ? { bearerToken: args.bearerToken } : {}),
    customHeaders,
  };
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

function printUsage(): void {
  process.stdout.write([
    '',
    'MANINY DIGITAL v0.4.0 — Elite Offensive Security CLI',
    '',
    'Usage:',
    '  maniny --allow-hosts <hosts> --target-urls <urls> [flags]',
    '  httpx -l targets.txt -json | maniny --allow-hosts "*.example.com" --from-httpx-pipe --attack-report',
    '',
    'Required (or --from-httpx-pipe):',
    '  --allow-hosts <hosts>          Comma-separated allow-list of target hostnames.',
    '                                 Wildcards: *.example.com   Catch-all: *',
    '  --target-urls <urls>           Comma-separated list of target URLs.',
    '',
    'Output (choose one; default: summary + findings + chains):',
    '  --attack-report                Full JSON report (all sections).',
    '  --top-exploitability-rank      Sorted verified findings by score (max 20).',
    '  --elite-matrix                 Hybrid exploit chains with reproduction steps.',
    '',
    'Session / Auth:',
    '  --cookie "name=value"          Session cookie (repeatable).',
    '  --bearer-token <token>         Authorization: Bearer <token>.',
    '  --header "Name: Value"         Custom request header (repeatable).',
    '',
    'Performance:',
    '  --concurrency <n>              Parallel URL probes (default: 3, max: 20).',
    '  --rate-limit <ms>              Per-host delay between requests (default: 300ms).',
    '  --timeout <ms>                 HTTP request timeout (default: 7000ms).',
    '',
    'Integration:',
    '  --from-httpx-pipe              Read httpx NDJSON from stdin instead of --target-urls.',
    '  --check-ssrf                   Enable SSRF detection via parameter injection.',
    '  --check-takeover               Enable subdomain takeover fingerprint detection.',
    '',
    '  -h, --help                     Print this help.',
    '',
    'Examples:',
    '  maniny --allow-hosts api.example.com \\',
    '         --target-urls "https://api.example.com/v1/users?id=1" \\',
    '         --attack-report',
    '',
    '  maniny --allow-hosts "*.example.com" \\',
    '         --target-urls "https://admin.example.com/login" \\',
    '         --cookie "session=abc123" --bearer-token "eyJ..." \\',
    '         --elite-matrix',
    '',
    '  httpx -l targets.txt -json | \\',
    '  maniny --allow-hosts "*.example.com" --from-httpx-pipe --attack-report',
    '',
    'RESPONSIBLE USE: Run only against systems you own or have explicit written permission to test.',
    '',
  ].join('\n'));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  if (args.help) { printUsage(); process.exit(0); }

  if (!args.allowHosts) {
    errorOut('--allow-hosts is required. Use --help for usage.');
    process.exit(1);
  }

  const allowedHosts = parseAllowedHosts(args.allowHosts);
  if (allowedHosts.length === 0) {
    errorOut('--allow-hosts produced an empty host list.');
    process.exit(1);
  }

  const targetUrls = args.fromHttpxPipe
    ? []  // runner reads from stdin
    : (args.targetUrls ?? '').split(',').map(u => u.trim()).filter(Boolean);

  if (!args.fromHttpxPipe && targetUrls.length === 0) {
    errorOut('--target-urls is required (or use --from-httpx-pipe). Use --help for usage.');
    process.exit(1);
  }

  const config: ScanConfig = {
    allowedHosts,
    targetUrls,
    timeoutMs:     args.timeoutMs,
    topRank:       args.topRank,
    attackReport:  args.attackReport,
    eliteMatrix:   args.eliteMatrix,
    session:       buildSessionConfig(args),
    rateLimitMs:   args.rateLimitMs,
    concurrency:   args.concurrency,
    fromHttpxPipe:  args.fromHttpxPipe,
    checkSsrf:      args.checkSsrf,
    checkTakeover:  args.checkTakeover,
  };

  const report = await runScan(config);

  if (args.attackReport)  { printJson(formatAttackReport(report)); return; }
  if (args.topRank)       { printJson(formatTopRank(report.findings)); return; }
  if (args.eliteMatrix)   { printJson(formatEliteMatrix(report.hybridChains)); return; }
  printJson(formatDefault(report));
}

main().catch(err => {
  errorOut(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
