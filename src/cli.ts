#!/usr/bin/env node
// MANINY DIGITAL — CLI entry point.
// Parses process.argv, validates allow-host boundaries, invokes the runner,
// and writes structured JSON to stdout based on the active output flag.
// All errors and warnings are written to stderr only.

import { parseAllowedHosts } from './utils/host-validator.js';
import {
  printJson,
  errorOut,
  warn,
  formatAttackReport,
  formatTopRank,
  formatEliteMatrix,
  formatDefault,
} from './utils/json-output.js';
import { runScan } from './runner.js';
import type { ScanConfig } from './types.js';

// ---------------------------------------------------------------------------
// Argument parsing (no external deps)
// ---------------------------------------------------------------------------

interface ParsedArgs {
  allowHosts: string | null;
  targetUrls: string | null;
  topRank: boolean;
  attackReport: boolean;
  eliteMatrix: boolean;
  timeoutMs: number;
  help: boolean;
}

function parseArgs(argv: string[]): ParsedArgs {
  const args = argv.slice(2);
  const result: ParsedArgs = {
    allowHosts: null,
    targetUrls: null,
    topRank: false,
    attackReport: false,
    eliteMatrix: false,
    timeoutMs: 7_000,
    help: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg) continue;

    if (arg === '-h' || arg === '--help') {
      result.help = true;
      continue;
    }

    if (arg === '--top-exploitability-rank') {
      result.topRank = true;
      continue;
    }

    if (arg === '--attack-report') {
      result.attackReport = true;
      continue;
    }

    if (arg === '--elite-matrix') {
      result.eliteMatrix = true;
      continue;
    }

    // Handle --key=value and --key value forms
    const eqIndex = arg.indexOf('=');
    if (arg.startsWith('--') && eqIndex !== -1) {
      const key = arg.slice(2, eqIndex);
      const val = arg.slice(eqIndex + 1);
      setNamedArg(result, key, val);
      continue;
    }

    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const nextArg = args[i + 1];
      if (nextArg !== undefined && !nextArg.startsWith('--')) {
        setNamedArg(result, key, nextArg);
        i++;
      }
    }
  }

  return result;
}

function setNamedArg(result: ParsedArgs, key: string, value: string): void {
  switch (key) {
    case 'allow-hosts':
      result.allowHosts = value;
      break;
    case 'target-urls':
      result.targetUrls = value;
      break;
    case 'timeout':
      result.timeoutMs = Math.max(1_000, parseInt(value, 10) || 7_000);
      break;
    default:
      warn(`Unknown flag: --${key}`);
  }
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

function printUsage(): void {
  process.stdout.write(
    [
      '',
      'MANINY DIGITAL v0.2.0 — CLI Security Scanner',
      '',
      'Usage:',
      '  maniny --allow-hosts <hosts> --target-urls <urls> [flags]',
      '',
      'Required:',
      '  --allow-hosts <hosts>    Comma-separated allow-list of target hostnames.',
      '                           Wildcards: *.example.com  Catch-all: *',
      '  --target-urls <urls>     Comma-separated list of target URLs to scan.',
      '',
      'Output flags (choose one; default: summary + findings + chains):',
      '  --attack-report          Full JSON attack report (all fields).',
      '  --top-exploitability-rank  Sorted list of verified findings by score.',
      '  --elite-matrix           Hybrid exploit chains with reproduction steps.',
      '',
      'Options:',
      '  --timeout <ms>           HTTP request timeout in milliseconds (default 7000).',
      '  -h, --help               Print this help text.',
      '',
      'Examples:',
      '  maniny --allow-hosts example.com --target-urls https://example.com --attack-report',
      '  maniny --allow-hosts "*.example.com" --target-urls "https://api.example.com/v1" \\',
      '         --top-exploitability-rank',
      '',
      'Responsible use: Run only against systems you are explicitly authorised to test.',
      '',
    ].join('\n')
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv);

  if (args.help) {
    printUsage();
    process.exit(0);
  }

  if (!args.allowHosts) {
    errorOut('--allow-hosts is required. Use --help for usage.');
    process.exit(1);
  }

  if (!args.targetUrls) {
    errorOut('--target-urls is required. Use --help for usage.');
    process.exit(1);
  }

  const allowedHosts = parseAllowedHosts(args.allowHosts);
  if (allowedHosts.length === 0) {
    errorOut('--allow-hosts value produced an empty host list after parsing.');
    process.exit(1);
  }

  const targetUrls = args.targetUrls
    .split(',')
    .map(u => u.trim())
    .filter(u => u.length > 0);

  if (targetUrls.length === 0) {
    errorOut('--target-urls value produced an empty URL list after parsing.');
    process.exit(1);
  }

  const config: ScanConfig = {
    allowedHosts,
    targetUrls,
    timeoutMs: args.timeoutMs,
    topRank: args.topRank,
    attackReport: args.attackReport,
    eliteMatrix: args.eliteMatrix,
  };

  const report = await runScan(config);

  // Select output format based on active flags.
  // Priority: --attack-report > --top-exploitability-rank > --elite-matrix > default.
  if (args.attackReport) {
    printJson(formatAttackReport(report));
    return;
  }

  if (args.topRank) {
    printJson(formatTopRank(report.findings));
    return;
  }

  if (args.eliteMatrix) {
    printJson(formatEliteMatrix(report.hybridChains));
    return;
  }

  printJson(formatDefault(report));
}

main().catch(err => {
  errorOut(`Unhandled error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
