#!/usr/bin/env node
// MANINY DIGITAL — Smoke test suite.
// Tests CLI output shape and pure utility functions after `npm run build`.
// All tests run offline; no real network access required.

import { execSync } from 'node:child_process';
import { strictEqual, ok, doesNotThrow } from 'node:assert';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗  ${name}`);
    console.error(`     ${err.message}`);
    failed++;
  }
}

function runCli(...args) {
  const cmd = `node ./dist/cli.js ${args.join(' ')}`;
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 15_000 });
  } catch (err) {
    // execSync throws on non-zero exit; return stdout anyway if available
    return err.stdout ?? '';
  }
}

function parseJson(str) {
  try {
    return JSON.parse(str);
  } catch {
    throw new Error(`Output is not valid JSON:\n${str.slice(0, 300)}`);
  }
}

// ---------------------------------------------------------------------------
// Suite 1: Pure utility imports
// ---------------------------------------------------------------------------

console.log('\n── Suite 1: Utility imports ──');

const { uniqueById, generateFindingId, generateScanId } = await import('../dist/utils/deduplicator.js');
const { isHostAllowed, filterAllowedUrls, parseAllowedHosts } = await import('../dist/utils/host-validator.js');

test('uniqueById removes duplicates', () => {
  const items = [{ id: 'a' }, { id: 'b' }, { id: 'a' }, { id: 'c' }];
  const result = uniqueById(items);
  strictEqual(result.length, 3);
  strictEqual(result[0].id, 'a');
  strictEqual(result[1].id, 'b');
  strictEqual(result[2].id, 'c');
});

test('uniqueById preserves order', () => {
  const items = [{ id: 'z' }, { id: 'a' }, { id: 'z' }];
  const result = uniqueById(items);
  strictEqual(result[0].id, 'z');
  strictEqual(result[1].id, 'a');
});

test('uniqueById handles empty array', () => {
  const result = uniqueById([]);
  strictEqual(result.length, 0);
});

test('generateFindingId is deterministic', () => {
  const id1 = generateFindingId('example.com', '/api', 'cors', 'CORS Issue');
  const id2 = generateFindingId('example.com', '/api', 'cors', 'CORS Issue');
  strictEqual(id1, id2);
  ok(id1.startsWith('finding-'));
});

test('generateFindingId differs on different inputs', () => {
  const id1 = generateFindingId('example.com', '/a', 'cors', 'T');
  const id2 = generateFindingId('example.com', '/b', 'cors', 'T');
  ok(id1 !== id2);
});

test('generateScanId returns non-empty string', () => {
  const id = generateScanId();
  ok(typeof id === 'string');
  ok(id.startsWith('scan-'));
  ok(id.length > 10);
});

// ---------------------------------------------------------------------------
// Suite 2: Host validator
// ---------------------------------------------------------------------------

console.log('\n── Suite 2: Host validator ──');

test('isHostAllowed — exact match', () => {
  ok(isHostAllowed('example.com', ['example.com']));
});

test('isHostAllowed — subdomain wildcard', () => {
  ok(isHostAllowed('sub.example.com', ['*.example.com']));
});

test('isHostAllowed — wildcard matches apex', () => {
  ok(isHostAllowed('example.com', ['*.example.com']));
});

test('isHostAllowed — denied when no match', () => {
  ok(!isHostAllowed('evil.com', ['example.com']));
});

test('isHostAllowed — empty allow list denies all', () => {
  ok(!isHostAllowed('example.com', []));
});

test('isHostAllowed — catch-all *', () => {
  ok(isHostAllowed('anything.example.com', ['*']));
});

test('filterAllowedUrls partitions correctly', () => {
  const urls = [
    'https://example.com/api',
    'https://evil.com/attack',
    'https://sub.example.com/data',
  ];
  const { allowed, rejected } = filterAllowedUrls(urls, ['*.example.com', 'example.com']);
  strictEqual(allowed.length, 2);
  strictEqual(rejected.length, 1);
  ok(rejected[0].includes('evil.com'));
});

test('parseAllowedHosts splits and trims', () => {
  const hosts = parseAllowedHosts('  example.com , evil.com ,  *.test.com  ');
  strictEqual(hosts.length, 3);
  strictEqual(hosts[0], 'example.com');
  strictEqual(hosts[2], '*.test.com');
});

// ---------------------------------------------------------------------------
// Suite 3: CLI output shape
// ---------------------------------------------------------------------------

console.log('\n── Suite 3: CLI output shape ──');

test('CLI --help exits cleanly and prints usage', () => {
  const out = execSync('node ./dist/cli.js --help', { encoding: 'utf-8', timeout: 5_000 });
  ok(out.includes('--allow-hosts'));
  ok(out.includes('--target-urls'));
  ok(out.includes('--attack-report'));
});

test('CLI default output is valid JSON with expected keys', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999',
    '--timeout 500'
  );
  const json = parseJson(out);
  ok('scanId' in json, 'missing scanId');
  ok('timestamp' in json, 'missing timestamp');
  ok('summary' in json, 'missing summary');
  ok('findings' in json, 'missing findings');
  ok('hybridChains' in json, 'missing hybridChains');
  ok(Array.isArray(json.findings), 'findings should be an array');
  ok(Array.isArray(json.hybridChains), 'hybridChains should be an array');
});

test('CLI --attack-report includes all report sections', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999',
    '--attack-report',
    '--timeout 500'
  );
  const json = parseJson(out);
  ok('agents' in json, 'missing agents');
  ok('compliance' in json, 'missing compliance');
  ok('topExploitabilityRank' in json, 'missing topExploitabilityRank');
  ok('target' in json, 'missing target');
  ok('version' in json, 'missing version');
});

test('CLI --top-exploitability-rank returns an array', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999',
    '--top-exploitability-rank',
    '--timeout 500'
  );
  const json = parseJson(out);
  ok(Array.isArray(json), '--top-exploitability-rank should return an array');
});

test('CLI --elite-matrix returns an array', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999',
    '--elite-matrix',
    '--timeout 500'
  );
  const json = parseJson(out);
  ok(Array.isArray(json), '--elite-matrix should return an array');
});

test('CLI summary has correct numeric fields', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999',
    '--timeout 500'
  );
  const json = parseJson(out);
  const s = json.summary;
  ok(typeof s.total === 'number');
  ok(typeof s.critical === 'number');
  ok(typeof s.high === 'number');
  ok(typeof s.chains === 'number');
  strictEqual(s.total, s.critical + s.high + s.medium + s.low + s.info);
});

test('CLI rejects denied hosts (no host in allow list → empty findings)', () => {
  const out = runCli(
    '--allow-hosts allowed.example.com',
    '--target-urls http://localhost:19999',
    '--timeout 500'
  );
  const json = parseJson(out);
  // localhost is not in the allow list → 0 URLs scanned → empty findings
  strictEqual(json.findings.length, 0);
});

// ---------------------------------------------------------------------------
// Suite 4: Static stage output shapes
// ---------------------------------------------------------------------------

console.log('\n── Suite 4: Static stage shapes ──');

const { runHeadersStage } = await import('../dist/stages/headers-stage.js');
const { runAuthStage } = await import('../dist/stages/auth-stage.js');
const { runInjectionStage } = await import('../dist/stages/injection-stage.js');
const { runCorsStage } = await import('../dist/stages/cors-stage.js');

test('runHeadersStage flags plain HTTP', () => {
  const result = runHeadersStage('http://example.com/index.html');
  ok(result.findings.some(f => f.title.includes('Plaintext')));
});

test('runHeadersStage flags .bak extension', () => {
  const result = runHeadersStage('https://example.com/backup.bak');
  ok(result.findings.some(f => f.title.includes('Sensitive File')));
});

test('runAuthStage flags admin path', () => {
  const result = runAuthStage('https://example.com/admin/users');
  ok(result.findings.some(f => f.category === 'auth'));
});

test('runAuthStage flags token in query string', () => {
  const result = runAuthStage('https://example.com/api?token=abc123');
  ok(result.findings.some(f => f.title.includes('Token') || f.title.includes('Credential')));
});

test('runInjectionStage flags id parameter', () => {
  const result = runInjectionStage('https://example.com/page?id=1');
  ok(result.findings.some(f => f.category === 'injection'));
});

test('runCorsStage flags /api/ path', () => {
  const result = runCorsStage('https://example.com/api/v1/users');
  ok(result.findings.some(f => f.category === 'cors'));
});

test('All findings have required fields', () => {
  const all = [
    ...runHeadersStage('http://example.com/?id=1&token=x&redirect=/').findings,
    ...runAuthStage('http://example.com/?id=1&token=x&redirect=/').findings,
    ...runInjectionStage('http://example.com/?id=1&token=x&redirect=/').findings,
    ...runCorsStage('http://example.com/api/v1?id=1').findings,
  ];
  for (const f of all) {
    ok(typeof f.id === 'string' && f.id.length > 0, `finding.id missing: ${JSON.stringify(f)}`);
    ok(typeof f.host === 'string', 'finding.host missing');
    ok(typeof f.severity === 'string', 'finding.severity missing');
    ok(typeof f.exploitability === 'number', 'finding.exploitability missing');
    ok(f.exploitability >= 0 && f.exploitability <= 100, 'exploitability out of range');
    ok(Array.isArray(f.reproductionSteps), 'reproductionSteps must be array');
  }
});

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);

if (failed > 0) {
  process.exit(1);
}
