#!/usr/bin/env node
// MANINY DIGITAL — Tests for v0.3.0 new modules.

import { strictEqual, ok, deepStrictEqual } from 'node:assert';

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log(`  ✓  ${name}`); passed++; }
  catch (err) { console.error(`  ✗  ${name}\n     ${err.message}`); failed++; }
}

// ---------------------------------------------------------------------------
// SessionManager
// ---------------------------------------------------------------------------
console.log('\n── SessionManager ──');
const { SessionManager } = await import('../dist/core/session-manager.js');

test('buildHeaders returns Bearer token', () => {
  const sm = new SessionManager({ cookies: {}, bearerToken: 'tok123', customHeaders: {} });
  const h = sm.buildHeaders();
  strictEqual(h['Authorization'], 'Bearer tok123');
});

test('buildHeaders returns cookie string', () => {
  const sm = new SessionManager({ cookies: { session: 'abc', csrfToken: 'xyz' }, customHeaders: {} });
  const h = sm.buildHeaders();
  ok(h['Cookie'].includes('session=abc'));
  ok(h['Cookie'].includes('csrfToken=xyz'));
});

test('buildHeaders returns custom headers', () => {
  const sm = new SessionManager({ cookies: {}, customHeaders: { 'X-Custom': 'value' } });
  strictEqual(sm.buildHeaders()['X-Custom'], 'value');
});

test('updateFromSetCookie absorbs cookies', () => {
  const sm = new SessionManager({ cookies: {}, customHeaders: {} });
  sm.updateFromSetCookie(['session=new123; Path=/; HttpOnly; Secure']);
  ok(sm.buildHeaders()['Cookie'].includes('session=new123'));
});

test('updateFromSetCookie handles array', () => {
  const sm = new SessionManager({ cookies: {}, customHeaders: {} });
  sm.updateFromSetCookie(['a=1; Path=/', 'b=2; HttpOnly']);
  const h = sm.buildHeaders()['Cookie'];
  ok(h.includes('a=1') && h.includes('b=2'));
});

test('empty() produces no headers', () => {
  const sm = SessionManager.empty();
  const h = sm.buildHeaders();
  ok(!h['Authorization']);
  ok(!h['Cookie']);
});

test('hasBearerToken is true when set', () => {
  const sm = new SessionManager({ cookies: {}, bearerToken: 'tok', customHeaders: {} });
  ok(sm.hasBearerToken);
});

test('hasCookies is false when empty', () => {
  ok(!SessionManager.empty().hasCookies);
});

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------
console.log('\n── RateLimiter ──');
const { RateLimiter } = await import('../dist/core/rate-limiter.js');

test('unlimited returns immediately', async () => {
  const rl = RateLimiter.unlimited();
  const before = Date.now();
  await rl.throttle('example.com');
  ok(Date.now() - before < 50);
});

test('mark then throttle respects delay', async () => {
  const rl = new RateLimiter(100);
  rl.mark('host.com');
  const before = Date.now();
  await rl.throttle('host.com');
  ok(Date.now() - before >= 90); // allow small timer variance
});

test('different hosts do not share delay', async () => {
  const rl = new RateLimiter(500);
  rl.mark('a.com');
  const before = Date.now();
  await rl.throttle('b.com'); // different host → no delay
  ok(Date.now() - before < 50);
});

// ---------------------------------------------------------------------------
// TechFingerprinter
// ---------------------------------------------------------------------------
console.log('\n── TechFingerprinter ──');
const { fingerprintTech, techFindingsFrom } = await import('../dist/core/tech-fingerprinter.js');

test('detects Nginx from server header', () => {
  const fp = fingerprintTech('example.com', { server: 'nginx/1.24.0' }, '');
  ok(fp.techs.some(t => t.name === 'Nginx'));
});

test('extracts Nginx version', () => {
  const fp = fingerprintTech('example.com', { server: 'nginx/1.24.0' }, '');
  const nginx = fp.techs.find(t => t.name === 'Nginx');
  strictEqual(nginx?.version, '1.24.0');
});

test('detects PHP from x-powered-by', () => {
  const fp = fingerprintTech('example.com', { 'x-powered-by': 'PHP/8.2.1' }, '');
  ok(fp.techs.some(t => t.name === 'PHP'));
});

test('detects Cloudflare from cf-ray', () => {
  const fp = fingerprintTech('example.com', { 'cf-ray': '8abc-FRA' }, '');
  ok(fp.techs.some(t => t.name === 'Cloudflare'));
  ok(fp.wafDetected === false); // CF is CDN, not WAF
});

test('detects Sucuri WAF', () => {
  const fp = fingerprintTech('example.com', { 'x-sucuri-id': '12345' }, '');
  ok(fp.techs.some(t => t.name === 'Sucuri'));
  ok(fp.wafDetected);
});

test('detects WAF from body pattern', () => {
  const fp = fingerprintTech('example.com', {}, 'Incapsula incident ID: 123456');
  ok(fp.wafDetected);
});

test('no tech → empty array + wafDetected false', () => {
  const fp = fingerprintTech('example.com', {}, '');
  strictEqual(fp.techs.length, 0);
  strictEqual(fp.wafDetected, false);
});

test('version disclosure → low finding', () => {
  const fp = fingerprintTech('example.com', { server: 'Apache/2.4.51' }, '');
  const findings = techFindingsFrom('https://example.com/', 'example.com', '/', fp);
  ok(findings.some(f => f.title.includes('Version Disclosure') && f.severity === 'low'));
});

test('WAF detected → info finding', () => {
  const fp = fingerprintTech('example.com', { 'x-sucuri-id': '99' }, '');
  const findings = techFindingsFrom('https://example.com/', 'example.com', '/', fp);
  ok(findings.some(f => f.severity === 'info' && f.title.includes('WAF')));
});

// ---------------------------------------------------------------------------
// JWT Analyzer
// ---------------------------------------------------------------------------
console.log('\n── JWT Analyzer ──');
const { analyzeJwt, extractJwts } = await import('../dist/core/jwt-analyzer.js');

// Build a real alg:none JWT
function makeJwt(header, payload) {
  const enc = obj => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${enc(header)}.${enc(payload)}.`;
}

const algNoneJwt   = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: 'user1', admin: false });
const hs256Jwt     = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'user1' });
const expiredJwt   = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'user1', exp: 1000000 });
const sensJwt      = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'user1', password: 'hunter2' });

test('detects alg:none as critical', () => {
  const f = analyzeJwt(algNoneJwt, 'https://example.com/', 'example.com', '/');
  ok(f.some(x => x.severity === 'critical' && x.title.includes('none')));
});

test('detects HS256 as medium', () => {
  const f = analyzeJwt(hs256Jwt, 'https://example.com/', 'example.com', '/');
  ok(f.some(x => x.severity === 'medium' && x.title.includes('HS256')));
});

test('detects expired token as high', () => {
  const f = analyzeJwt(expiredJwt, 'https://example.com/', 'example.com', '/');
  ok(f.some(x => x.severity === 'high' && x.title.includes('Expired')));
});

test('detects sensitive claim in payload', () => {
  const f = analyzeJwt(sensJwt, 'https://example.com/', 'example.com', '/');
  ok(f.some(x => x.title.includes('Sensitive Data')));
});

test('returns empty for invalid token', () => {
  const f = analyzeJwt('notajwt', 'https://example.com/', 'example.com', '/');
  strictEqual(f.length, 0);
});

test('extractJwts finds Bearer token from header', () => {
  const headers = { authorization: `Bearer ${hs256Jwt}` };
  const tokens = extractJwts(headers, '');
  ok(tokens.includes(hs256Jwt));
});

test('extractJwts finds JWT embedded in body', () => {
  const body = `{"token": "${hs256Jwt}"}`;
  const tokens = extractJwts({}, body);
  ok(tokens.length > 0);
});

// ---------------------------------------------------------------------------
// New CLI flags
// ---------------------------------------------------------------------------
console.log('\n── CLI new flags ──');
import { execSync } from 'node:child_process';

function runCli(...args) {
  try {
    return execSync(`node ./dist/cli.js ${args.join(' ')}`,
      { encoding: 'utf-8', timeout: 10_000 });
  } catch (e) { return e.stdout ?? ''; }
}

test('--help shows new flags', () => {
  const out = execSync('node ./dist/cli.js --help', { encoding: 'utf-8' });
  ok(out.includes('--cookie'));
  ok(out.includes('--bearer-token'));
  ok(out.includes('--concurrency'));
  ok(out.includes('--rate-limit'));
  ok(out.includes('--from-httpx-pipe'));
});

test('report includes techFingerprints array', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999',
    '--attack-report --timeout 400'
  );
  const json = JSON.parse(out);
  ok(Array.isArray(json.techFingerprints), 'techFingerprints should be array');
});

test('version is 0.3.0', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999',
    '--timeout 400'
  );
  const json = JSON.parse(out);
  strictEqual(json.version, '0.4.0');
});

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------
console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);

// ---------------------------------------------------------------------------
// SSRF Prober — unit tests (offline, no real SSRF needed)
// ---------------------------------------------------------------------------
console.log('\n── SSRF Prober ──');
const { runSsrfProbe } = await import('../dist/core/ssrf-prober.js');

test('runSsrfProbe returns empty array when no params', async () => {
  const findings = await runSsrfProbe('https://example.com/page');
  ok(Array.isArray(findings));
  strictEqual(findings.length, 0);
});

test('runSsrfProbe returns empty array for unparseable URL', async () => {
  const findings = await runSsrfProbe('not-a-url');
  strictEqual(findings.length, 0);
});

test('runSsrfProbe handles network error gracefully', async () => {
  const findings = await runSsrfProbe(
    'http://localhost:19999/page?url=test',
    { timeoutMs: 300 }
  );
  ok(Array.isArray(findings));
});

// ---------------------------------------------------------------------------
// Subdomain Takeover — unit tests (signature matching without network)
// ---------------------------------------------------------------------------
console.log('\n── Subdomain Takeover ──');
const { checkSubdomainTakeover, checkSubdomainTakeovers } = await import('../dist/core/subdomain-takeover.js');

test('checkSubdomainTakeover returns empty on unparseable URL', async () => {
  const f = await checkSubdomainTakeover('not-a-url');
  strictEqual(f.length, 0);
});

test('checkSubdomainTakeover handles network error gracefully', async () => {
  const f = await checkSubdomainTakeover('http://localhost:19999/', { timeoutMs: 300 });
  ok(Array.isArray(f));
});

test('checkSubdomainTakeovers processes multiple URLs', async () => {
  const urls = [
    'http://localhost:19998/',
    'http://localhost:19999/',
  ];
  const f = await checkSubdomainTakeovers(urls, { timeoutMs: 300 });
  ok(Array.isArray(f));
});

// ---------------------------------------------------------------------------
// New CLI flags
// ---------------------------------------------------------------------------
console.log('\n── CLI v0.4.0 flags ──');

test('--check-ssrf flag appears in --help', () => {
  const out = execSync('node ./dist/cli.js --help', { encoding: 'utf-8' });
  ok(out.includes('--check-ssrf'), '--check-ssrf missing from help');
});

test('--check-takeover flag appears in --help', () => {
  const out = execSync('node ./dist/cli.js --help', { encoding: 'utf-8' });
  ok(out.includes('--check-takeover'), '--check-takeover missing from help');
});

test('scan with --check-ssrf produces valid JSON', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999/?url=x',
    '--check-ssrf --timeout 400'
  );
  const json = JSON.parse(out);
  ok('findings' in json);
});

test('scan with --check-takeover produces valid JSON', () => {
  const out = runCli(
    '--allow-hosts localhost',
    '--target-urls http://localhost:19999/',
    '--check-takeover --timeout 400'
  );
  const json = JSON.parse(out);
  ok('findings' in json);
});

// ---------------------------------------------------------------------------
// GitHub Actions workflows exist
// ---------------------------------------------------------------------------
console.log('\n── CI/CD Workflows ──');
import { existsSync } from 'node:fs';

test('ci.yml exists', () => {
  ok(existsSync('.github/workflows/ci.yml'));
});

test('release.yml exists', () => {
  ok(existsSync('.github/workflows/release.yml'));
});

import { readFileSync as readFs } from 'node:fs';

test('ci.yml contains Node 20 and 22 matrix', () => {
  const ci = readFs('.github/workflows/ci.yml', 'utf-8');
  ok(ci.includes("'20'") && ci.includes("'22'"));
});

test('release.yml triggers on version tags', () => {
  const rel = readFs('.github/workflows/release.yml', 'utf-8');
  ok(rel.includes("tags: ['v*']"));
});
