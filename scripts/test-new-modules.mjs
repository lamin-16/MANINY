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
  strictEqual(json.version, '0.3.0');
});

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------
console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);
if (failed > 0) process.exit(1);
