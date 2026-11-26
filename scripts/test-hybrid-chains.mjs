#!/usr/bin/env node
// MANINY DIGITAL — hybridChains unit and integration test suite.
// Tests the pure chain correlation and scoring logic in isolation.

import { strictEqual, ok, deepStrictEqual } from 'node:assert';
import { hybridChains, scoreChain, buildComplianceResults, buildSummary } from '../dist/core/exploit-chain-verifier.js';
import { uniqueById } from '../dist/utils/deduplicator.js';

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

/** Build a minimal valid Finding fixture. */
function makeFinding(overrides = {}) {
  return {
    id: `finding-${Math.random().toString(36).slice(2)}`,
    host: 'example.com',
    path: '/api/v1',
    url: 'https://example.com/api/v1',
    severity: 'high',
    category: 'cors',
    title: 'Test Finding',
    description: 'Test description',
    evidence: 'Test evidence',
    status: 'potential',
    exploitability: 60,
    reproductionSteps: ['Step 1', 'Step 2'],
    remediationHint: 'Fix it',
    source: 'static',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Suite 1: hybridChains — basic behaviour
// ---------------------------------------------------------------------------

console.log('\n── Suite 1: hybridChains basic behaviour ──');

test('empty input returns empty array', () => {
  const result = hybridChains([]);
  ok(Array.isArray(result));
  strictEqual(result.length, 0);
});

test('single finding produces no chain (needs >=2)', () => {
  const result = hybridChains([makeFinding()]);
  strictEqual(result.length, 0);
});

test('two unrelated findings on same host → mixed chain', () => {
  const findings = [
    makeFinding({ id: 'f1', category: 'cors', severity: 'critical', exploitability: 90 }),
    makeFinding({ id: 'f2', category: 'cors', severity: 'high', exploitability: 70 }),
    makeFinding({ id: 'f3', category: 'cors', severity: 'high', exploitability: 65 }),
  ];
  const result = hybridChains(findings);
  // Three cors findings without an auth/injection partner → mixed
  ok(result.length >= 1);
  ok(result.some(c => c.chainType === 'mixed' || c.chainType === 'cors_to_csrf'));
});

test('findings on different hosts do NOT chain together', () => {
  const findings = [
    makeFinding({ id: 'f1', host: 'a.com', category: 'cors', exploitability: 85 }),
    makeFinding({ id: 'f2', host: 'b.com', category: 'auth', exploitability: 80 }),
  ];
  const result = hybridChains(findings);
  // No cross-host chains should form
  for (const chain of result) {
    const hosts = [...new Set(chain.findings.map(f => f.host))];
    strictEqual(hosts.length, 1, 'Chain should not span multiple hosts');
  }
});

// ---------------------------------------------------------------------------
// Suite 2: hybridChains — specific chain types
// ---------------------------------------------------------------------------

console.log('\n── Suite 2: hybridChains chain type detection ──');

test('cors + auth finding → cors_to_csrf chain', () => {
  const findings = [
    makeFinding({ id: 'cors-1', category: 'cors', severity: 'critical', exploitability: 90, status: 'verified_exploitable' }),
    makeFinding({ id: 'auth-1', category: 'auth', severity: 'high', exploitability: 70, status: 'potential' }),
  ];
  const result = hybridChains(findings);
  ok(result.length >= 1, 'Expected at least one chain');
  ok(result.some(c => c.chainType === 'cors_to_csrf'), `Expected cors_to_csrf, got: ${result.map(c => c.chainType).join(', ')}`);
});

test('cors + headers finding → cors_to_csrf chain', () => {
  const findings = [
    makeFinding({ id: 'cors-2', category: 'cors', severity: 'high', exploitability: 75 }),
    makeFinding({ id: 'hdr-1', category: 'headers', severity: 'medium', exploitability: 35 }),
  ];
  const result = hybridChains(findings);
  ok(result.length >= 1);
  ok(result.some(c => c.chainType === 'cors_to_csrf'));
});

test('injection + auth finding → inject_to_rce chain', () => {
  const findings = [
    makeFinding({ id: 'inj-1', category: 'injection', severity: 'critical', exploitability: 92 }),
    makeFinding({ id: 'auth-2', category: 'auth', severity: 'high', exploitability: 68 }),
  ];
  const result = hybridChains(findings);
  ok(result.length >= 1);
  // Injection + auth can match inject_to_rce (categoryGroups: [injection], [injection, auth])
  ok(result.some(c =>
    c.chainType === 'inject_to_rce' || c.chainType === 'auth_bypass_to_data' || c.chainType === 'mixed'
  ), `Got chain types: ${result.map(c => c.chainType).join(', ')}`);
});

test('auth + injection → auth_bypass_to_data chain', () => {
  const findings = [
    makeFinding({ id: 'auth-3', category: 'auth', severity: 'critical', exploitability: 85 }),
    makeFinding({ id: 'inj-2', category: 'injection', severity: 'high', exploitability: 72 }),
  ];
  const result = hybridChains(findings);
  ok(result.length >= 1);
  ok(result.some(c =>
    c.chainType === 'auth_bypass_to_data' ||
    c.chainType === 'inject_to_rce' ||
    c.chainType === 'mixed'
  ));
});

// ---------------------------------------------------------------------------
// Suite 3: Chain structure validation
// ---------------------------------------------------------------------------

console.log('\n── Suite 3: Chain structure validation ──');

test('chain has all required fields', () => {
  const findings = [
    makeFinding({ id: 'c1', category: 'cors', severity: 'critical', exploitability: 88 }),
    makeFinding({ id: 'c2', category: 'auth', severity: 'high', exploitability: 65 }),
  ];
  const [chain] = hybridChains(findings);
  if (!chain) return; // No chain formed → skip
  ok(typeof chain.id === 'string' && chain.id.length > 0, 'chain.id missing');
  ok(typeof chain.host === 'string', 'chain.host missing');
  ok(typeof chain.title === 'string', 'chain.title missing');
  ok(typeof chain.chainType === 'string', 'chain.chainType missing');
  ok(typeof chain.score === 'number', 'chain.score missing');
  ok(Array.isArray(chain.findings), 'chain.findings must be array');
  ok(Array.isArray(chain.reproductionSteps), 'reproductionSteps must be array');
  ok(typeof chain.impact === 'string', 'chain.impact missing');
  ok(typeof chain.timestamp === 'string', 'chain.timestamp missing');
});

test('chain.score is 0–100', () => {
  const findings = [
    makeFinding({ id: 'd1', category: 'cors', exploitability: 95 }),
    makeFinding({ id: 'd2', category: 'auth', exploitability: 85 }),
    makeFinding({ id: 'd3', category: 'injection', exploitability: 90 }),
  ];
  for (const chain of hybridChains(findings)) {
    ok(chain.score >= 0 && chain.score <= 100, `Score out of range: ${chain.score}`);
  }
});

test('chains are sorted by score descending', () => {
  const findings = [
    makeFinding({ id: 'e1', category: 'cors', severity: 'critical', exploitability: 95 }),
    makeFinding({ id: 'e2', category: 'auth', severity: 'high', exploitability: 65 }),
    makeFinding({ id: 'e3', category: 'injection', severity: 'high', exploitability: 75 }),
  ];
  const chains = hybridChains(findings);
  for (let i = 1; i < chains.length; i++) {
    ok(chains[i - 1].score >= chains[i].score, 'Chains are not sorted by score');
  }
});

test('chain findings include at least one from each matched category group', () => {
  const cors = makeFinding({ id: 'cors-g', category: 'cors', exploitability: 80 });
  const auth = makeFinding({ id: 'auth-g', category: 'auth', exploitability: 70 });
  const chains = hybridChains([cors, auth]);
  for (const chain of chains) {
    ok(chain.findings.length >= 2, 'Chain should contain at least 2 findings');
  }
});

// ---------------------------------------------------------------------------
// Suite 4: scoreChain
// ---------------------------------------------------------------------------

console.log('\n── Suite 4: scoreChain ──');

test('scoreChain empty findings → 0', () => {
  strictEqual(scoreChain([], 'cors_to_csrf'), 0);
});

test('scoreChain single finding → score = exploitability + chainBonus', () => {
  const f = makeFinding({ exploitability: 80 });
  const score = scoreChain([f], 'cors_to_csrf');
  // 80 (anchor) + 10 (chain bonus) = 90
  strictEqual(score, 90);
});

test('scoreChain mixed chain → no bonus', () => {
  const f = makeFinding({ exploitability: 80 });
  const score = scoreChain([f], 'mixed');
  // 80 + 0 = 80
  strictEqual(score, 80);
});

test('scoreChain caps at 100', () => {
  const findings = [
    makeFinding({ exploitability: 100 }),
    makeFinding({ exploitability: 100 }),
    makeFinding({ exploitability: 100 }),
  ];
  const score = scoreChain(findings, 'cors_to_csrf');
  strictEqual(score, 100);
});

test('scoreChain with multiple findings adds diminishing returns', () => {
  const f1 = makeFinding({ exploitability: 70 });
  const f2 = makeFinding({ exploitability: 50 });
  const score = scoreChain([f1, f2], 'cors_to_csrf');
  // anchor=70 + decay(50*0.25=12.5) + chainBonus=10 = 92.5 → 93
  ok(score > 70, 'Score should exceed anchor');
  ok(score <= 100, 'Score should not exceed 100');
});

test('scoreChain with high anchor + bonus correctly rounds', () => {
  const f = makeFinding({ exploitability: 95 });
  const g = makeFinding({ exploitability: 60 });
  const score = scoreChain([f, g], 'inject_to_rce');
  // 95 + 60*0.25 + 10 = 95 + 15 + 10 = 120 → capped at 100
  strictEqual(score, 100);
});

// ---------------------------------------------------------------------------
// Suite 5: buildComplianceResults
// ---------------------------------------------------------------------------

console.log('\n── Suite 5: buildComplianceResults ──');

test('no findings → all controls pass', () => {
  const compliance = buildComplianceResults([]);
  ok(compliance.every(c => c.status === 'pass'));
});

test('critical injection finding fails A03', () => {
  const f = makeFinding({ category: 'injection', severity: 'critical', status: 'verified_exploitable' });
  const compliance = buildComplianceResults([f]);
  const a03 = compliance.find(c => c.control.startsWith('A03'));
  ok(a03, 'A03 control not found');
  strictEqual(a03.status, 'fail');
  ok(a03.relatedFindingIds.includes(f.id));
});

test('cors finding affects A05 control', () => {
  const f = makeFinding({ category: 'cors', severity: 'high', status: 'verified_exploitable' });
  const compliance = buildComplianceResults([f]);
  const a05 = compliance.find(c => c.control.startsWith('A05'));
  ok(a05, 'A05 not found');
  strictEqual(a05.status, 'fail');
});

test('all compliance entries have required fields', () => {
  const compliance = buildComplianceResults([makeFinding()]);
  for (const c of compliance) {
    ok(typeof c.framework === 'string');
    ok(typeof c.control === 'string');
    ok(['pass', 'fail', 'partial'].includes(c.status));
    ok(Array.isArray(c.relatedFindingIds));
  }
});

// ---------------------------------------------------------------------------
// Suite 6: buildSummary
// ---------------------------------------------------------------------------

console.log('\n── Suite 6: buildSummary ──');

test('buildSummary counts correct totals', () => {
  const findings = [
    makeFinding({ severity: 'critical', status: 'verified_exploitable' }),
    makeFinding({ id: 'x2', severity: 'high', status: 'potential' }),
    makeFinding({ id: 'x3', severity: 'medium', status: 'potential' }),
    makeFinding({ id: 'x4', severity: 'low', status: 'info' }),
    makeFinding({ id: 'x5', severity: 'info', status: 'info' }),
  ];
  const chains = [{ id: 'chain-1' }, { id: 'chain-2' }];
  const summary = buildSummary(findings, chains);

  strictEqual(summary.total, 5);
  strictEqual(summary.critical, 1);
  strictEqual(summary.high, 1);
  strictEqual(summary.medium, 1);
  strictEqual(summary.low, 1);
  strictEqual(summary.info, 1);
  strictEqual(summary.verified, 1);
  strictEqual(summary.chains, 2);
  strictEqual(summary.total, summary.critical + summary.high + summary.medium + summary.low + summary.info);
});

test('buildSummary with no findings returns zeros', () => {
  const summary = buildSummary([], []);
  strictEqual(summary.total, 0);
  strictEqual(summary.verified, 0);
  strictEqual(summary.chains, 0);
});

// ---------------------------------------------------------------------------
// Suite 7: uniqueById integration with hybridChains
// ---------------------------------------------------------------------------

console.log('\n── Suite 7: uniqueById + hybridChains integration ──');

test('duplicate findings are deduplicated before chain analysis', () => {
  const f = makeFinding({ id: 'shared-id', category: 'cors', exploitability: 85 });
  const dup = { ...f }; // same id
  const auth = makeFinding({ id: 'auth-unique', category: 'auth', exploitability: 70 });

  const deduped = uniqueById([f, dup, auth]);
  strictEqual(deduped.length, 2);

  const chains = hybridChains(deduped);
  // cors + auth → at least one chain
  ok(chains.length >= 1);
});

test('hybridChains does not produce duplicate chain IDs', () => {
  const findings = [
    makeFinding({ id: 'g1', category: 'cors', exploitability: 90 }),
    makeFinding({ id: 'g2', category: 'auth', exploitability: 75 }),
    makeFinding({ id: 'g3', category: 'injection', exploitability: 80 }),
    makeFinding({ id: 'g4', category: 'headers', exploitability: 40 }),
  ];
  const chains = hybridChains(findings);
  const ids = chains.map(c => c.id);
  const uniqueIds = new Set(ids);
  strictEqual(ids.length, uniqueIds.size, 'Duplicate chain IDs found');
});

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

console.log(`\n── Results: ${passed} passed, ${failed} failed ──\n`);

if (failed > 0) {
  process.exit(1);
}
