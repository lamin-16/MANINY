import assert from "node:assert/strict";
import { correlateHybridChains } from "../dist/core/hybrid-chain-correlator.js";

const makeFinding = (id, ruleId, status = "needs_review", stage = "verify") => ({
  id,
  ruleId,
  status,
  evidence: [{ stage }],
});

const findings = [
  makeFinding("F-1", "MANINY-SRF-001", "needs_review", "detect"),
  makeFinding("F-2", "MANINY-HDR-001", "needs_review", "review"),
  makeFinding("F-2", "MANINY-HDR-001", "needs_review", "review"),
  makeFinding("F-3", "MANINY-CODE-001", "needs_review", "verify"),
  makeFinding("F-4", "MANINY-TMP-001", "needs_review", "review"),
  makeFinding("F-5", "MANINY-AUTH-002", "verified_exploitable", "verify"),
  makeFinding("F-6", "MANINY-SQL-001", "needs_review", "detect"),
];

const chains = correlateHybridChains(findings);
assert.equal(chains.length, 3);

const exposureChain = chains.find((c) => c.chainId === "CHAIN-HYBRID-EXPOSURE-AUTH-03");
assert.ok(exposureChain);
assert.equal(exposureChain.severityScore, 9.4);
assert.deepEqual(exposureChain.findingIds, ["F-5", "F-6"]);

const execChain = chains.find((c) => c.chainId === "CHAIN-HYBRID-EXEC-STATE-02");
assert.ok(execChain);
assert.ok(execChain.findingIds.includes("F-4"));

const boundaryChain = chains.find((c) => c.chainId === "CHAIN-HYBRID-BOUNDARY-01");
assert.ok(boundaryChain);
assert.equal(boundaryChain.findingIds.filter((id) => id === "F-2").length, 1);

console.log("ALL HYBRID CHAIN TESTS PASSED:", chains.map((c) => c.chainId));
