import fs from "node:fs/promises";
import path from "node:path";
import {
  Finding,
  ManinyPolicy,
  PipelineReport,
  ReportFormat,
  RunMode,
} from "./core/types.js";
import { formatSarifReport } from "./core/reporter.js";
import { runDetector } from "./stages/detector.js";
import { runSafeVerifier } from "./stages/verifier.js";
import { runExposureChecks } from "./stages/exposure-checker.js";
import { runAdversarialSimulation } from "./stages/adversarial-sim.js";
import { runFixer } from "./stages/fixer.js";
import { runDefenderReviewer } from "./stages/reviewer.js";

function buildReport(
  mode: RunMode,
  policy: ManinyPolicy,
  findings: Finding[]
): PipelineReport {
  return {
    tool: "MANINY",
    version: "0.2.0",
    mode,
    workspaceRoot: policy.workspaceRoot,
    generatedAt: new Date().toISOString(),
    summary: {
      total: findings.length,
      detected: findings.filter((f) => f.status === "detected").length,
      verifiedExploitable: findings.filter((f) => f.status === "verified_exploitable")
        .length,
      needsReview: findings.filter((f) => f.status === "needs_review").length,
      patched: findings.filter((f) => f.status === "patched").length,
      verifiedFixed: findings.filter((f) => f.status === "verified_fixed").length,
      rolledBack: findings.filter((f) => f.status === "rolled_back").length,
    },
    findings,
  };
}

export async function executeManiny(options: {
  mode: RunMode;
  policy: ManinyPolicy;
  targetUrls?: string[];
  reportBasePath?: string;
  reportFormat?: ReportFormat;
}): Promise<PipelineReport> {
  const {
    mode,
    policy,
    targetUrls = [],
    reportBasePath,
    reportFormat = "json",
  } = options;

  let findings: Finding[] = await runDetector(policy, targetUrls);

  if (mode === "verify" || mode === "pipeline") {
    findings = await runSafeVerifier(findings, policy);

    const exposureBatches = await runExposureChecks(targetUrls, policy);
    for (const batch of exposureBatches) {
      findings.push(...batch.findings);
    }

    const simFindings = await runAdversarialSimulation(targetUrls, policy);
    findings.push(...simFindings);
  }

  if (mode === "fix" || mode === "pipeline") {
    findings = await runFixer(findings, policy);
  }

  if (mode === "review" || mode === "pipeline") {
    findings = await runDefenderReviewer(findings, policy);
  }

  const report = buildReport(mode, policy, findings);

  if (reportBasePath) {
    const absBase = path.resolve(policy.workspaceRoot, reportBasePath);
    await fs.mkdir(path.dirname(absBase), { recursive: true });

    if (reportFormat === "json" || reportFormat === "both") {
      await fs.writeFile(`${absBase}.json`, JSON.stringify(report, null, 2), "utf8");
    }
    if (reportFormat === "sarif" || reportFormat === "both") {
      await fs.writeFile(`${absBase}.sarif`, formatSarifReport(report), "utf8");
    }
  }

  return report;
}
