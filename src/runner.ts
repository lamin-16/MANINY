import fs from "node:fs/promises";
import { Finding, ManinyPolicy, PipelineReport, ReportFormat, RunMode } from "./core/types.js";
import { formatSarifReport } from "./core/reporter.js";
import { runDetector } from "./stages/detector.js";
import { runDependencyAuditor } from "./stages/dependency-auditor.js";
import { runEnvAuditor } from "./stages/env-auditor.js";
import { runBehavioralAuditor } from "./stages/behavioral-auditor.js";
import { runSafeVerifier } from "./stages/verifier.js";
import { runAdversarialSimulation } from "./stages/adversarial-sim.js";
import { runFixer } from "./stages/fixer.js";
import { runDefenderReviewer } from "./stages/reviewer.js";

export interface ExecuteManinyOptions {
  mode: RunMode;
  policy: ManinyPolicy;
  targetUrls?: string[];
  reportFormat?: ReportFormat;
  reportBasePath?: string;
  skipWorkspaceScan?: boolean;
}

function summarizeFindings(findings: Finding[]): PipelineReport["summary"] {
  return {
    total: findings.length,
    detected: findings.filter((x) => x.status === "detected").length,
    verifiedExploitable: findings.filter((x) => x.status === "verified_exploitable").length,
    needsReview: findings.filter((x) => x.status === "needs_review").length,
    patched: findings.filter((x) => x.status === "patched").length,
    verifiedFixed: findings.filter((x) => x.status === "verified_fixed").length,
    rolledBack: findings.filter((x) => x.status === "rolled_back").length,
  };
}

export async function executeManiny(options: ExecuteManinyOptions): Promise<PipelineReport> {
  const {
    mode,
    policy,
    targetUrls = [],
    reportFormat = "json",
    reportBasePath,
    skipWorkspaceScan = false,
  } = options;

  let findings = await runDetector(policy, targetUrls, { skipWorkspaceScan });

  if (!skipWorkspaceScan) {
    const [depFindings, envFindings, behFindings] = await Promise.all([
      runDependencyAuditor(policy),
      runEnvAuditor(policy),
      runBehavioralAuditor(policy),
    ]);
    findings = [...findings, ...depFindings, ...envFindings, ...behFindings];
  }

  if (mode === "verify" || mode === "pipeline") {
    findings = await runSafeVerifier(findings, policy);
    const simFindings = await runAdversarialSimulation(targetUrls, policy);
    findings = [...findings, ...simFindings];
  }

  if (mode === "fix" || mode === "pipeline") {
    findings = await runFixer(findings, policy);
  }

  if (mode === "review" || mode === "pipeline") {
    findings = await runDefenderReviewer(findings, policy);
  }

  const report: PipelineReport = {
    tool: "MANINY",
    version: "0.2.0",
    mode,
    workspaceRoot: policy.workspaceRoot,
    generatedAt: new Date().toISOString(),
    summary: summarizeFindings(findings),
    findings,
  };

  if (reportBasePath) {
    if (reportFormat === "json" || reportFormat === "both") {
      await fs.writeFile(`${reportBasePath}.json`, JSON.stringify(report, null, 2), "utf8");
    }
    if (reportFormat === "sarif" || reportFormat === "both") {
      await fs.writeFile(`${reportBasePath}.sarif`, formatSarifReport(report), "utf8");
    }
  }

  return report;
}
