import { ManinyPolicy, PipelineReport, ReportFormat, RunMode } from "./core/types.js";
import { buildReport, writeReportArtifacts } from "./core/report.js";
import { runDetector } from "./stages/detector.js";
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

  const report = buildReport(mode, policy, findings);

  if (reportBasePath) {
    await writeReportArtifacts(report, reportBasePath, reportFormat);
  }

  return report;
}
