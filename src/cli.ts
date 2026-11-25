import fs from "node:fs/promises";
import path from "node:path";
import { Finding, ManinyPolicy, PipelineReport, ReportFormat, RunMode, Severity } from "./core/types.js";
import { listRules } from "./core/registry.js";
import { AgentProviderId, discoverConfiguredAgents, runMultiAgentAdvisory } from "./core/agents.js";
import { buildExecutionAudit } from "./core/audit-trail.js";
import { executeManiny } from "./runner.js";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const CODE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json"]);

async function collectWorkspaceStats(rootDir: string): Promise<{
  workspaceRoot: string;
  filesCount: number;
  totalLines: number;
  rulesRegistered: number;
}> {
  let filesCount = 0;
  let totalLines = 0;

  async function walk(dir: string): Promise<void> {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          await walk(path.join(dir, entry.name));
        }
      } else if (entry.isFile() && CODE_EXTS.has(path.extname(entry.name).toLowerCase())) {
        const full = path.join(dir, entry.name);
        const content = await fs.readFile(full, "utf8");
        filesCount++;
        totalLines += content.split(/\r?\n/).length;
      }
    }
  }

  await walk(rootDir);
  return {
    workspaceRoot: rootDir,
    filesCount,
    totalLines,
    rulesRegistered: listRules().length,
  };
}

function recomputeSummary(report: PipelineReport): void {
  const f = report.findings;
  report.summary = {
    total: f.length,
    detected: f.filter((x) => x.status === "detected").length,
    verifiedExploitable: f.filter((x) => x.status === "verified_exploitable").length,
    needsReview: f.filter((x) => x.status === "needs_review").length,
    patched: f.filter((x) => x.status === "patched").length,
    verifiedFixed: f.filter((x) => x.status === "verified_fixed").length,
    rolledBack: f.filter((x) => x.status === "rolled_back").length,
  };
}

function buildComplianceSummary(report: PipelineReport, hasIntegrity: boolean) {
  const s = report.summary;
  const unresolvedActive = s.verifiedExploitable + s.needsReview + s.rolledBack;
  const posture =
    s.total === 0
      ? "CLEAN"
      : unresolvedActive === 0 && s.verifiedFixed > 0
        ? "REMEDIATED"
        : s.needsReview > 0 || s.verifiedExploitable > 0
          ? "ACTION_REQUIRED"
          : "OBSERVED";

  return {
    posture,
    integrityVerified: hasIntegrity,
    totalFindings: s.total,
    verifiedFixed: s.verifiedFixed,
    needsManualReview: s.needsReview,
    rolledBack: s.rolledBack,
    remainingUnresolved: unresolvedActive,
  };
}

function shouldFailGate(report: PipelineReport, failOn?: Severity): boolean {
  if (!failOn) return false;
  const threshold = SEVERITY_RANK[failOn];
  return report.findings.some(
    (f: Finding) =>
      f.status !== "verified_fixed" && SEVERITY_RANK[f.severity] >= threshold
  );
}

function parseArgs(argv: string[]): {
  mode: RunMode;
  workspace: string;
  allowHosts: string[];
  targetUrls: string[];
  allowProbes: boolean;
  allowFix: boolean;
  urlOnly: boolean;
  jsonCompact: boolean;
  compliance: boolean;
  stats: boolean;
  showVersion: boolean;
  showHelp: boolean;
  quiet: boolean;
  listRules: boolean;
  agentsRequested: boolean;
  agentsStatusOnly: boolean;
  includeIntegrity: boolean;
  agentProviders: AgentProviderId[];
  minSeverity?: Severity;
  failOn?: Severity;
  reportBase?: string;
  reportFormat: ReportFormat;
} {
  let mode: RunMode = "pipeline";
  let workspace = process.cwd();
  const allowHosts: string[] = [];
  const targetUrls: string[] = [];
  let allowProbes = false;
  let allowFix = false;
  let urlOnly = false;
  let jsonCompact = false;
  let compliance = false;
  let stats = false;
  let showVersion = false;
  let showHelp = false;
  let quiet = false;
  let shouldListRules = false;
  let agentsRequested = false;
  let agentsStatusOnly = false;
  let includeIntegrity = false;
  const agentProviders: AgentProviderId[] = [];
  let minSeverity: Severity | undefined;
  let failOn: Severity | undefined;
  let reportBase: string | undefined;
  let reportFormat: ReportFormat = "json";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    const next = argv[i + 1];

    if (arg === "--quiet" || arg === "-q") {
      quiet = true;
    } else if (arg === "--help" || arg === "-h") {
      showHelp = true;
    } else if (arg === "--version" || arg === "-v") {
      showVersion = true;
    } else if (arg === "--list-rules") {
      shouldListRules = true;
    } else if (arg === "--stats") {
      stats = true;
    } else if (arg === "--url-only") {
      urlOnly = true;
    } else if (arg === "--json-compact") {
      jsonCompact = true;
    } else if (arg === "--compliance") {
      compliance = true;
    } else if (arg === "--agents-status") {
      agentsStatusOnly = true;
    } else if (arg === "--integrity") {
      includeIntegrity = true;
    } else if (arg === "--agents") {
      agentsRequested = true;
      if (next && !next.startsWith("--")) {
        for (const raw of next.split(",")) {
          const p = raw.trim().toLowerCase();
          if (
            p === "openai" ||
            p === "claude" ||
            p === "deepseek" ||
            p === "gemini" ||
            p === "custom"
          ) {
            agentProviders.push(p);
          }
        }
        i++;
      }
    } else if (arg === "--severity" && next) {
      if (
        next === "info" ||
        next === "low" ||
        next === "medium" ||
        next === "high" ||
        next === "critical"
      ) {
        minSeverity = next;
      }
      i++;
    } else if (arg === "--fail-on" && next) {
      if (
        next === "info" ||
        next === "low" ||
        next === "medium" ||
        next === "high" ||
        next === "critical"
      ) {
        failOn = next;
      }
      i++;
    } else if (arg === "--mode" && next) {
      if (
        next === "detect" ||
        next === "verify" ||
        next === "fix" ||
        next === "review" ||
        next === "pipeline"
      ) {
        mode = next;
      }
      i++;
    } else if ((arg === "--workspace" || arg === "-w") && next) {
      workspace = next;
      i++;
    } else if (arg === "--allow-host" && next) {
      allowHosts.push(next);
      i++;
    } else if (arg === "--url" && next) {
      targetUrls.push(next);
      i++;
    } else if (arg === "--allow-probes") {
      allowProbes = true;
    } else if (arg === "--allow-fix") {
      allowFix = true;
    } else if ((arg === "--report" || arg === "-o") && next) {
      reportBase = next.replace(/\.(json|sarif)$/i, "");
      i++;
    } else if ((arg === "--format" || arg === "-f") && next) {
      if (next === "json" || next === "sarif" || next === "both") {
        reportFormat = next;
      }
      i++;
    }
  }

  return {
    mode,
    workspace: path.resolve(workspace),
    allowHosts,
    targetUrls,
    allowProbes,
    allowFix,
    urlOnly,
    jsonCompact,
    compliance,
    stats,
    showVersion,
    showHelp,
    quiet,
    listRules: shouldListRules,
    agentsRequested,
    agentsStatusOnly,
    includeIntegrity,
    agentProviders,
    reportFormat,
    ...(minSeverity ? { minSeverity } : {}),
    ...(failOn ? { failOn } : {}),
    ...(reportBase ? { reportBase } : {}),
  };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.showHelp) {
    console.log("MANINY CLI flags: --mode <detect|verify|fix|review|pipeline> --workspace|-w <dir> --url <url> --allow-host <host> --allow-probes --allow-fix --url-only --json-compact --compliance --fail-on <sev> --severity <sev> --integrity --stats --list-rules --agents [list] --agents-status --report|-o <path> --format|-f <json|sarif|both> --version|-v --quiet|-q --help|-h");
    return;
  }

  if (args.showVersion) {
    console.log("MANINY v0.2.0");
    return;
  }

  if (args.stats) {
    const s = await collectWorkspaceStats(args.workspace);
    console.log(JSON.stringify(s, null, 2));
    return;
  }

  if (args.listRules) {
    const rules = listRules().map((r) => ({
      ruleId: r.ruleId,
      severity: r.severity,
      category: r.category,
      autoFix: Boolean(r.fixLine),
      title: r.title,
    }));
    console.log(JSON.stringify({ total: rules.length, rules }, null, 2));
    return;
  }

  if (args.agentsStatusOnly) {
    const active = discoverConfiguredAgents(args.agentProviders);
    console.log(
      JSON.stringify(
        {
          configuredCount: active.length,
          agents: active.map((a) => ({
            provider: a.provider,
            model: a.model,
            baseUrl: a.baseUrl ?? "default",
            ready: true,
          })),
        },
        null,
        2
      )
    );
    return;
  }

  const policy: ManinyPolicy = {
    workspaceRoot: args.workspace,
    allowedTargetHosts: args.allowHosts,
    allowSafeOffensiveProbes: args.allowProbes,
    allowAutoFix: args.allowFix,
    maxAutoFixSeverity: "high",
    blockedPathSubstrings: [".env", ".git", "node_modules", "id_rsa", "credentials"],
  };

  const report = await executeManiny({
    mode: args.mode,
    policy,
    targetUrls: args.targetUrls,
    reportFormat: args.reportFormat,
    skipWorkspaceScan: args.urlOnly,
    ...(args.reportBase ? { reportBasePath: args.reportBase } : {}),
  });

  if (args.minSeverity) {
    const threshold = SEVERITY_RANK[args.minSeverity];
    report.findings = report.findings.filter((f: Finding) => SEVERITY_RANK[f.severity] >= threshold);
    recomputeSummary(report);
  }

  const audit = args.includeIntegrity ? buildExecutionAudit(report.findings) : undefined;
  const complianceSummary = args.compliance
    ? buildComplianceSummary(report, Boolean(audit))
    : undefined;
  const gateFailed = shouldFailGate(report, args.failOn);

  if (args.jsonCompact) {
    console.log(
      JSON.stringify(
        {
          tool: report.tool,
          mode: report.mode,
          summary: report.summary,
          ...(complianceSummary ? { compliance: complianceSummary } : {}),
          ...(audit ? { auditId: audit.auditId, integritySha256: audit.integritySha256 } : {}),
          ...(args.failOn ? { gate: { failOn: args.failOn, breached: gateFailed } } : {}),
          items: report.findings.map((f) => ({
            id: f.id,
            ruleId: f.ruleId,
            severity: f.severity,
            status: f.status,
            target: f.filePath ? `${f.filePath}:${f.line ?? 1}` : f.targetUrl ?? "",
          })),
        },
        null,
        2
      )
    );
  } else if (args.agentsRequested) {
    const configured = discoverConfiguredAgents(args.agentProviders);
    const insights = await runMultiAgentAdvisory(configured, report.findings);
    console.log(
      JSON.stringify(
        {
          ...report,
          ...(complianceSummary ? { compliance: complianceSummary } : {}),
          ...(audit ? { audit } : {}),
          ...(args.failOn ? { gate: { failOn: args.failOn, breached: gateFailed } } : {}),
          agents: {
            configuredCount: configured.length,
            providers: configured.map((c) => ({ provider: c.provider, model: c.model })),
            insights,
          },
        },
        null,
        2
      )
    );
  } else {
    console.log(
      JSON.stringify(
        {
          ...report,
          ...(complianceSummary ? { compliance: complianceSummary } : {}),
          ...(audit ? { audit } : {}),
          ...(args.failOn ? { gate: { failOn: args.failOn, breached: gateFailed } } : {}),
        },
        null,
        2
      )
    );
  }

  if (gateFailed) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("MANINY fatal error:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
