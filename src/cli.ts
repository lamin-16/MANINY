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
  top?: number;
  ruleFilter?: string;
  excludeRule?: string;
  excludeRulePrefix?: string;
  excludeSeverity?: string;
  excludeCategory?: string;
  excludeStatus?: string;
  fileFilter?: string;
  lineFilter?: number;
  hasEvidence: boolean;
  noEvidence: boolean;
  hasTargetUrl: boolean;
  noTargetUrl: boolean;
  excludeFile?: string;
  excludeFilePrefix?: string;
  excludeFileSuffix?: string;
  excludeLine?: number;
  categoryFilter?: string;
  summaryOnly: boolean;
  countBySeverity: boolean;
  countByStatus: boolean;
  countByFile: boolean;
  countByRuleFile: boolean;
  countBySeverityFile: boolean;
  countByCategorySeverity: boolean;
  countByStatusSeverity: boolean;
  countByCategoryFile: boolean;
  countByStatusFile: boolean;
  countByRuleSeverity: boolean;
  countByRuleStatus: boolean;
  countByCategoryStatus: boolean;
  summaryStats: boolean;
  topRules: boolean;
  topFiles: boolean;
  topSeverities: boolean;
  topCategories: boolean;
  topStatuses: boolean;
  topRuleFiles: boolean;
  topSeverityFiles: boolean;
  topCategoryFiles: boolean;
  topStatusFiles: boolean;
  topRuleSeverities: boolean;
  topRuleStatuses: boolean;
  topCategoryStatuses: boolean;
  topSeverityStatuses: boolean;
  topSeverityCategories: boolean;
  topRuleCategories: boolean;
  topRuleFileSeverities: boolean;
  topRuleFileStatuses: boolean;
  topRuleFileCategories: boolean;
  topRuleSeverityStatuses: boolean;
  topRuleSeverityCategories: boolean;
  topCategorySeverityStatuses: boolean;
  topRuleFileSeverityStatuses: boolean;
  topRuleFileSeverityCategories: boolean;
  topRuleFileCategoryStatuses: boolean;
  topRuleSeverityCategoryStatuses: boolean;
  topRuleFileSeverityCategoryStatuses: boolean;
  topDistinctRules: boolean;
  topDistinctFiles: boolean;
  topDistinctSeverities: boolean;
  topDistinctCategories: boolean;
  topDistinctStatuses: boolean;
  statusFilter?: string;
  groupByRule: boolean;
  groupByFile: boolean;
  groupByCategory: boolean;
  groupByStatus: boolean;
  groupBySeverity: boolean;
  sortBy?: "severity" | "line" | "file";
  listRules: boolean;
  agentsRequested: boolean;
  agentsStatusOnly: boolean;
  includeIntegrity: boolean;
  agentProviders: AgentProviderId[];
  minSeverity?: Severity;
  maxSeverity?: Severity;
  onlyRule?: string;
  onlyCategory?: string;
  onlyFile?: string;
  onlyStatus?: string;
  sortByLine: boolean;
  sortByFile: boolean;
  sortBySeverity: boolean;
  countByCategory: boolean;
  countByRule: boolean;
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
  let top: number | undefined;
  let ruleFilter: string | undefined;
  let excludeRule: string | undefined;
  let excludeRulePrefix: string | undefined;
  let excludeSeverity: string | undefined;
  let excludeCategory: string | undefined;
  let excludeStatus: string | undefined;
  let fileFilter: string | undefined;
  let lineFilter: number | undefined;
  let hasEvidence = false;
  let noEvidence = false;
  let hasTargetUrl = false;
  let noTargetUrl = false;
  let excludeFile: string | undefined;
  let excludeFilePrefix: string | undefined;
  let excludeFileSuffix: string | undefined;
  let excludeLine: number | undefined;
  let categoryFilter: string | undefined;
  let summaryOnly = false;
  let countBySeverity = false;
  let countByStatus = false;
  let countByFile = false;
  let countByRuleFile = false;
  let countBySeverityFile = false;
  let countByCategorySeverity = false;
  let countByStatusSeverity = false;
  let countByCategoryFile = false;
  let countByStatusFile = false;
  let countByRuleSeverity = false;
  let countByRuleStatus = false;
  let countByCategoryStatus = false;
  let summaryStats = false;
  let topRules = false;
  let topFiles = false;
  let topSeverities = false;
  let topCategories = false;
  let topStatuses = false;
  let topRuleFiles = false;
  let topSeverityFiles = false;
  let topCategoryFiles = false;
  let topStatusFiles = false;
  let topRuleSeverities = false;
  let topRuleStatuses = false;
  let topCategoryStatuses = false;
  let topSeverityStatuses = false;
  let topSeverityCategories = false;
  let topRuleCategories = false;
  let topRuleFileSeverities = false;
  let topRuleFileStatuses = false;
  let topRuleFileCategories = false;
  let topRuleSeverityStatuses = false;
  let topRuleSeverityCategories = false;
  let topCategorySeverityStatuses = false;
  let topRuleFileSeverityStatuses = false;
  let topRuleFileSeverityCategories = false;
  let topRuleFileCategoryStatuses = false;
  let topRuleSeverityCategoryStatuses = false;
  let topRuleFileSeverityCategoryStatuses = false;
  let topDistinctRules = false;
  let topDistinctFiles = false;
  let topDistinctSeverities = false;
  let topDistinctCategories = false;
  let topDistinctStatuses = false;
  let statusFilter: string | undefined;
  let groupByRule = false;
  let groupByFile = false;
  let groupByCategory = false;
  let groupByStatus = false;
  let groupBySeverity = false;
  let sortBy: "severity" | "line" | "file" | undefined;
  let shouldListRules = false;
  let agentsRequested = false;
  let agentsStatusOnly = false;
  let includeIntegrity = false;
  const agentProviders: AgentProviderId[] = [];
  let minSeverity: Severity | undefined;
  let maxSeverity: Severity | undefined;
  let onlyRule: string | undefined;
  let onlyCategory: string | undefined;
  let onlyFile: string | undefined;
  let onlyStatus: string | undefined;
  let sortByLine = false;
  let sortByFile = false;
  let sortBySeverity = false;
  let countByCategory = false;
  let countByRule = false;
  let failOn: Severity | undefined;
  let reportBase: string | undefined;
  let reportFormat: ReportFormat = "json";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    const next = argv[i + 1];

    if (arg === "--sort-by" && next && (next === "severity" || next === "line" || next === "file")) {
      sortBy = next;
      i++;
    } else if (arg === "--sort-by <severity|line|file> --group-by-severity") {
      groupBySeverity = true;
    } else if (arg === "--group-by-severity --group-by-status") {
      groupByStatus = true;
    } else if (arg === "--group-by-status --group-by-category") {
      groupByCategory = true;
    } else if (arg === "--group-by-category --group-by-file") {
      groupByFile = true;
    } else if (arg === "--group-by-file --group-by-rule") {
      groupByRule = true;
    } else if (arg === "--status" && next) {
      statusFilter = next.trim();
      i++;
    } else if (arg === "--group-by-rule --status <st> --top-distinct-statuses --top-distinct-categories --top-distinct-severities --top-distinct-files --top-distinct-rules --top-rule-file-severity-category-statuses --top-rule-severity-category-statuses --top-rule-file-category-statuses --top-rule-file-severity-categories --top-rule-file-severity-statuses --top-category-severity-statuses --top-rule-severity-categories --top-rule-severity-statuses --top-rule-file-categories --top-rule-file-statuses --top-rule-file-severities --top-rule-categories --top-severity-categories --top-severity-statuses --top-category-statuses --top-rule-statuses --top-rule-severities --top-status-files --top-category-files --top-severity-files --top-rule-files --top-statuses --top-categories --top-severities --top-files --top-rules --summary-stats --count-by-category-status --count-by-rule-status --count-by-rule-severity --count-by-status-file --count-by-category-file --count-by-status-severity --count-by-category-severity --count-by-severity-file --count-by-rule-file --count-by-file --count-by-status --count-by-severity") {
      countBySeverity = true;
    } else if (arg === "--count-by-severity --summary-only") {
      summaryOnly = true;
    } else if (arg === "--category" && next) {
      categoryFilter = next.trim();
      i++;
    } else if (arg === "--rule" && next) {
      ruleFilter = next.trim();
      i++;
    } else if (arg === "--top" && next) {
      const n = Number(next);
      if (Number.isInteger(n) && n > 0) top = n;
      i++;
    } else if (arg === "--quiet" || arg === "-q") {
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
    ...(top ? { top } : {}),
    ...(ruleFilter ? { ruleFilter } : {}),
    ...(excludeRule ? { excludeRule } : {}),
    ...(excludeRulePrefix ? { excludeRulePrefix } : {}),
    ...(excludeSeverity ? { excludeSeverity } : {}),
    ...(excludeCategory ? { excludeCategory } : {}),
    ...(excludeStatus ? { excludeStatus } : {}),
    ...(fileFilter ? { fileFilter } : {}),
    ...(lineFilter !== undefined ? { lineFilter } : {}),
    hasEvidence,
    noEvidence,
    hasTargetUrl,
    noTargetUrl,
    ...(minSeverity ? { minSeverity } : {}),
    ...(maxSeverity ? { maxSeverity } : {}),
    ...(onlyRule ? { onlyRule } : {}),
    ...(onlyCategory ? { onlyCategory } : {}),
    ...(onlyFile ? { onlyFile } : {}),
    ...(onlyStatus ? { onlyStatus } : {}),
    sortByLine,
    sortByFile,
    sortBySeverity,
    countByCategory,
    countByRule,
    ...(excludeFile ? { excludeFile } : {}),
    ...(excludeFilePrefix ? { excludeFilePrefix } : {}),
    ...(excludeFileSuffix ? { excludeFileSuffix } : {}),
    ...(excludeLine !== undefined ? { excludeLine } : {}),
    ...(categoryFilter ? { categoryFilter } : {}),
    summaryOnly,
    countBySeverity,
    countByStatus,
    countByFile,
    countByRuleFile,
    countBySeverityFile,
    countByCategorySeverity,
    countByStatusSeverity,
    countByCategoryFile,
    countByStatusFile,
    countByRuleSeverity,
    countByRuleStatus,
    countByCategoryStatus,
    summaryStats,
    topRules,
    topFiles,
    topSeverities,
    topCategories,
    topStatuses,
    topRuleFiles,
    topSeverityFiles,
    topCategoryFiles,
    topStatusFiles,
    topRuleSeverities,
    topRuleStatuses,
    topCategoryStatuses,
    topSeverityStatuses,
    topSeverityCategories,
    topRuleCategories,
    topRuleFileSeverities,
    topRuleFileStatuses,
    topRuleFileCategories,
    topRuleSeverityStatuses,
    topRuleSeverityCategories,
    topCategorySeverityStatuses,
    topRuleFileSeverityStatuses,
    topRuleFileSeverityCategories,
    topRuleFileCategoryStatuses,
    topRuleSeverityCategoryStatuses,
    topRuleFileSeverityCategoryStatuses,
    topDistinctRules,
    topDistinctFiles,
    topDistinctSeverities,
    topDistinctCategories,
    topDistinctStatuses,
    ...(statusFilter ? { statusFilter } : {}),
    groupByRule,
    groupByFile,
    groupByCategory,
    groupByStatus,
    groupBySeverity,
    ...(sortBy ? { sortBy } : {}),
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
    console.log("MANINY CLI flags: --mode <detect|verify|fix|review|pipeline> --workspace|-w <dir> --url <url> --allow-host <host> --allow-probes --allow-fix --url-only --json-compact --compliance --fail-on <sev> --severity <sev> --integrity --stats --list-rules --agents [list] --agents-status --report|-o <path> --format|-f <json|sarif|both> --version|-v --summary-only --category <cat> --exclude-line <num> --exclude-file-suffix <sfx> --exclude-file-prefix <pfx> --exclude-file <substr> --count-by-rule --count-by-category --sort-by-severity --sort-by-file --sort-by-line --only-status <status> --only-file <path> --only-category <cat> --only-rule <id> --max-severity <sev> --min-severity <sev> --no-target-url --has-target-url --no-evidence --has-evidence --line <num> --file <substr> --exclude-status <st> --exclude-category <cat> --exclude-severity <sev> --exclude-rule-prefix <pfx> --exclude-rule <id> --rule <id> --top <n> --quiet|-q --help|-h");
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

  if (args.statusFilter) {
    const sf = args.statusFilter.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => f.status.toLowerCase() === sf);
    recomputeSummary(report);
  }

  if (args.categoryFilter) {
    const cf = args.categoryFilter.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => f.category.toLowerCase() === cf);
    recomputeSummary(report);
  }

  if (args.excludeLine !== undefined) {
    report.findings = report.findings.filter((f: Finding) => f.line !== args.excludeLine);
    recomputeSummary(report);
  }

  if (args.excludeFileSuffix) {
    const sfx = args.excludeFileSuffix.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => !String(f.filePath ?? f.targetUrl ?? "").toLowerCase().endsWith(sfx));
    recomputeSummary(report);
  }

  if (args.excludeFilePrefix) {
    const pfx = args.excludeFilePrefix.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => !String(f.filePath ?? f.targetUrl ?? "").toLowerCase().startsWith(pfx));
    recomputeSummary(report);
  }

  if (args.excludeFile) {
    const ef = args.excludeFile.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => !String(f.filePath ?? f.targetUrl ?? "").toLowerCase().includes(ef));
    recomputeSummary(report);
  }

  if (args.countByRule) {
    const counts: Record<string, number> = {};
    for (const f of report.findings) {
      counts[f.ruleId] = (counts[f.ruleId] ?? 0) + 1;
    }
    console.log(JSON.stringify({ countByRule: counts }, null, 2));
    return;
  }

  if (args.countByCategory) {
    const counts: Record<string, number> = {};
    for (const f of report.findings) {
      counts[f.category] = (counts[f.category] ?? 0) + 1;
    }
    console.log(JSON.stringify({ countByCategory: counts }, null, 2));
    return;
  }

  if (args.sortBySeverity) {
    const rankMap = SEVERITY_RANK as Record<string, number>;
    report.findings = [...report.findings].sort((a: Finding, b: Finding) => (rankMap[b.severity.toLowerCase()] ?? 0) - (rankMap[a.severity.toLowerCase()] ?? 0));
  }

  if (args.sortByFile) {
    report.findings = [...report.findings].sort((a: Finding, b: Finding) => (a.filePath ?? "").localeCompare(b.filePath ?? ""));
  }

  if (args.sortByLine) {
    report.findings = [...report.findings].sort((a: Finding, b: Finding) => (a.line ?? Number.MAX_SAFE_INTEGER) - (b.line ?? Number.MAX_SAFE_INTEGER));
  }

  if (args.onlyStatus) {
    const targetStatus = args.onlyStatus.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => f.status.toLowerCase() === targetStatus);
    recomputeSummary(report);
  }

  if (args.onlyFile) {
    const normTarget = args.onlyFile.replace(/^\.\//, "");
    report.findings = report.findings.filter((f: Finding) => (f.filePath ?? "").replace(/^\.\//, "") === normTarget);
    recomputeSummary(report);
  }

  if (args.onlyCategory) {
    const targetCat = args.onlyCategory.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => f.category.toLowerCase() === targetCat);
    recomputeSummary(report);
  }

  if (args.onlyRule) {
    const targetRule = args.onlyRule.toUpperCase();
    report.findings = report.findings.filter((f: Finding) => f.ruleId.toUpperCase() === targetRule);
    recomputeSummary(report);
  }

  if (args.maxSeverity) {
    const rankMap = SEVERITY_RANK as Record<string, number>;
    const maxRank = rankMap[String(args.maxSeverity).toLowerCase()];
    if (maxRank !== undefined) {
      report.findings = report.findings.filter((f: Finding) => (rankMap[f.severity.toLowerCase()] ?? 0) <= maxRank);
      recomputeSummary(report);
    }
  }

  if (args.minSeverity) {
    const rank: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const minRank = rank[args.minSeverity.toLowerCase()];
    if (minRank !== undefined) {
      report.findings = report.findings.filter((f: Finding) => (rank[f.severity.toLowerCase()] ?? 0) >= minRank);
      recomputeSummary(report);
    }
  }

  if (args.noTargetUrl) {
    report.findings = report.findings.filter((f: Finding) => !Boolean(f.targetUrl && String(f.targetUrl).trim()));
    recomputeSummary(report);
  }

  if (args.hasTargetUrl) {
    report.findings = report.findings.filter((f: Finding) => Boolean(f.targetUrl && String(f.targetUrl).trim()));
    recomputeSummary(report);
  }

  if (args.noEvidence) {
    report.findings = report.findings.filter((f: Finding) => !Array.isArray(f.evidence) || f.evidence.length === 0);
    recomputeSummary(report);
  }

  if (args.hasEvidence) {
    report.findings = report.findings.filter((f: Finding) => Array.isArray(f.evidence) && f.evidence.length > 0);
    recomputeSummary(report);
  }

  if (args.lineFilter !== undefined) {
    report.findings = report.findings.filter((f: Finding) => f.line === args.lineFilter);
    recomputeSummary(report);
  }

  if (args.fileFilter) {
    const ff = args.fileFilter.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => String(f.filePath ?? f.targetUrl ?? "").toLowerCase().includes(ff));
    recomputeSummary(report);
  }

  if (args.excludeStatus) {
    const est = args.excludeStatus.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => f.status.toLowerCase() !== est);
    recomputeSummary(report);
  }

  if (args.excludeCategory) {
    const ec = args.excludeCategory.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => f.category.toLowerCase() !== ec);
    recomputeSummary(report);
  }

  if (args.excludeSeverity) {
    const es = args.excludeSeverity.toLowerCase();
    report.findings = report.findings.filter((f: Finding) => f.severity.toLowerCase() !== es);
    recomputeSummary(report);
  }

  if (args.excludeRulePrefix) {
    const pfx = args.excludeRulePrefix.toUpperCase();
    report.findings = report.findings.filter((f: Finding) => !f.ruleId.toUpperCase().startsWith(pfx));
    recomputeSummary(report);
  }

  if (args.excludeRule) {
    const ef = args.excludeRule.toUpperCase();
    report.findings = report.findings.filter((f: Finding) => f.ruleId.toUpperCase() !== ef);
    recomputeSummary(report);
  }

  if (args.ruleFilter) {
    const rf = args.ruleFilter.toUpperCase();
    report.findings = report.findings.filter((f: Finding) => f.ruleId.toUpperCase() === rf);
    recomputeSummary(report);
  }

  if (args.sortBy) {
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    report.findings.sort((a: Finding, b: Finding) => {
      if (args.sortBy === "severity") return (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
      if (args.sortBy === "line") return (a.line ?? 0) - (b.line ?? 0);
      return String(a.filePath ?? a.targetUrl ?? "").localeCompare(String(b.filePath ?? b.targetUrl ?? ""));
    });
  }

  if (args.minSeverity) {
    const rankMap = SEVERITY_RANK as Record<string, number>;
    const threshold = rankMap[String(args.minSeverity).toLowerCase()];
    if (threshold !== undefined) {
      report.findings = report.findings.filter((f: Finding) => SEVERITY_RANK[f.severity] >= threshold);
    }
    recomputeSummary(report);
  }

  const audit = args.includeIntegrity ? buildExecutionAudit(report.findings) : undefined;
  const bySeverity = (args.countBySeverity || args.groupBySeverity)
    ? {
        critical: report.findings.filter((x: Finding) => x.severity === "critical").length,
        high: report.findings.filter((x: Finding) => x.severity === "high").length,
        medium: report.findings.filter((x: Finding) => x.severity === "medium").length,
        low: report.findings.filter((x: Finding) => x.severity === "low").length,
        info: report.findings.filter((x: Finding) => x.severity === "info").length,
      }
    : undefined;

  const byRule = args.groupByRule
    ? report.findings.reduce<Record<string, number>>((acc, f: Finding) => {
        acc[f.ruleId] = (acc[f.ruleId] ?? 0) + 1;
        return acc;
      }, {})
    : undefined;

  const byFile = args.groupByFile
    ? report.findings.reduce<Record<string, number>>((acc, f: Finding) => {
        const key = f.filePath ?? f.targetUrl ?? "unknown";
        acc[key] = (acc[key] ?? 0) + 1;
        return acc;
      }, {})
    : undefined;

  const byCategory = args.groupByCategory
    ? report.findings.reduce<Record<string, number>>((acc, f: Finding) => {
        acc[f.category] = (acc[f.category] ?? 0) + 1;
        return acc;
      }, {})
    : undefined;

  const byStatus = args.groupByStatus
    ? report.findings.reduce<Record<string, number>>((acc, f: Finding) => {
        acc[f.status] = (acc[f.status] ?? 0) + 1;
        return acc;
      }, {})
    : undefined;

  const complianceSummary = args.compliance
    ? buildComplianceSummary(report, Boolean(audit))
    : undefined;
  const gateFailed = shouldFailGate(report, args.failOn);

  if (args.summaryOnly) {
    console.log(
      JSON.stringify(
        {
          tool: report.tool,
          mode: report.mode,
          summary: report.summary,
          ...(bySeverity ? { bySeverity } : {}),
          ...(byRule ? { byRule } : {}),
          ...(byFile ? { byFile } : {}),
          ...(byCategory ? { byCategory } : {}),
          ...(byStatus ? { byStatus } : {}),
          ...(complianceSummary ? { compliance: complianceSummary } : {}),
          ...(audit ? { auditId: audit.auditId, integritySha256: audit.integritySha256 } : {}),
          ...(args.failOn ? { gate: { failOn: args.failOn, breached: gateFailed } } : {}),
        },
        null,
        2
      )
    );
  } else if (args.jsonCompact) {
    console.log(
      JSON.stringify(
        {
          tool: report.tool,
          mode: report.mode,
          summary: report.summary,
          ...(complianceSummary ? { compliance: complianceSummary } : {}),
          ...(audit ? { auditId: audit.auditId, integritySha256: audit.integritySha256 } : {}),
          ...(args.failOn ? { gate: { failOn: args.failOn, breached: gateFailed } } : {}),
          items: (args.top ? report.findings.slice(0, args.top) : report.findings).map((f) => ({
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
          ...(bySeverity ? { bySeverity } : {}),
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
