import fs from "node:fs/promises";
import { Finding, ManinyPolicy, PipelineReport, ReportFormat, RunMode } from "./core/types.js";
import { formatSarifReport } from "./core/reporter.js";
import { runDetector } from "./stages/detector.js";
import { runDependencyAuditor } from "./stages/dependency-auditor.js";
import { runEnvAuditor } from "./stages/env-auditor.js";
import { runBehavioralAuditor } from "./stages/behavioral-auditor.js";
import { runLockfileAuditor } from "./stages/lockfile-auditor.js";
import { runPermissionAuditor } from "./stages/permission-auditor.js";
import { runCryptoAuditor } from "./stages/crypto-auditor.js";
import { runProcessAuditor } from "./stages/process-auditor.js";
import { runInputAuditor } from "./stages/input-auditor.js";
import { runSecurityConfigAuditor } from "./stages/security-config-auditor.js";
import { runFrontendXssAuditor } from "./stages/frontend-xss-auditor.js";
import { runRedirectAuditor } from "./stages/redirect-auditor.js";
import { runModuleLoadAuditor } from "./stages/module-load-auditor.js";
import { runQueryAuditor } from "./stages/query-auditor.js";
import { runSessionCookieAuditor } from "./stages/session-cookie-auditor.js";
import { runSerializationAuditor } from "./stages/serialization-auditor.js";
import { runMessagingAuditor } from "./stages/messaging-auditor.js";
import { runRegexAuditor } from "./stages/regex-auditor.js";
import { runObjectPrototypeAuditor } from "./stages/object-prototype-auditor.js";
import { runAuthJwtAuditor } from "./stages/auth-jwt-auditor.js";
import { runTimingResilienceAuditor } from "./stages/timing-resilience-auditor.js";
import { runLogLeakAuditor } from "./stages/log-leak-auditor.js";
import { runNetworkFetchAuditor } from "./stages/network-fetch-auditor.js";
import { runStorageCacheAuditor } from "./stages/storage-cache-auditor.js";
import { runCorsHeadersAuditor } from "./stages/cors-headers-auditor.js";
import { runTemplateHtmlAuditor } from "./stages/template-html-auditor.js";
import { runDbOrmAuditor } from "./stages/db-orm-auditor.js";
import { runSensitivePathAuditor } from "./stages/sensitive-path-auditor.js";
import { runArchiveCompressionAuditor } from "./stages/archive-compression-auditor.js";
import { runGraphqlWebhookAuditor } from "./stages/graphql-webhook-auditor.js";
import { runOauthApiKeyAuditor } from "./stages/oauth-api-key-auditor.js";
import { runSsrfDnsAuditor } from "./stages/ssrf-dns-auditor.js";
import { runRateLimitAuditor } from "./stages/rate-limit-auditor.js";
import { runCspSecurityHeadersAuditor } from "./stages/csp-security-headers-auditor.js";
import { runSubprocessExecAuditor } from "./stages/subprocess-exec-auditor.js";
import { runDynamicEvalAuditor } from "./stages/dynamic-eval-auditor.js";
import { runWebsocketAuditor } from "./stages/websocket-auditor.js";
import { runFileUploadAuditor } from "./stages/file-upload-auditor.js";
import { runOpenRedirectCorsAuditor } from "./stages/open-redirect-cors-auditor.js";
import { runJwtTokenAuditor } from "./stages/jwt-token-auditor.js";
import { runGraphqlSecurityAuditor } from "./stages/graphql-security-auditor.js";
import { runSsrfNetworkAuditor } from "./stages/ssrf-network-auditor.js";
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
    const [
      depFindings,
      envFindings,
      behFindings,
      lockFindings,
      permFindings,
      cryFindings,
      prcFindings,
      inpFindings,
      cfgFindings,
      xssFindings,
      rdrFindings,
      modFindings,
      qryFindings,
      sesFindings,
      serFindings,
      msgFindings,
      rgxFindings,
      objFindings,
      authFindings,
      tmpFindings,
      logFindings,
      netFetchFindings,
      stoCacheFindings,
      corsFindings,
      tplHtmlFindings,
      dbOrmFindings,
      pthFindings,
      arcFindings,
      gqlWebhookFindings,
      keyFindings,
      ssrDnsFindings,
      rlmFindings,
      cspHdrFindings,
      subExecFindings,
      dynEvalFindings,
      wskFindings,
      uplFindings,
      openRdrCorsFindings,
      jwtTokFindings,
      gqlSecFindings,
      ssrNetFindings,
      rtlFindings,
    ] = await Promise.all([
      runDependencyAuditor(policy),
      runEnvAuditor(policy),
      runBehavioralAuditor(policy),
      runLockfileAuditor(policy),
      runPermissionAuditor(policy),
      runCryptoAuditor(policy),
      runProcessAuditor(policy),
      runInputAuditor(policy),
      runSecurityConfigAuditor(policy),
      runFrontendXssAuditor(policy),
      runRedirectAuditor(policy),
      runModuleLoadAuditor(policy),
      runQueryAuditor(policy),
      runSessionCookieAuditor(policy),
      runSerializationAuditor(policy),
      runMessagingAuditor(policy),
      runRegexAuditor(policy),
      runObjectPrototypeAuditor(policy),
      runAuthJwtAuditor(policy),
      runTimingResilienceAuditor(policy),
      runLogLeakAuditor(policy),
      runNetworkFetchAuditor(policy),
      runStorageCacheAuditor(policy),
      runCorsHeadersAuditor(policy),
      runTemplateHtmlAuditor(policy),
      runDbOrmAuditor(policy),
      runSensitivePathAuditor(policy),
      runArchiveCompressionAuditor(policy),
      runGraphqlWebhookAuditor(policy),
      runOauthApiKeyAuditor(policy),
      runSsrfDnsAuditor(policy),
      runRateLimitAuditor(policy),
      runCspSecurityHeadersAuditor(policy),
      runSubprocessExecAuditor(policy),
      runDynamicEvalAuditor(policy),
      runWebsocketAuditor(policy),
      runFileUploadAuditor(policy),
      runOpenRedirectCorsAuditor(policy),
      runJwtTokenAuditor(policy),
      runGraphqlSecurityAuditor(policy),
      runSsrfNetworkAuditor(policy),
      runRateLimitAuditor(policy),
    ]);
    findings = [
      ...findings,
      ...depFindings,
      ...envFindings,
      ...behFindings,
      ...lockFindings,
      ...permFindings,
      ...cryFindings,
      ...prcFindings,
      ...inpFindings,
      ...cfgFindings,
      ...xssFindings,
      ...rdrFindings,
      ...modFindings,
      ...qryFindings,
      ...sesFindings,
      ...serFindings,
      ...msgFindings,
      ...rgxFindings,
      ...objFindings,
      ...authFindings,
      ...tmpFindings,
      ...logFindings,
      ...netFetchFindings,
      ...stoCacheFindings,
      ...corsFindings,
      ...tplHtmlFindings,
      ...dbOrmFindings,
      ...pthFindings,
      ...arcFindings,
      ...gqlWebhookFindings,
      ...keyFindings,
      ...ssrDnsFindings,
      ...rlmFindings,
      ...cspHdrFindings,
      ...subExecFindings,
      ...dynEvalFindings,
      ...wskFindings,
      ...uplFindings,
      ...openRdrCorsFindings,
      ...jwtTokFindings,
      ...gqlSecFindings,
      ...ssrNetFindings,
      ...rtlFindings,
    ];
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
