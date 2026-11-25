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
import { runCorsOriginAuditor } from "./stages/cors-origin-auditor.js";
import { runSecretRotationAuditor } from "./stages/secret-rotation-auditor.js";
import { runCommandExecutionAuditor } from "./stages/command-execution-auditor.js";
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
import { runCryptoKeyAuditor } from "./stages/crypto-key-auditor.js";
import { runHttpHeadersAuditor } from "./stages/http-headers-auditor.js";
import { runInjectionGuardAuditor } from "./stages/injection-guard-auditor.js";
import { runXxeParserAuditor } from "./stages/xxe-parser-auditor.js";
import { runCspSecurityHeadersAuditor } from "./stages/csp-security-headers-auditor.js";
import { runSubprocessExecAuditor } from "./stages/subprocess-exec-auditor.js";
import { runDynamicEvalAuditor } from "./stages/dynamic-eval-auditor.js";
import { runWebsocketAuditor } from "./stages/websocket-auditor.js";
import { runFileUploadAuditor } from "./stages/file-upload-auditor.js";
import { runSsrfOutboundAuditor } from "./stages/ssrf-outbound-auditor.js";
import { runOpenRedirectCorsAuditor } from "./stages/open-redirect-cors-auditor.js";
import { runJwtTokenAuditor } from "./stages/jwt-token-auditor.js";
import { runGraphqlSecurityAuditor } from "./stages/graphql-security-auditor.js";
import { runMassAssignmentAuditor } from "./stages/mass-assignment-auditor.js";
import { runSecretExposureAuditor } from "./stages/secret-exposure-auditor.js";
import { runAccessControlAuditor } from "./stages/access-control-auditor.js";
import { runCryptoWeaknessAuditor } from "./stages/crypto-weakness-auditor.js";
import { runLogInjectionAuditor } from "./stages/log-injection-auditor.js";
import { runEnvConfigAuditor } from "./stages/env-config-auditor.js";
import { runSubprocessSecurityAuditor } from "./stages/subprocess-security-auditor.js";
import { runRegexSecurityAuditor } from "./stages/regex-security-auditor.js";
import { runSqlQueryAuditor } from "./stages/sql-query-auditor.js";
import { runXssSinkAuditor } from "./stages/xss-sink-auditor.js";
import { runSsrfNetworkAuditor } from "./stages/ssrf-network-auditor.js";
import { runCspHeadersAuditor } from "./stages/csp-headers-auditor.js";
import { runPathTraversalAuditor } from "./stages/path-traversal-auditor.js";
import { runSsrfRequestAuditor } from "./stages/ssrf-request-auditor.js";
import { runCommandExecAuditor } from "./stages/command-exec-auditor.js";
import { runDeserializationAuditor } from "./stages/deserialization-auditor.js";
import { runSecurityHeadersAuditor } from "./stages/security-headers-auditor.js";
import { runPrototypePollutionAuditor } from "./stages/prototype-pollution-auditor.js";
import { runSqlInjectionAuditor } from "./stages/sql-injection-auditor.js";
import { runXssDomAuditor } from "./stages/xss-dom-auditor.js";
import { runRedosPatternAuditor } from "./stages/redos-pattern-auditor.js";
import { runLdapInjectionAuditor } from "./stages/ldap-injection-auditor.js";
import { runNosqlInjectionAuditor } from "./stages/nosql-injection-auditor.js";
import { runTemplateInjectionAuditor } from "./stages/template-injection-auditor.js";
import { runArchiveTempAuditor } from "./stages/archive-temp-auditor.js";
import { runQueueEventAuditor } from "./stages/queue-event-auditor.js";
import { runWebsocketSecurityAuditor } from "./stages/websocket-security-auditor.js";
import { runRaceConditionAuditor } from "./stages/race-condition-auditor.js";
import { runTimingSidechannelAuditor } from "./stages/timing-sidechannel-auditor.js";
import { runResourceExhaustionAuditor } from "./stages/resource-exhaustion-auditor.js";
import { runHardcodedCredentialsAuditor } from "./stages/hardcoded-credentials-auditor.js";
import { runDependencySupplyChainAuditor } from "./stages/dependency-supply-chain-auditor.js";
import { runContainerSecurityAuditor } from "./stages/container-security-auditor.js";
import { runIacPermissionsAuditor } from "./stages/iac-permissions-auditor.js";
import { runAuthzPrivilegeAuditor } from "./stages/authz-privilege-auditor.js";
import { runAuditLoggingAuditor } from "./stages/audit-logging-auditor.js";
import { runFileTransferAuditor } from "./stages/file-transfer-auditor.js";
import { runMfaSessionAuditor } from "./stages/mfa-session-auditor.js";
import { runCsrfProtectionAuditor } from "./stages/csrf-protection-auditor.js";
import { runBackupRetentionAuditor } from "./stages/backup-retention-auditor.js";
import { runSsrfDynamicAuditor } from "./stages/ssrf-dynamic-auditor.js";
import { runJwtAuthAuditor } from "./stages/jwt-auth-auditor.js";
import { runWebhookSignatureAuditor } from "./stages/webhook-signature-auditor.js";
import { runDependencySupplyAuditor } from "./stages/dependency-supply-auditor.js";
import { runOauthStateAuditor } from "./stages/oauth-state-auditor.js";
import { runTenantIsolationAuditor } from "./stages/tenant-isolation-auditor.js";
import { runFeatureFlagAuditor } from "./stages/feature-flag-auditor.js";
import { runNotificationInjectionAuditor } from "./stages/notification-injection-auditor.js";
import { runUploadSafetyAuditor } from "./stages/upload-safety-auditor.js";
import { runOpenRedirectAuditor } from "./stages/open-redirect-auditor.js";
import { runSsrfGuardAuditor } from "./stages/ssrf-guard-auditor.js";
import { runSensitiveDataAuditor } from "./stages/sensitive-data-auditor.js";
import { runTokenEntropyAuditor } from "./stages/token-entropy-auditor.js";
import { runCorsPolicyAuditor } from "./stages/cors-policy-auditor.js";
import { runCookieSecurityAuditor } from "./stages/cookie-security-auditor.js";
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
      cspSecHdrFindings,
      pthTravFindings,
      cmdExecFindings,
      dsrFindings,
      prtFindings,
      sqlInjFindings,
      xssDomFindings,
      rdxPatFindings,
      ldpInjFindings,
      srfDynFindings,
      jwtAuthFindings,
      whkSigFindings,
      uplSafFindings,
      opnRdrFindings,
      crsPolFindings,
      cokSecFindings,
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
      runCspHeadersAuditor(policy),
      runPathTraversalAuditor(policy),
      runCommandExecAuditor(policy),
      runDeserializationAuditor(policy),
      runPrototypePollutionAuditor(policy),
      runSqlInjectionAuditor(policy),
      runXssDomAuditor(policy),
      runRedosPatternAuditor(policy),
      runLdapInjectionAuditor(policy),
      runSsrfDynamicAuditor(policy),
      runJwtAuthAuditor(policy),
      runWebhookSignatureAuditor(policy),
      runUploadSafetyAuditor(policy),
      runOpenRedirectAuditor(policy),
      runCorsPolicyAuditor(policy),
      runCookieSecurityAuditor(policy),
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
      ...cspSecHdrFindings,
      ...pthTravFindings,
      ...cmdExecFindings,
      ...dsrFindings,
      ...prtFindings,
      ...sqlInjFindings,
      ...xssDomFindings,
      ...rdxPatFindings,
      ...ldpInjFindings,
      ...srfDynFindings,
      ...jwtAuthFindings,
      ...whkSigFindings,
      ...uplSafFindings,
      ...opnRdrFindings,
      ...crsPolFindings,
      ...cokSecFindings,
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
