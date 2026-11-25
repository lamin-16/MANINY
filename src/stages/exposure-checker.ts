import { Finding, ManinyPolicy } from "../core/types.js";
import { isHostInAllowedScope } from "../core/policy-guard.js";

export interface ExposureCheckResult {
  target: string;
  inScope: boolean;
  checkedAt: string;
  findings: Finding[];
}

export async function runExposureChecks(
  targets: string[],
  policy: ManinyPolicy
): Promise<ExposureCheckResult[]> {
  const results: ExposureCheckResult[] = [];

  for (const target of targets) {
    const inScope =
      policy.allowSafeOffensiveProbes &&
      isHostInAllowedScope(target, policy.allowedTargetHosts);

    if (!inScope) {
      results.push({
        target,
        inScope: false,
        checkedAt: new Date().toISOString(),
        findings: [],
      });
      continue;
    }

    const detected: Finding[] = [];
    try {
      const response = await fetch(target, { method: "GET", redirect: "follow" });
      if (!response.headers.get("strict-transport-security")) {
        detected.push({
          id: `EXP-HSTS-${Buffer.from(target).toString("base64url").slice(0, 8)}`,
          ruleId: "MANINY-EXP-HSTS",
          title: "Missing Strict-Transport-Security header",
          category: "http-hardening",
          severity: "medium",
          targetUrl: target,
          description: "Target response lacks HSTS header for transport enforcement.",
          status: "detected",
          evidence: [
            {
              stage: "verify",
              probeType: "safe-http-check",
              target,
              confirmed: true,
              message: `HTTP ${response.status} without Strict-Transport-Security header.`,
              timestamp: new Date().toISOString(),
            },
          ],
        });
      }
    } catch {
      // Keep non-destructive check silent on unreachable/timed-out targets
    }

    results.push({
      target,
      inScope: true,
      checkedAt: new Date().toISOString(),
      findings: detected,
    });
  }

  return results;
}
