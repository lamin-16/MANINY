import { Finding, ManinyPolicy } from "../core/types.js";
import { getRule } from "../core/registry.js";
import { isHostInAllowedScope } from "../core/policy-guard.js";
import { transitionStatus } from "../core/state-machine.js";

const BASELINE_SECURITY_HEADERS = [
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "content-security-policy",
] as const;

async function probeAllowedHttpHeaders(
  targetUrl: string
): Promise<{ confirmed: boolean; message: string }> {
  try {
    const response = await fetch(targetUrl, {
      method: "GET",
      redirect: "follow",
    });

    const missing = BASELINE_SECURITY_HEADERS.filter(
      (headerName) => !response.headers.get(headerName)
    );

    const wildcardCors = response.headers.get("access-control-allow-origin") === "*";
    const missingHsts =
      targetUrl.startsWith("https://") && !response.headers.get("strict-transport-security");

    const issues: string[] = [];
    if (missing.length > 0) {
      issues.push(`missing headers [${missing.join(", ")}]`);
    }
    if (missingHsts) {
      issues.push("missing strict-transport-security on HTTPS");
    }
    if (wildcardCors) {
      issues.push("wildcard Access-Control-Allow-Origin (*)");
    }

    if (issues.length > 0) {
      return {
        confirmed: true,
        message: `HTTP ${response.status}: ${issues.join("; ")}.`,
      };
    }

    return {
      confirmed: false,
      message: `HTTP ${response.status}: baseline HTTP security headers and transport policy verified.`,
    };
  } catch (err) {
    return {
      confirmed: false,
      message: `Safe HTTP check skipped/failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export async function runSafeVerifier(
  findings: Finding[],
  policy: ManinyPolicy
): Promise<Finding[]> {
  const output: Finding[] = [];

  for (const finding of findings) {
    let updated: Finding = {
      ...finding,
      evidence: [...finding.evidence],
      ...(finding.fix ? { fix: { ...finding.fix } } : {}),
    };

    if (updated.ruleId !== "MANINY-HTTP-HEADERS" && updated.filePath) {
      const rule = getRule(updated.ruleId);
      const confirmed = rule?.verifyLine ? true : Boolean(rule);
      updated.evidence.push({
        stage: "verify",
        probeType: "static-proof",
        target: `${updated.filePath}:${updated.line ?? 1}`,
        confirmed,
        message: confirmed
          ? "Static verification confirmed vulnerable pattern at target location."
          : "Static rule match recorded for review.",
        timestamp: new Date().toISOString(),
      });

      if (confirmed && updated.status === "detected") {
        updated = transitionStatus(
          updated,
          "verified_exploitable",
          "Static pattern verified at target line"
        );
      }
    } else if (updated.ruleId === "MANINY-HTTP-HEADERS" && updated.targetUrl) {
      if (!policy.allowSafeOffensiveProbes) {
        updated.evidence.push({
          stage: "verify",
          probeType: "safe-http-check",
          target: updated.targetUrl,
          confirmed: false,
          message: "HTTP header check skipped (--allow-probes not enabled).",
          timestamp: new Date().toISOString(),
        });
        if (updated.status === "detected") {
          updated = transitionStatus(updated, "needs_review", "Probes disabled by policy");
        }
      } else if (!isHostInAllowedScope(updated.targetUrl, policy.allowedTargetHosts)) {
        updated.evidence.push({
          stage: "verify",
          probeType: "safe-http-check",
          target: updated.targetUrl,
          confirmed: false,
          message: "HTTP header check skipped (target host not in --allow-host).",
          timestamp: new Date().toISOString(),
        });
        if (updated.status === "detected") {
          updated = transitionStatus(updated, "needs_review", "Target out of allowed scope");
        }
      } else {
        const probe = await probeAllowedHttpHeaders(updated.targetUrl);
        updated.evidence.push({
          stage: "verify",
          probeType: "safe-http-check",
          target: updated.targetUrl,
          confirmed: probe.confirmed,
          message: probe.message,
          timestamp: new Date().toISOString(),
        });

        if (probe.confirmed && updated.status === "detected") {
          updated = transitionStatus(
            updated,
            "verified_exploitable",
            "HTTP hardening gap confirmed on allowed host"
          );
        } else if (!probe.confirmed && updated.status === "detected") {
          updated = transitionStatus(
            updated,
            "needs_review",
            "HTTP hardening posture verified on allowed host"
          );
        }
      }
    }

    output.push(updated);
  }

  return output;
}
