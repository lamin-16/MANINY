import fs from "node:fs/promises";
import { Finding, ManinyPolicy } from "../core/types.js";
import { getRule } from "../core/registry.js";
import { transitionStatus } from "../core/state-machine.js";
import { isHostInAllowedScope, resolveSafeWorkspacePath } from "../core/policy-guard.js";

async function probeAllowedHttpHeaders(
  targetUrl: string,
  timeoutMs = 5000
): Promise<{ confirmed: boolean; message: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(targetUrl, {
      method: "GET",
      signal: controller.signal,
      redirect: "follow",
    });

    const missingHeaders: string[] = [];
    if (!response.headers.get("x-content-type-options")) {
      missingHeaders.push("x-content-type-options");
    }
    if (
      !response.headers.get("x-frame-options") &&
      !response.headers.get("content-security-policy")
    ) {
      missingHeaders.push("x-frame-options/csp");
    }

    if (missingHeaders.length > 0) {
      return {
        confirmed: true,
        message: `HTTP ${response.status} received; missing baseline headers: ${missingHeaders.join(", ")}.`,
      };
    }

    return {
      confirmed: false,
      message: `HTTP ${response.status} received; baseline security headers present.`,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Unknown network probe error";
    return {
      confirmed: false,
      message: `Safe HTTP probe did not confirm issue: ${msg}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function runSafeVerifier(
  findings: Finding[],
  policy: ManinyPolicy
): Promise<Finding[]> {
  const output: Finding[] = [];

  for (const finding of findings) {
    let updated: Finding = { ...finding, evidence: [...finding.evidence] };

    if (updated.filePath) {
      const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, updated.filePath);
      if (safePath) {
        try {
          const content = await fs.readFile(safePath, "utf8");
          const lines = content.split(/\r?\n/);
          const snippet = updated.line ? lines[updated.line - 1] ?? "" : content;
          const rule = getRule(updated.ruleId);

          const confirmed = rule?.verifyLine
            ? rule.verifyLine(snippet)
            : rule
              ? rule.detectLine(snippet)
              : false;

          updated.evidence.push({
            stage: "verify",
            probeType: "static-proof",
            target: `${updated.filePath}${updated.line ? `:${updated.line}` : ""}`,
            confirmed,
            message: confirmed
              ? "Static verification confirmed vulnerable pattern at target location."
              : "Static verification did not confirm active pattern.",
            timestamp: new Date().toISOString(),
          });

          if (confirmed && updated.status === "detected") {
            updated = transitionStatus(
              updated,
              "verified_exploitable",
              "Confirmed by static verification"
            );
          } else if (!confirmed && updated.status === "detected") {
            updated = transitionStatus(
              updated,
              "needs_review",
              "Unconfirmed pattern requires review"
            );
          }
        } catch {
          updated = transitionStatus(
            updated,
            "needs_review",
            "Unable to read target file during verification"
          );
        }
      }
    } else if (updated.targetUrl) {
      if (!policy.allowSafeOffensiveProbes) {
        updated.evidence.push({
          stage: "verify",
          probeType: "safe-http-check",
          target: updated.targetUrl,
          confirmed: false,
          message: "Safe offensive probes are disabled by policy.",
          timestamp: new Date().toISOString(),
        });
        if (updated.status === "detected") {
          updated = transitionStatus(updated, "needs_review", "Probes disabled");
        }
      } else if (!isHostInAllowedScope(updated.targetUrl, policy.allowedTargetHosts)) {
        updated.evidence.push({
          stage: "verify",
          probeType: "safe-http-check",
          target: updated.targetUrl,
          confirmed: false,
          message: "Target host is outside policy allowedTargetHosts scope.",
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
            "Missing baseline security headers confirmed on allowed host"
          );
        } else if (!probe.confirmed && updated.status === "detected") {
          updated = transitionStatus(
            updated,
            "needs_review",
            "No header weakness confirmed by safe check"
          );
        }
      }
    }

    output.push(updated);
  }

  return output;
}
