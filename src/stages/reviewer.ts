import fs from "node:fs/promises";
import { Finding, ManinyPolicy } from "../core/types.js";
import { getRule } from "../core/registry.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";
import { transitionStatus } from "../core/state-machine.js";

export async function runDefenderReviewer(
  findings: Finding[],
  policy: ManinyPolicy
): Promise<Finding[]> {
  const reviewed: Finding[] = [];

  for (const finding of findings) {
    let current: Finding = {
      ...finding,
      evidence: [...finding.evidence],
      ...(finding.fix ? { fix: { ...finding.fix } } : {}),
    };

    if (current.status !== "patched" || !current.fix || !current.filePath) {
      reviewed.push(current);
      continue;
    }

    const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, current.filePath);
    if (!safePath) {
      reviewed.push(current);
      continue;
    }

    const currentContent = await fs.readFile(safePath, "utf8");
    const lines = currentContent.split(/\r?\n/);
    const idx = current.line ? current.line - 1 : 0;
    const targetLine = lines[idx] ?? "";
    const rule = getRule(current.ruleId);

    const stillVulnerable = rule?.verifyLine
      ? rule.verifyLine(targetLine)
      : rule
        ? rule.detectLine(targetLine)
        : false;

    const hasNonEmptyContent = currentContent.trim().length > 0;

    if (!stillVulnerable && hasNonEmptyContent) {
      current.evidence.push({
        stage: "review",
        probeType: "remediation-check",
        target: `${current.filePath}:${idx + 1}`,
        confirmed: true,
        message:
          "Defender review confirmed target pattern is removed and file integrity is intact.",
        timestamp: new Date().toISOString(),
      });
      current = transitionStatus(
        current,
        "verified_fixed",
        "Remediation verified by defensive reviewer"
      );
    } else {
      await fs.writeFile(safePath, current.fix.backupContent, "utf8");
      current.fix.rolledBackAt = new Date().toISOString();
      current.evidence.push({
        stage: "review",
        probeType: "remediation-check",
        target: `${current.filePath}:${idx + 1}`,
        confirmed: false,
        message:
          "Defender review detected incomplete fix or invalid state; rolled back file.",
        timestamp: new Date().toISOString(),
      });
      current = transitionStatus(
        current,
        "rolled_back",
        "Rolled back after defensive review check"
      );
    }

    reviewed.push(current);
  }

  return reviewed;
}
