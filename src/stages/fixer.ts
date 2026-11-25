import fs from "node:fs/promises";
import crypto from "node:crypto";
import { Finding, ManinyPolicy } from "../core/types.js";
import { getRule } from "../core/registry.js";
import { checkAutoFixEligibility, resolveSafeWorkspacePath } from "../core/policy-guard.js";
import { transitionStatus } from "../core/state-machine.js";

function createSimpleDiff(filePath: string, beforeText: string, afterText: string): string {
  return [
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
    `@@ -1 +1 @@`,
    `- ${beforeText.replace(/\r?\n/g, " | ")}`,
    `+ ${afterText.replace(/\r?\n/g, " | ")}`,
  ].join("\n");
}

export async function runFixer(
  findings: Finding[],
  policy: ManinyPolicy
): Promise<Finding[]> {
  const results: Finding[] = [];

  for (const finding of findings) {
    let current: Finding = {
      ...finding,
      evidence: [...finding.evidence],
      ...(finding.fix ? { fix: { ...finding.fix } } : {}),
    };

    const canPatchCurrentState =
      current.status === "verified_exploitable" ||
      current.status === "detected" ||
      current.status === "needs_review";

    if (!canPatchCurrentState || !current.filePath) {
      results.push(current);
      continue;
    }

    const eligibility = checkAutoFixEligibility(current, policy);
    if (!eligibility.allowed) {
      current.evidence.push({
        stage: "review",
        probeType: "remediation-check",
        target: current.filePath,
        confirmed: false,
        message: `Auto-fix skipped: ${eligibility.reason}`,
        timestamp: new Date().toISOString(),
      });
      if (current.status !== "needs_review") {
        current = transitionStatus(current, "needs_review", eligibility.reason);
      }
      results.push(current);
      continue;
    }

    const rule = getRule(current.ruleId);
    if (!rule?.fixLine) {
      current.evidence.push({
        stage: "review",
        probeType: "remediation-check",
        target: current.filePath,
        confirmed: false,
        message: `No automated fix handler registered for ${current.ruleId}; manual review required.`,
        timestamp: new Date().toISOString(),
      });
      if (current.status !== "needs_review") {
        current = transitionStatus(
          current,
          "needs_review",
          `No automated fix rule available for ${current.ruleId}`
        );
      }
      results.push(current);
      continue;
    }

    const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, current.filePath);
    if (!safePath) {
      results.push(current);
      continue;
    }

    const originalContent = await fs.readFile(safePath, "utf8");
    const lines = originalContent.split(/\r?\n/);
    const idx = current.line ? current.line - 1 : -1;

    if (idx < 0 || idx >= lines.length) {
      current = transitionStatus(current, "needs_review", "Line index out of range");
      results.push(current);
      continue;
    }

    const originalLine = lines[idx] ?? "";
    const fixResult = rule.fixLine(originalLine);

    if (!fixResult.changed) {
      current = transitionStatus(
        current,
        "needs_review",
        `Rule ${current.ruleId} produced no change on target line.`
      );
      results.push(current);
      continue;
    }

    const nextLines = [...lines];
    nextLines[idx] = fixResult.nextLine;
    const updatedContent = nextLines.join("\n");

    await fs.writeFile(safePath, updatedContent, "utf8");

    const fixId =
      "FIX-" +
      crypto.createHash("sha256").update(`${current.id}:${Date.now()}`).digest("hex").slice(0, 8);

    current.fix = {
      fixId,
      ruleId: current.ruleId,
      filePath: current.filePath,
      backupContent: originalContent,
      unifiedDiff: createSimpleDiff(current.filePath, originalLine, fixResult.nextLine),
      appliedAt: new Date().toISOString(),
    };

    current = transitionStatus(current, "patched", `Applied fix ${fixId}`);
    results.push(current);
  }

  return results;
}
