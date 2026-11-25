import path from "node:path";
import { Finding, ManinyPolicy, Severity } from "./types.js";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function resolveSafeWorkspacePath(
  workspaceRoot: string,
  candidatePath: string
): string | null {
  const resolvedRoot = path.resolve(workspaceRoot);
  const resolvedTarget = path.resolve(resolvedRoot, candidatePath);
  const relative = path.relative(resolvedRoot, resolvedTarget);

  if (
    relative === "" ||
    relative.startsWith("..") ||
    path.isAbsolute(relative)
  ) {
    return null;
  }

  return resolvedTarget;
}

export function isProtectedPath(
  filePath: string,
  blockedSubstrings: string[]
): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return blockedSubstrings.some((item) =>
    normalized.includes(item.replace(/\\/g, "/").toLowerCase())
  );
}

export function isHostInAllowedScope(
  targetUrl: string,
  allowedHosts: string[]
): boolean {
  if (allowedHosts.length === 0) {
    return false;
  }

  try {
    const parsed = new URL(targetUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return false;
    }

    const hostname = parsed.hostname.toLowerCase();
    return allowedHosts.some((allowed) => {
      const cleanAllowed = allowed.trim().toLowerCase();
      return hostname === cleanAllowed || hostname.endsWith(`.${cleanAllowed}`);
    });
  } catch {
    return false;
  }
}

export function checkAutoFixEligibility(
  finding: Finding,
  policy: ManinyPolicy
): { allowed: boolean; reason: string } {
  if (!policy.allowAutoFix) {
    return { allowed: false, reason: "Auto-fix is disabled by policy." };
  }

  if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[policy.maxAutoFixSeverity]) {
    return {
      allowed: false,
      reason: `Finding severity (${finding.severity}) exceeds policy limit (${policy.maxAutoFixSeverity}).`,
    };
  }

  if (!finding.filePath) {
    return { allowed: false, reason: "No target file path associated with finding." };
  }

  if (isProtectedPath(finding.filePath, policy.blockedPathSubstrings)) {
    return {
      allowed: false,
      reason: `Target file (${finding.filePath}) matches a protected path rule.`,
    };
  }

  const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, finding.filePath);
  if (!safePath) {
    return {
      allowed: false,
      reason: `Target file (${finding.filePath}) is outside the workspace root.`,
    };
  }

  return { allowed: true, reason: "Eligible for safe automated remediation." };
}
