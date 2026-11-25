import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const LOCKFILES = [
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
];

function makeSupFindingId(ruleId: string, scopeKey: string): string {
  const hash = crypto
    .createHash("sha256")
    .update(`${ruleId}:${scopeKey}`)
    .digest("hex")
    .slice(0, 10);
  return `F-${hash}`;
}

async function fileExistsSafe(root: string, rel: string): Promise<boolean> {
  const safe = resolveSafeWorkspacePath(root, rel);
  if (!safe) return false;
  try {
    await fs.access(safe);
    return true;
  } catch {
    return false;
  }
}

export async function runLockfileAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  const findings: Finding[] = [];
  const hasPackageJson = await fileExistsSafe(policy.workspaceRoot, "package.json");
  if (!hasPackageJson) {
    return findings;
  }

  let hasAnyLockfile = false;
  for (const lf of LOCKFILES) {
    if (await fileExistsSafe(policy.workspaceRoot, lf)) {
      hasAnyLockfile = true;
      break;
    }
  }

  if (!hasAnyLockfile) {
    findings.push({
      id: makeSupFindingId("MANINY-SUP-001", policy.workspaceRoot),
      ruleId: "MANINY-SUP-001",
      title: "Missing dependency lockfile alongside package.json",
      category: "secret-exposure",
      severity: "low",
      filePath: path.relative(policy.workspaceRoot, policy.workspaceRoot) || "package.json",
      line: 1,
      description:
        "No lockfile (package-lock.json, pnpm-lock.yaml, yarn.lock, or bun.lock) found; dependency resolution may drift across environments.",
      status: "detected",
      evidence: [],
    });
  }

  const hasGitignore = await fileExistsSafe(policy.workspaceRoot, ".gitignore");
  if (!hasGitignore) {
    findings.push({
      id: makeSupFindingId("MANINY-SUP-002", `${policy.workspaceRoot}:gitignore`),
      ruleId: "MANINY-SUP-002",
      title: "Missing .gitignore file in Node/TypeScript workspace",
      category: "http-hardening",
      severity: "info",
      filePath: ".gitignore",
      line: 1,
      description:
        "Add a .gitignore file to prevent committing local environment files, build artifacts, or sensitive credentials.",
      status: "detected",
      evidence: [],
    });
  }

  return findings;
}
