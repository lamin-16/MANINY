import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const HIGH_RISK_PACKAGES = new Set([
  "event-stream",
  "node-ipc",
  "ua-parser-js",
  "colors",
  "faker",
  "request",
]);

function makeDepFindingId(depName: string, versionSpec: string): string {
  const hash = crypto
    .createHash("sha256")
    .update(`MANINY-DEP-001:${depName}:${versionSpec}`)
    .digest("hex")
    .slice(0, 10);
  return `F-${hash}`;
}

export async function runDependencyAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  const pkgPath = resolveSafeWorkspacePath(policy.workspaceRoot, "package.json");
  if (!pkgPath) {
    return [];
  }

  let raw: string;
  try {
    raw = await fs.readFile(pkgPath, "utf8");
  } catch {
    return [];
  }

  let parsed: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  try {
    parsed = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
  } catch {
    return [];
  }

  const combined: Array<[string, string, string]> = [];
  for (const [name, ver] of Object.entries(parsed.dependencies ?? {})) {
    combined.push([name, String(ver), "dependencies"]);
  }
  for (const [name, ver] of Object.entries(parsed.devDependencies ?? {})) {
    combined.push([name, String(ver), "devDependencies"]);
  }

  const findings: Finding[] = [];

  for (const [depName, versionSpec, section] of combined) {
    const cleanVer = versionSpec.trim();
    const isWildcardOrLatest = cleanVer === "*" || cleanVer === "latest" || cleanVer === "";
    const isRiskyPkg = HIGH_RISK_PACKAGES.has(depName);
    const isUnencryptedGitOrHttp = /^http:\/\//i.test(cleanVer) || /git\+http:\/\//i.test(cleanVer);

    if (isRiskyPkg || isWildcardOrLatest || isUnencryptedGitOrHttp) {
      const severity = isRiskyPkg || isUnencryptedGitOrHttp ? "high" : "medium";
      const reasons: string[] = [];
      if (isRiskyPkg) reasons.push(`high-risk package "${depName}"`);
      if (isWildcardOrLatest) reasons.push(`unpinned version "${cleanVer || "empty"}"`);
      if (isUnencryptedGitOrHttp) reasons.push(`unencrypted http source "${cleanVer}"`);

      findings.push({
        id: makeDepFindingId(depName, cleanVer),
        ruleId: "MANINY-DEP-001",
        title: `Dependency risk in ${section}: ${depName}`,
        category: "secret-exposure",
        severity,
        filePath: path.relative(policy.workspaceRoot, pkgPath) || "package.json",
        line: 1,
        description: `Detected ${reasons.join(" and ")} in ${section}. Pin exact/caret semver ranges and audit supply-chain integrity.`,
        status: "detected",
        evidence: [],
      });
    }
  }

  return findings;
}
