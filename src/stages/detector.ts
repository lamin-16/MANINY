import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy } from "../core/types.js";
import { listRules } from "../core/registry.js";
import { isProtectedPath, resolveSafeWorkspacePath } from "../core/policy-guard.js";

const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  "coverage",
]);

const SCANNABLE_EXTS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".env",
  ".yaml",
  ".yml",
]);

function isReportArtifact(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  return lower.startsWith("maniny-report") || lower.endsWith(".sarif");
}

async function collectFiles(dir: string, acc: string[]): Promise<void> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name) || isReportArtifact(entry.name)) {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectFiles(fullPath, acc);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SCANNABLE_EXTS.has(ext) || entry.name.startsWith(".env")) {
        acc.push(fullPath);
      }
    }
  }
}

function makeFindingId(seed: string): string {
  return "F-" + crypto.createHash("sha256").update(seed).digest("hex").slice(0, 10);
}

export async function runDetector(
  policy: ManinyPolicy,
  targetUrls: string[] = []
): Promise<Finding[]> {
  const files: string[] = [];
  await collectFiles(policy.workspaceRoot, files);

  const rules = listRules();
  const findings: Finding[] = [];

  for (const fullFilePath of files) {
    const relPath = path.relative(policy.workspaceRoot, fullFilePath);
    if (isProtectedPath(relPath, policy.blockedPathSubstrings)) {
      continue;
    }

    const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, relPath);
    if (!safePath) {
      continue;
    }

    let content: string;
    try {
      content = await fs.readFile(safePath, "utf8");
    } catch {
      continue;
    }

    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i] ?? "";
      for (const rule of rules) {
        if (rule.detectLine(lineText)) {
          const lineNumber = i + 1;
          findings.push({
            id: makeFindingId(`${rule.ruleId}:${relPath}:${lineNumber}`),
            ruleId: rule.ruleId,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            filePath: relPath,
            line: lineNumber,
            description: rule.description,
            status: "detected",
            evidence: [],
          });
        }
      }
    }
  }

  for (const url of targetUrls) {
    findings.push({
      id: makeFindingId(`MANINY-HTTP-HEADERS:${url}`),
      ruleId: "MANINY-HTTP-HEADERS",
      title: "HTTP security headers baseline audit",
      category: "http-hardening",
      severity: "low",
      targetUrl: url,
      description:
        "Target endpoint queued for safe non-destructive HTTP header verification.",
      status: "detected",
      evidence: [],
    });
  }

  return findings;
}
