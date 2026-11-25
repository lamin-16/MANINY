import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy } from "../core/types.js";
import { listRules } from "../core/registry.js";
import { isHostInAllowedScope, resolveSafeWorkspacePath } from "../core/policy-guard.js";

const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  "coverage",
]);

const SCANNABLE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".py",
  ".sh",
  ".go",
  ".env.example",
  ".yaml",
  ".yml",
]);

function isIgnoredFile(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  return lower.startsWith("maniny-report") || lower.endsWith(".sarif");
}

function isCommentOrRegexPatternLine(trimmedLine: string): boolean {
  if (!trimmedLine) return true;
  if (
    trimmedLine.startsWith("//") ||
    trimmedLine.startsWith("/*") ||
    trimmedLine.startsWith("*") ||
    trimmedLine.startsWith("*/")
  ) {
    return true;
  }
  // Skip regex literal definitions inside rule matchers
  if (/^\s*\/.+\/[gimsuvy]*\s*[,;)]?\s*$/.test(trimmedLine)) {
    return true;
  }
  return false;
}

async function walkWorkspaceFiles(dirPath: string, rootDir: string): Promise<string[]> {
  const entries = await fs.readdir(dirPath, { withFileTypes: true });
  const files: string[] = [];

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) {
        continue;
      }
      const nested = await walkWorkspaceFiles(path.join(dirPath, entry.name), rootDir);
      files.push(...nested);
    } else if (entry.isFile()) {
      if (isIgnoredFile(entry.name)) {
        continue;
      }
      const ext = path.extname(entry.name).toLowerCase();
      if (SCANNABLE_EXTENSIONS.has(ext) || entry.name.startsWith(".env")) {
        const fullPath = path.join(dirPath, entry.name);
        const relPath = path.relative(rootDir, fullPath);
        if (relPath) {
          files.push(relPath);
        }
      }
    }
  }

  return files;
}

function createFindingId(ruleId: string, target: string, line?: number): string {
  const hash = crypto
    .createHash("sha256")
    .update(`${ruleId}:${target}:${line ?? 0}`)
    .digest("hex")
    .slice(0, 10);
  return `F-${hash}`;
}

export async function runDetector(
  policy: ManinyPolicy,
  targetUrls: string[] = [],
  options: { skipWorkspaceScan?: boolean } = {}
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const rules = listRules();

  if (!options.skipWorkspaceScan) {
    const relativeFiles = await walkWorkspaceFiles(policy.workspaceRoot, policy.workspaceRoot);

    for (const relPath of relativeFiles) {
      const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, relPath);
      if (!safePath) {
        continue;
      }

      const content = await fs.readFile(safePath, "utf8");
      const lines = content.split(/\r?\n/);

      for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i] ?? "";
        const trimmed = lineText.trim();
        if (isCommentOrRegexPatternLine(trimmed)) {
          continue;
        }

        const lineNumber = i + 1;

        for (const rule of rules) {
          if (rule.detectLine(lineText)) {
            findings.push({
              id: createFindingId(rule.ruleId, relPath, lineNumber),
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
  }

  for (const url of targetUrls) {
    const allowed = isHostInAllowedScope(url, policy.allowedTargetHosts);
    findings.push({
      id: createFindingId("MANINY-HTTP-HEADERS", url),
      ruleId: "MANINY-HTTP-HEADERS",
      title: "HTTP security headers baseline audit",
      category: "http-hardening",
      severity: allowed ? "low" : "info",
      targetUrl: url,
      description: allowed
        ? "Target endpoint queued for safe non-destructive HTTP header verification."
        : "Target endpoint recorded; add --allow-host to permit safe verification probes.",
      status: "detected",
      evidence: [],
    });
  }

  return findings;
}
