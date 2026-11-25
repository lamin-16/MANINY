import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { Finding, ManinyPolicy, Severity } from "../core/types.js";
import { resolveSafeWorkspacePath } from "../core/policy-guard.js";

const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", ".next", "coverage"]);
const SCAN_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json"]);

export interface LineAuditRule {
  id: string;
  severity: Severity;
  category: Finding["category"];
  title: string;
  regex: RegExp;
  description: string;
  extensions?: Set<string>;
}

export function makeStageFindingId(ruleId: string, relFile: string, line: number): string {
  const hash = crypto.createHash("sha256").update(`${ruleId}:${relFile}:${line}`).digest("hex").slice(0, 10);
  return `F-${hash}`;
}

async function collectWorkspaceFiles(dir: string, root: string): Promise<string[]> {
  const safeRoot = path.resolve(root);
  const relDir = path.relative(safeRoot, dir);
  const safeDir = relDir === "" ? safeRoot : resolveSafeWorkspacePath(safeRoot, relDir);
  if (!safeDir) return [];
  const entries = await fs.readdir(safeDir, { withFileTypes: true });
  const results: string[] = [];
  for (const entry of entries) {
    if (entry.name.includes("..") || path.isAbsolute(entry.name)) continue;
    const candidate = resolveSafeWorkspacePath(safeRoot, path.relative(safeRoot, path.join(safeDir, entry.name)));
    if (!candidate) continue;
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) results.push(...(await collectWorkspaceFiles(candidate, safeRoot)));
    } else if (entry.isFile() && SCAN_EXTS.has(path.extname(entry.name).toLowerCase())) {
      const rel = path.relative(safeRoot, candidate);
      if (rel && !rel.startsWith("..")) results.push(rel);
    }
  }
  return results;
}

const RULE_DEFINITION_LINE = /^\s*(?:title|description|regex)\s*:/;

export function isRuleDefinitionLine(lineText: string, skipRegExpCtor = true): boolean {
  if (RULE_DEFINITION_LINE.test(lineText)) return true;
  return skipRegExpCtor && lineText.includes("new RegExp(");
}

export interface ScanOptions {
  skipRegExpCtor?: boolean;
}

export async function scanWorkspaceRules(policy: ManinyPolicy, rules: LineAuditRule[], options: ScanOptions = {}): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await collectWorkspaceFiles(policy.workspaceRoot, policy.workspaceRoot);
  for (const relFile of files) {
    const ext = path.extname(relFile).toLowerCase();
    const activeRules = rules.filter((r) => (r.extensions ?? new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"])).has(ext));
    if (!activeRules.length) continue;
    const safePath = resolveSafeWorkspacePath(policy.workspaceRoot, relFile);
    if (!safePath) continue;
    let content: string;
    try { content = await fs.readFile(safePath, "utf8"); } catch { continue; }
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i] ?? "";
      const trimmed = lineText.trim();
      if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
      for (const rule of activeRules) {
        if (!isRuleDefinitionLine(lineText, options.skipRegExpCtor ?? true) && rule.regex.test(lineText)) {
          const lineNum = i + 1;
          findings.push({
            id: makeStageFindingId(rule.id, relFile, lineNum),
            ruleId: rule.id,
            title: rule.title,
            category: rule.category,
            severity: rule.severity,
            filePath: relFile,
            line: lineNum,
            description: rule.description,
            status: "detected",
            evidence: [],
          });
        }
      }
    }
  }
  return findings;
}
