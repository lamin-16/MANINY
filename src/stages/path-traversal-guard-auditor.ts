import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const PATH_TRAVERSAL_GUARD_RULES: LineAuditRule[] = [
  {
    id: "MANINY-PTH-001",
    severity: "high",
    category: "code-pattern",
    title: "Path resolution or archive entry handling lacks visible root boundary or traversal check",
    regex: /\b(resolveWorkspacePath|openUserFileStream|serveArchiveEntry)\s*\([^\r\n)]*(\b(filePath|entryName|relPath|req\.query|req\.params)\b|\$\{)[^\r\n)]*(?![^\r\n]*(isWithinRoot|realpathSync|normalizePath|rejectTraversal))/i,
    description: "Canonicalize paths with realpath/normalize and verify containment inside the intended base directory.",
  },
  {
    id: "MANINY-PTH-002",
    severity: "medium",
    category: "code-pattern",
    title: "Path traversal protection explicitly disabled",
    regex: /\b(skipPathTraversalCheck|allowDotDotSegments)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep path containment and traversal checks active.",
  },
];

export async function runPathTraversalGuardAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, PATH_TRAVERSAL_GUARD_RULES);
}
