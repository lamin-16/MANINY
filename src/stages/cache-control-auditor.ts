import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const CACHE_CONTROL_RULES: LineAuditRule[] = [
  {
    id: "MANINY-CCH-001",
    severity: "medium",
    category: "code-pattern",
    title: "Sensitive or authenticated response cache directive lacks no-store or private",
    regex: /\b(setCacheControl|cacheHeaders|Cache-Control)\b[^\r\n;,)]*(account|profile|session|private|auth)[^\r\n;,)]*(?![^\r\n]*(no-store|private|no-cache))/i,
    description: "Use Cache-Control directives such as no-store or private on sensitive or user-specific responses.",
  },
  {
    id: "MANINY-CCH-002",
    severity: "low",
    category: "code-pattern",
    title: "Public caching explicitly enabled on potentially sensitive response handler",
    regex: /\b(Cache-Control|cacheControl)\b[^\r\n;,)]*[:=]\s*['"`]?public\b/i,
    description: "Avoid marking authenticated or sensitive endpoints as publicly cacheable.",
  },
];

export async function runCacheControlAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, CACHE_CONTROL_RULES);
}
