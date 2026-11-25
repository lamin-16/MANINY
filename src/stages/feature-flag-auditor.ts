import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const FEATURE_FLAG_RULES: LineAuditRule[] = [
  {
    id: "MANINY-FLG-001",
    severity: "medium",
    category: "code-pattern",
    title: "Feature flag evaluation or override uses untrusted input without visible validation or authorization",
    regex: /\b(evaluateFeatureFlag|isFeatureEnabled|overrideFeatureFlag)\s*\([^\r\n)]*(\b(req\.body|flagName|overrideFlag)\b|\$\{)[^\r\n)]*(?![^\r\n]*(validateFlag|authorizeFlagOverride|allowedFlags|sanitize))/i,
    description: "Validate feature flag names and enforce authorization checks before allowing runtime flag overrides.",
  },
  {
    id: "MANINY-FLG-002",
    severity: "low",
    category: "code-pattern",
    title: "Security feature flag or safety guard explicitly forced off or bypassed",
    regex: /\b(forceDisableSecurityFlags|allowUnsafeFlagOverride)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Prevent runtime flag overrides from disabling critical security controls.",
  },
];

export async function runFeatureFlagAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, FEATURE_FLAG_RULES);
}
