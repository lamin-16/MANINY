import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const DEVICE_TRUST_RULES: LineAuditRule[] = [
  {
    id: "MANINY-DVT-001",
    severity: "medium",
    category: "code-pattern",
    title: "Device trust evaluation lacks visible attestation, OS posture, certificate binding, or audit check",
    regex: /\b(evaluateDeviceTrust|attestDevicePosture|bindDeviceCertificate)\s*\([^\r\n)]*(\b(deviceId|posture|certificate|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(verifyDeviceAttestation|checkOsCompliance|auditDeviceTrustDecision|requireDeviceBinding))/i,
    description: "Verify device attestation and certificate binding, check OS posture compliance, and log trust decisions.",
  },
  {
    id: "MANINY-DVT-002",
    severity: "low",
    category: "code-pattern",
    title: "Device trust or posture check explicitly bypassed",
    regex: /\b(skipDeviceTrust|ignoreDevicePosture)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep device posture and attestation checks active for protected resources.",
  },
];

export async function runDeviceTrustAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, DEVICE_TRUST_RULES);
}
