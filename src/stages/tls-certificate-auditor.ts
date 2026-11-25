import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const TLS_CERTIFICATE_RULES: LineAuditRule[] = [
  {
    id: "MANINY-TLS-001",
    severity: "high",
    category: "code-pattern",
    title: "TLS certificate or hostname verification explicitly disabled",
    regex: /\b(rejectUnauthorized|insecureSkipVerify|allowInvalidCert)\b[^\r\n;,)]*[:=]\s*false|\b(insecureSkipVerify|allowInvalidCert)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep TLS certificate and hostname verification enabled for all encrypted network connections.",
  },
  {
    id: "MANINY-TLS-002",
    severity: "medium",
    category: "code-pattern",
    title: "Deprecated TLS or SSL protocol version configured",
    regex: /\b(minVersion|secureProtocol|tlsVersion)\b[^\r\n;,)]*[:=]\s*["']?(TLSv1(\.[01])?|SSLv[23])["']?/i,
    description: "Use modern TLS versions such as TLSv1.2 or TLSv1.3 instead of legacy TLS or SSL protocols.",
  },
];

export async function runTlsCertificateAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, TLS_CERTIFICATE_RULES);
}
