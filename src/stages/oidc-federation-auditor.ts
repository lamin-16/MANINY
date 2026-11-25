import { Finding, ManinyPolicy } from "../core/types.js";
import { LineAuditRule, scanWorkspaceRules } from "./stage-utils.js";

const OIDC_FEDERATION_RULES: LineAuditRule[] = [
  {
    id: "MANINY-OID-001",
    severity: "high",
    category: "code-pattern",
    title: "OIDC or federation token check lacks visible nonce, audience, or trusted issuer validation",
    regex: /\b(verifyIdTokenClaims|exchangeFederationToken|validateJwksUri)\s*\([^\r\n)]*(\b(idToken|assertion|issuer|req\.body)\b|\$\{)[^\r\n)]*(?![^\r\n]*(expectedAudience|trustedIssuer|validateNonce|enforceHttpsJwks))/i,
    description: "Validate token audience, issuer, and nonce claims, and require HTTPS for remote JWKS endpoints.",
  },
  {
    id: "MANINY-OID-002",
    severity: "medium",
    category: "code-pattern",
    title: "OIDC nonce or audience validation explicitly disabled",
    regex: /\b(skipNonceValidation|disableAudienceCheck)\b[^\r\n;,)]*[:=]\s*true/i,
    description: "Keep OIDC nonce and audience claim checks enabled to prevent token replay and confusion.",
  },
];

export async function runOidcFederationAuditor(policy: ManinyPolicy): Promise<Finding[]> {
  return scanWorkspaceRules(policy, OIDC_FEDERATION_RULES);
}
