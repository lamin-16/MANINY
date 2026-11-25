import { Finding } from "./types.js";

export interface CorrelatedAttackChain {
  chainId: string;
  title: string;
  severityScore: number;
  findingIds: string[];
  stagesInvolved: string[];
}

function collectStages(matched: Finding[]): string[] {
  const stages = new Set<string>(["detect"]);
  for (const item of matched) {
    for (const ev of item.evidence) {
      stages.add(String(ev.stage));
    }
  }
  return [...stages];
}

export function correlateHybridChains(findings: Finding[]): CorrelatedAttackChain[] {
  const chains: CorrelatedAttackChain[] = [];

  const ssrfOrRedirect = findings.filter((f) =>
    /^(MANINY-SRF|MANINY-RDR|MANINY-NET)/.test(f.ruleId)
  );
  const authOrHeaders = findings.filter((f) =>
    /^(MANINY-HDR|MANINY-CSP|MANINY-HTTP)/.test(f.ruleId)
  );
  const codeOrProto = findings.filter((f) =>
    /^(MANINY-CODE|MANINY-OBJ|MANINY-PRP|MANINY-RGX|MANINY-TMP)/.test(f.ruleId)
  );
  const exposureOrAuth = findings.filter((f) =>
    /^(MANINY-SEC|MANINY-AUTH|MANINY-INJ|MANINY-SQL|MANINY-XSS)/.test(f.ruleId)
  );

  if (ssrfOrRedirect.length > 0 && authOrHeaders.length > 0) {
    const matched = [...ssrfOrRedirect.slice(0, 3), ...authOrHeaders.slice(0, 3)];
    const hasVerified = matched.some((m) => m.status === "verified_exploitable");
    chains.push({
      chainId: "CHAIN-HYBRID-BOUNDARY-01",
      title: "Outbound/Redirect vector paired with permissive transport or header posture",
      severityScore: hasVerified ? 9.1 : 7.4,
      findingIds: matched.map((m) => m.id),
      stagesInvolved: collectStages(matched),
    });
  }

  if (codeOrProto.length > 0) {
    const matched = codeOrProto.slice(0, 4);
    const hasVerified = matched.some((m) => m.status === "verified_exploitable");
    chains.push({
      chainId: "CHAIN-HYBRID-EXEC-STATE-02",
      title: "Execution or object-state mutation vector requiring strict input/key containment",
      severityScore: hasVerified ? 8.8 : 6.9,
      findingIds: matched.map((m) => m.id),
      stagesInvolved: collectStages(matched),
    });
  }

  if (exposureOrAuth.length > 0) {
    const matched = exposureOrAuth.slice(0, 4);
    const hasVerified = matched.some((m) => m.status === "verified_exploitable");
    chains.push({
      chainId: "CHAIN-HYBRID-EXPOSURE-AUTH-03",
      title: "Sensitive exposure, authentication, or injection vector requiring hard boundary controls",
      severityScore: hasVerified ? 9.4 : 7.8,
      findingIds: matched.map((m) => m.id),
      stagesInvolved: collectStages(matched),
    });
  }

  return chains.sort((a, b) => b.severityScore - a.severityScore);
}
