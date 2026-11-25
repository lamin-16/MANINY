import { EvidenceRecord, Finding, ManinyPolicy } from "../core/types.js";
import { isHostInAllowedScope } from "../core/policy-guard.js";

export interface AdversarialSimOptions {
  requestTimeoutMs?: number;
}

const SAFE_TEST_PROBES: Array<{
  name: string;
  queryParam: string;
  queryValue: string;
  requireAngleBracketCheck?: boolean;
}> = [
  {
    name: "benign-reflection-probe",
    queryParam: "maniny_probe",
    queryValue: "maniny_safe_check_123",
  },
  {
    name: "benign-tag-encoding-probe",
    queryParam: "maniny_q",
    queryValue: "maniny_tag_<test>",
    requireAngleBracketCheck: true,
  },
];

function buildProbeUrl(baseUrl: string, param: string, value: string): string | null {
  try {
    const parsed = new URL(baseUrl);
    parsed.searchParams.set(param, value);
    return parsed.toString();
  } catch {
    return null;
  }
}

async function runSingleSafeProbe(
  targetUrl: string,
  probe: {
    name: string;
    queryParam: string;
    queryValue: string;
    requireAngleBracketCheck?: boolean;
  },
  timeoutMs: number
): Promise<Finding | null> {
  const probeUrl = buildProbeUrl(targetUrl, probe.queryParam, probe.queryValue);
  if (!probeUrl) {
    return null;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(probeUrl, {
      method: "GET",
      signal: controller.signal,
      redirect: "manual",
    });

    const bodyText = await response.text();
    const rawReflected = bodyText.includes(probe.queryValue);
    const hasEncodedBrackets =
      bodyText.includes("&lt;test&gt;") || bodyText.includes("&#60;test&#62;");

    const confirmed = probe.requireAngleBracketCheck
      ? rawReflected && !hasEncodedBrackets
      : rawReflected;

    const evidence: EvidenceRecord = {
      stage: "verify",
      probeType: "safe-http-check",
      target: probeUrl,
      confirmed,
      message: confirmed
        ? `Probe [${probe.name}] observed unencoded marker reflection in HTTP ${response.status} response.`
        : hasEncodedBrackets
          ? `Probe [${probe.name}] saw HTML-encoded output in HTTP ${response.status} response (not flagged as raw reflection).`
          : `Probe [${probe.name}] completed with HTTP ${response.status}; no raw marker reflection observed.`,
      timestamp: new Date().toISOString(),
    };

    if (!confirmed) {
      return null;
    }

    return {
      id: `ADV-${Buffer.from(probeUrl).toString("base64url").slice(0, 10)}`,
      ruleId: "MANINY-ADV-REFLECT-001",
      title: "Unencoded query parameter reflection observed during safe probe",
      category: "code-pattern",
      severity: "medium",
      targetUrl: probeUrl,
      description:
        "Safe non-destructive input reflection check observed raw probe value in response body; review output encoding and input handling.",
      status: "verified_exploitable",
      evidence: [evidence],
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export async function runAdversarialSimulation(
  targetUrls: string[],
  policy: ManinyPolicy,
  options: AdversarialSimOptions = {}
): Promise<Finding[]> {
  if (!policy.allowSafeOffensiveProbes || targetUrls.length === 0) {
    return [];
  }

  const timeoutMs = options.requestTimeoutMs ?? 5000;
  const findings: Finding[] = [];

  for (const url of targetUrls) {
    if (!isHostInAllowedScope(url, policy.allowedTargetHosts)) {
      continue;
    }

    for (const probe of SAFE_TEST_PROBES) {
      const finding = await runSingleSafeProbe(url, probe, timeoutMs);
      if (finding) {
        findings.push(finding);
      }
    }
  }

  return findings;
}
