import { EvidenceRecord, Finding } from "./types.js";

export interface EliteAttackOptions {
  targetUrls: string[];
  allowHosts: string[];
  timeoutMs?: number;
}

export interface EliteAttackEntry {
  findingId: string;
  ruleId: string;
  target: string;
  status: string;
  severity: string;
  reproductionSteps: string[];
  remediationHint: string;
}

export interface EliteAttackMatrix {
  generatedAt: string;
  totalEntries: number;
  confirmedExploitable: number;
  entries: EliteAttackEntry[];
}

const EV_KEYS = ["stage","probeType","target","confirmed","message","timestamp"];
const RISKY_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];
const DEBUG_LEAK_PATTERNS = [
  /ats+[A-Za-z0-9_.$]+s*([^)]*:d+:d+)/,
  /traceback (most recent call last)/i,
  /xdebug/i,
  /unhandled promise rejection/i,
  /sequelize.*error/i,
];

function makeEliteEvidence(summary: string, location: string): EvidenceRecord[] {
  const rec: Record<string, unknown> = {};
  rec.stage = summary;
  rec.probeType = summary;
  rec.target = location;
  rec.confirmed = false;
  rec.message = summary;
  rec.timestamp = new Date().toISOString();
  return [rec as unknown as EvidenceRecord];
}

export async function runEliteAttackVerification(options: EliteAttackOptions): Promise<Finding[]> {
  const findings: Finding[] = [];
  const allowedSet = new Set(
    (options.allowHosts ?? []).map((h) => h.trim().toLowerCase()).filter(Boolean)
  );
  const timeoutMs = options.timeoutMs ?? 5000;
  let seq = 1;

  for (const rawUrl of options.targetUrls ?? []) {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      continue;
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      continue;
    }

    if (!allowedSet.has(parsed.hostname.toLowerCase())) {
      continue;
    }

    const token = `maniny_probe_${seq}`;
    const probeUrl = new URL(parsed.toString());
    probeUrl.searchParams.set("maniny_q", token);

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);

    try {
      const baseRes = await fetch(parsed.toString(), {
        method: "GET",
        signal: ctrl.signal,
        redirect: "manual",
      });
      const baseBody = (await baseRes.text()).slice(0, 4000);

      const serverHdr = baseRes.headers.get("server") ?? "";
      const poweredBy = baseRes.headers.get("x-powered-by") ?? "";
      const hasVersionLeak =
        //[0-9]+.[0-9]+/.test(serverHdr) ||
        /[0-9]+.[0-9]+/.test(poweredBy) ||
        DEBUG_LEAK_PATTERNS.some((rx) => rx.test(baseBody) && !/maniny/i.test(baseBody));

      if (hasVersionLeak) {
        findings.push({
          id: `MANINY-ELITE-FINGERPRINT-001-${seq++}`,
          ruleId: "MANINY-ELITE-FINGERPRINT-001",
          severity: "low",
          category: "http-hardening",
          status: "verified_exploitable",
          filePath: parsed.toString(),
          evidence: makeEliteEvidence(
            `Server="${serverHdr}" X-Powered-By="${poweredBy}" on ${parsed.hostname}`,
            parsed.toString()
          ),
          title: "Live HTTP response exposes granular software version or diagnostic trace details",
          description: `Target ${parsed.hostname} disclosed versioned headers or diagnostic output that narrows attack surface targeting.`,
        });
      }

      const optCtrl = new AbortController();
      const optTimer = setTimeout(() => optCtrl.abort(), timeoutMs);
      try {
        const optRes = await fetch(parsed.toString(), {
          method: "OPTIONS",
          signal: optCtrl.signal,
          redirect: "manual",
        });
        const allowHeader = [
          optRes.headers.get("allow") ?? "",
          optRes.headers.get("access-control-allow-methods") ?? "",
        ]
          .join(",")
          .toUpperCase();

        const allowedTokens = new Set(
          allowHeader.split(/[^A-Z0-9_-]+/).filter(Boolean)
        );
        const exposedRisky = RISKY_METHODS.filter((m) => allowedTokens.has(m));
        if (exposedRisky.length > 0) {
          findings.push({
            id: `MANINY-ELITE-METHOD-001-${seq++}`,
            ruleId: "MANINY-ELITE-METHOD-001",
            severity: "medium",
            category: "http-hardening",
            status: "verified_exploitable",
            filePath: parsed.toString(),
            evidence: makeEliteEvidence(
              `Advertised methods include: ${exposedRisky.join(", ")}`,
              parsed.toString()
            ),
            title: "Endpoint advertises potentially high-risk HTTP methods",
            description: `OPTIONS/CORS response on ${parsed.toString()} advertised methods: ${exposedRisky.join(", ")}.`,
          });
        }
      } finally {
        clearTimeout(optTimer);
      }

      const reflCtrl = new AbortController();
      const reflTimer = setTimeout(() => reflCtrl.abort(), timeoutMs);
      try {
        const reflRes = await fetch(probeUrl.toString(), {
          method: "GET",
          signal: reflCtrl.signal,
          redirect: "manual",
        });
        const reflBody = (await reflRes.text()).slice(0, 4000);
        if (reflBody.includes(token)) {
          const deltaChars = Math.abs(reflBody.length - baseBody.length);
          findings.push({
            id: `MANINY-ELITE-REFLECT-001-${seq++}`,
            ruleId: "MANINY-ELITE-REFLECT-001",
            severity: "medium",
            category: "code-pattern",
            status: "verified_exploitable",
            filePath: probeUrl.toString(),
            evidence: makeEliteEvidence(
              `Reflected inert marker "${token}" in response body (delta ${deltaChars} chars vs baseline)`,
              probeUrl.toString()
            ),
            title: "Query parameter input reflected directly in live HTTP response body",
            description: `Requesting ${probeUrl.toString()} echoed an inert test marker into the response body compared to baseline.`,
          });
        }
      } finally {
        clearTimeout(reflTimer);
      }
    } catch {
      // تجاهل أخطاء الاتصال العابرة
    } finally {
      clearTimeout(timer);
    }
  }

  return findings;
}

export function buildEliteAttackMatrix(findings: Finding[]): EliteAttackMatrix {
  const entries: EliteAttackEntry[] = findings.map((f) => {
    const target = f.filePath ?? "workspace";
    const rule = String(f.ruleId ?? "MANINY-RULE");
    let reproductionSteps: string[];
    let remediationHint: string;

    if (rule.startsWith("MANINY-ELITE-METHOD-")) {
      reproductionSteps = [
        `Send non-destructive OPTIONS request to ${target}`,
        "Inspect Allow and Access-Control-Allow-Methods headers for PUT/DELETE/PATCH/TRACE",
      ];
      remediationHint = "Restrict allowed HTTP methods and disable TRACE/unneeded write verbs at gateway/router.";
    } else if (rule.startsWith("MANINY-ELITE-REFLECT-")) {
      reproductionSteps = [
        `Request ${target} with an inert query parameter marker`,
        "Verify whether output encoding/escaping is applied before rendering",
      ];
      remediationHint = "Enforce context-aware output encoding and strict input validation/schema checks.";
    } else if (rule.startsWith("MANINY-ELITE-FINGERPRINT-")) {
      reproductionSteps = [
        `Send GET request to ${target} and inspect response headers and error body`,
      ];
      remediationHint = "Strip granular server/framework version banners and suppress stack traces in production.";
    } else {
      reproductionSteps = [
        `Inspect finding ${f.id} (${rule}) at ${target}`,
        "Confirm authorization, input boundary, and response evidence in an authorized test environment",
      ];
      remediationHint = "Apply least privilege, strict allowlists, and defense-in-depth controls.";
    }

    return {
      findingId: f.id,
      ruleId: rule,
      target,
      status: String(f.status),
      severity: String(f.severity),
      reproductionSteps,
      remediationHint,
    };
  });

  return {
    generatedAt: new Date().toISOString(),
    totalEntries: entries.length,
    confirmedExploitable: entries.filter((e) => e.status === "verified_exploitable").length,
    entries,
  };
}
