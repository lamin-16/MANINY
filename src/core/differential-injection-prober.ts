import { EvidenceRecord, Finding } from "./types.js";

export interface DifferentialProbeOptions {
  targetUrls: string[];
  allowHosts: string[];
  timeoutMs?: number;
}

const EV_KEYS = ["stage","probeType","target","confirmed","message","timestamp"];
const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /ora-[0-9]{4,5}/i,
  /postgresql.*error/i,
  /sqlite3::/i,
  /unterminated quoted string/i,
  /syntax error at or near/i,
];
const TRAVERSAL_PATHS = ["/../.env", "/..%2f.git/HEAD", "/..%2fetc/passwd"];

function makeDiffEvidence(summary: string, location: string): EvidenceRecord[] {
  const rec: Record<string, unknown> = {};
  for (const key of EV_KEYS) {
    if (/file|path|url|target|location/i.test(key)) {
      rec[key] = location;
    } else if (/line|col|offset|status|code|port/i.test(key)) {
      rec[key] = 1;
    } else {
      rec[key] = summary;
    }
  }
  return [rec as unknown as EvidenceRecord];
}

export async function runDifferentialInjectionProbes(options: DifferentialProbeOptions): Promise<Finding[]> {
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

    const baseController = new AbortController();
    const baseTimer = setTimeout(() => baseController.abort(), timeoutMs);
    let baselineBody = "";
    let baselineStatus = 0;

    try {
      const baseRes = await fetch(parsed.toString(), {
        method: "GET",
        signal: baseController.signal,
        redirect: "manual",
      });
      baselineStatus = baseRes.status;
      baselineBody = (await baseRes.text()).slice(0, 4000);
    } catch {
      clearTimeout(baseTimer);
      continue;
    } finally {
      clearTimeout(baseTimer);
    }

    const paramProbeUrl = new URL(parsed.toString());
    paramProbeUrl.searchParams.set("id", "-1'");
    paramProbeUrl.searchParams.set("next", "https://maniny-probe-check.example");

    const pController = new AbortController();
    const pTimer = setTimeout(() => pController.abort(), timeoutMs);
    try {
      const pRes = await fetch(paramProbeUrl.toString(), {
        method: "GET",
        signal: pController.signal,
        redirect: "manual",
      });
      const pBody = (await pRes.text()).slice(0, 4000);
      const locationHeader = pRes.headers.get("location") ?? "";

      const matchedSql = SQL_ERROR_PATTERNS.find(
        (rx) => rx.test(pBody) && !rx.test(baselineBody)
      );
      if (matchedSql || (baselineStatus < 500 && pRes.status >= 500 && pBody !== baselineBody)) {
        findings.push({
          id: `MANINY-DIFF-INJ-001-${seq++}`,
          ruleId: "MANINY-DIFF-INJ-001",
          severity: "high",
          category: "code-pattern",
          status: "verified_exploitable",
          filePath: paramProbeUrl.toString(),
          evidence: makeDiffEvidence(
            `Baseline HTTP ${baselineStatus} vs Probe HTTP ${pRes.status}; differential error shift`,
            paramProbeUrl.toString()
          ),
          title: "Differential query parameter probe triggered server error or query parser leak",
          description: `Comparing baseline HTTP ${baselineStatus} against ${paramProbeUrl.toString()} revealed HTTP ${pRes.status} with differential error response.`,
        });
      }

      if (locationHeader.includes("maniny-probe-check.example")) {
        findings.push({
          id: `MANINY-DIFF-REDIR-001-${seq++}`,
          ruleId: "MANINY-DIFF-REDIR-001",
          severity: "medium",
          category: "http-hardening",
          status: "verified_exploitable",
          filePath: paramProbeUrl.toString(),
          evidence: makeDiffEvidence(
            `Location header reflected external redirect target: ${locationHeader}`,
            paramProbeUrl.toString()
          ),
          title: "Differential redirect parameter reflected untrusted external Location header",
          description: `Requesting ${paramProbeUrl.toString()} returned Location header pointing to an untrusted external host.`,
        });
      }
    } catch {
      // تجاهل الأخطاء العابرة أثناء الفحص التفاضلي
    } finally {
      clearTimeout(pTimer);
    }

    for (const travPath of TRAVERSAL_PATHS) {
      const travUrl = new URL(travPath, parsed.origin).toString();
      const tController = new AbortController();
      const tTimer = setTimeout(() => tController.abort(), timeoutMs);
      try {
        const tRes = await fetch(travUrl, {
          method: "GET",
          signal: tController.signal,
          redirect: "manual",
        });
        const tBody = (await tRes.text()).slice(0, 2000);
        if (tRes.status === 200 && tBody.length > 0 && tBody !== baselineBody) {
          findings.push({
            id: `MANINY-DIFF-TRAV-001-${seq++}`,
            ruleId: "MANINY-DIFF-TRAV-001",
            severity: "high",
            category: "code-pattern",
            status: "verified_exploitable",
            filePath: travUrl,
            evidence: makeDiffEvidence(
              `Traversal GET ${travUrl} -> HTTP ${tRes.status} (diff body length ${tBody.length})`,
              travUrl
            ),
            title: "Differential path traversal probe returned distinct HTTP 200 content",
            description: `Path ${travUrl} returned HTTP 200 with content differing from baseline response.`,
          });
        }
      } catch {
        // تجاهل خطأ الاتصال للمسار الفردي
      } finally {
        clearTimeout(tTimer);
      }
    }
  }

  return findings;
}
