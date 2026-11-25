import { Finding, PipelineReport, Severity } from "./types.js";

function mapSarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium") {
    return "warning";
  }
  return "note";
}

export function formatSarifReport(report: PipelineReport): string {
  const results = report.findings.map((finding: Finding) => ({
    ruleId: finding.ruleId,
    level: mapSarifLevel(finding.severity),
    message: {
      text: `[${finding.status}] ${finding.title}: ${finding.description}`,
    },
    locations: finding.filePath
      ? [
          {
            physicalLocation: {
              artifactLocation: {
                uri: finding.filePath.replace(/\\/g, "/"),
              },
              region: {
                startLine: finding.line ?? 1,
              },
            },
          },
        ]
      : [],
  }));

  const sarif = {
    $schema: "[https://json.schemastore.org/sarif-2.1.0.json](https://json.schemastore.org/sarif-2.1.0.json)",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: report.tool,
            version: report.version,
            rules: Array.from(
              new Map(
                report.findings.map((f) => [
                  f.ruleId,
                  {
                    id: f.ruleId,
                    name: f.title,
                    shortDescription: { text: f.title },
                    fullDescription: { text: f.description },
                  },
                ])
              ).values()
            ),
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
