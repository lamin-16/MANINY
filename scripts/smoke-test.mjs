import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

const repoRoot = process.cwd();
const cliPath = path.join(repoRoot, "dist", "cli.js");

function runCli(args) {
  const out = execFileSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return JSON.parse(out);
}

const statsOut = runCli(["--stats", "--workspace", repoRoot]);
if (!statsOut.filesCount || statsOut.filesCount < 5) {
  throw new Error("Expected valid workspace stats");
}

const rulesOut = runCli(["--list-rules"]);
if (!rulesOut.total || rulesOut.total < 10) {
  throw new Error(`Expected at least 10 rules, got ${rulesOut.total}`);
}

const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "maniny-smoke-"));
try {
  await fs.writeFile(
    path.join(tmpDir, "package.json"),
    JSON.stringify({ name: "smoke-target", dependencies: { badpkg: "*" } }, null, 2),
    "utf8"
  );
  await fs.writeFile(
    path.join(tmpDir, ".env.example"),
    "HOST=0.0.0.0\n",
    "utf8"
  );
  await fs.writeFile(
    path.join(tmpDir, "app.ts"),
    [
      'const x = eval("1+1");',
      'const agentOpts = { rejectUnauthorized: false };',
      "export { x, agentOpts };",
    ].join("\n"),
    "utf8"
  );

  const compactReport = runCli([
    "--mode",
    "pipeline",
    "--workspace",
    tmpDir,
    "--allow-fix",
    "--compliance",
    "--integrity",
    "--json-compact",
  ]);

  if (!compactReport.integritySha256 || compactReport.integritySha256.length !== 64) {
    throw new Error("Missing or invalid SHA-256 integrity digest");
  }
  if (!compactReport.compliance || !compactReport.compliance.posture) {
    throw new Error("Missing compliance posture summary");
  }
  if (!compactReport.items.some((i) => i.ruleId === "MANINY-ENV-002")) {
    throw new Error("Expected MANINY-ENV-002 finding for 0.0.0.0");
  }
  if (!compactReport.items.some((i) => i.ruleId === "MANINY-SUP-001")) {
    throw new Error("Expected MANINY-SUP-001 finding for missing lockfile");
  }

  console.log(
    JSON.stringify(
      {
        smoke: "PASSED",
        workspaceFiles: statsOut.filesCount,
        workspaceLines: statsOut.totalLines,
        findingsTotal: compactReport.summary.total,
        compliancePosture: compactReport.compliance.posture,
        auditId: compactReport.auditId,
      },
      null,
      2
    )
  );
} finally {
  await fs.rm(tmpDir, { recursive: true, force: true });
}
