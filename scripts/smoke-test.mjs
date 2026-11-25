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

// 1. Verify rules registry
const rulesOut = runCli(["--list-rules"]);
if (!rulesOut.total || rulesOut.total < 10) {
  throw new Error(`Expected at least 10 rules, got ${rulesOut.total}`);
}

// 2. Create isolated temporary workspace and run pipeline + fix + integrity
const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "maniny-smoke-"));
try {
  await fs.writeFile(
    path.join(tmpDir, "package.json"),
    JSON.stringify({ name: "smoke-target", dependencies: { badpkg: "*" } }, null, 2),
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
    "--integrity",
    "--json-compact",
  ]);

  if (!compactReport.integritySha256 || compactReport.integritySha256.length !== 64) {
    throw new Error("Missing or invalid SHA-256 integrity digest");
  }
  if (compactReport.summary.total < 3) {
    throw new Error(`Expected >= 3 findings in smoke workspace, got ${compactReport.summary.total}`);
  }

  const fixedCode = await fs.readFile(path.join(tmpDir, "app.ts"), "utf8");
  if (fixedCode.includes("eval(") || fixedCode.includes("rejectUnauthorized: false")) {
    throw new Error("Auto-fixable patterns were not remediated in smoke workspace");
  }

  console.log(
    JSON.stringify(
      {
        smoke: "PASSED",
        rulesCount: rulesOut.total,
        findingsTotal: compactReport.summary.total,
        verifiedFixed: compactReport.summary.verifiedFixed,
        auditId: compactReport.auditId,
      },
      null,
      2
    )
  );
} finally {
  await fs.rm(tmpDir, { recursive: true, force: true });
}
