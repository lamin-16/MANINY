# MANINY

Multi-stage detection, safe adversarial verification, controlled remediation, and defensive review engine in TypeScript.

## Pipeline Stages

1. **Detector (`src/stages/detector.ts`):** Scans workspace files and queues authorized URLs while skipping ignored directories and MANINY report artifacts.
2. **Safe Verifier (`src/stages/verifier.ts`):** Statically verifies code patterns and audits baseline HTTP security headers.
3. **Exposure Checker (`src/stages/exposure-checker.ts`):** Checks `Strict-Transport-Security` (`HSTS`) on authorized targets.
4. **Adversarial Simulation (`src/stages/adversarial-sim.ts`):** Runs benign reflection probes on authorized hosts when `--allow-probes` is enabled.
5. **Fixer (`src/stages/fixer.ts`):** Enforces workspace containment and policy guards, stores backup content and `unifiedDiff`, and applies line fixes.
6. **Defender Reviewer (`src/stages/reviewer.ts`):** Re-checks patched files and automatically restores the backup (`rolled_back`) if the fix is incomplete or invalid.

## Safety & Scope Boundaries

- HTTP probes and simulations run only when `--allow-probes` is passed and the host matches `--allow-host`.
- Automated edits stay strictly inside `workspaceRoot` and skip protected paths.
- Failed or incomplete fixes are automatically rolled back during review.

## Build & Run

Run `npm install` and `npm run build`, then execute `node ./dist/cli.js --mode pipeline --workspace ./sample-target --allow-fix --format both --report ./maniny-report`.
