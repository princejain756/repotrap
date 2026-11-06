#!/usr/bin/env node
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import {
  RULE_META,
  scanTextForPromptTraps,
  auditRepoTraps,
  generateGuardHook,
  getDemoResult
} from "../src/analyzer.mjs";

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const YELLOW = "\x1b[33m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";
const MAGENTA = "\x1b[35m";

function printHelp() {
  console.log(`
${BOLD}repotrap${RESET} v0.1.0 - Prompt-Injection, Unicode Steganography & Repo Trap Scanner

Usage:
  npx repotrap [options]

Options:
  --workspace <path>       Workspace directory to scan for repo-open traps (default: cwd)
  --file <path>            Scan a single Markdown, SKILL.md, or issue file
  --gh-issue <repo#num>    Fetch and scan a GitHub issue/PR via 'gh issue view' before agent triage
  --emit-hook              Output deterministic PostToolUse guardrail hook + settings.json
  --json                   Output structured JSON report
  --fail-on <severity>     Exit 1 if findings >= severity (CRITICAL, HIGH, MEDIUM, LOW)
  --demo                   Render benchmarked 534-skill + 153-session corpus audit output
  -h, --help               Show help
  -v, --version            Show version
`);
}

function parseArgs(argv) {
  const opts = {
    workspaceDir: null,
    file: null,
    ghIssue: null,
    emitHook: false,
    json: false,
    failOn: null,
    demo: false,
    help: false,
    version: false
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a === "--demo") opts.demo = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--emit-hook") opts.emitHook = true;
    else if (a === "--workspace") opts.workspaceDir = argv[++i];
    else if (a === "--file") opts.file = argv[++i];
    else if (a === "--gh-issue") opts.ghIssue = argv[++i];
    else if (a === "--fail-on") opts.failOn = String(argv[++i] || "").toUpperCase();
  }
  return opts;
}

function severityColor(sev) {
  if (sev === "CRITICAL") return `${BOLD}${RED}`;
  if (sev === "HIGH") return RED;
  if (sev === "MEDIUM") return YELLOW;
  if (sev === "LOW") return CYAN;
  return DIM;
}

function renderReport(res) {
  const gradeColor =
    res.grade === "A" ? GREEN : res.grade === "B" ? CYAN : res.grade === "C" ? YELLOW : RED;

  console.log(`\n${BOLD}${CYAN}repotrap v0.1.0${RESET} ${DIM}| Prompt-Injection, Invisible Unicode & Repo Trap Audit${RESET}`);
  console.log(`${DIM}${"=".repeat(76)}${RESET}`);
  console.log(
    `Skills Scanned: ${BOLD}${res.skillFilesScanned}${RESET}   ` +
      `Repos Checked: ${BOLD}${res.reposChecked}${RESET}   ` +
      `Sessions Replayed: ${BOLD}${res.sessionsScanned}${RESET}   ` +
      `Safety Score: ${BOLD}${gradeColor}${res.score}/100 (Grade ${res.grade})${RESET}`
  );
  console.log(
    `Severities:     ` +
      `${BOLD}${RED}CRITICAL: ${res.severityCounts.CRITICAL}${RESET}  ` +
      `${RED}HIGH: ${res.severityCounts.HIGH}${RESET}  ` +
      `${YELLOW}MEDIUM: ${res.severityCounts.MEDIUM}${RESET}  ` +
      `${CYAN}LOW: ${res.severityCounts.LOW}${RESET}  ` +
      `${DIM}INFO: ${res.severityCounts.INFO}${RESET}`
  );
  console.log(`${DIM}${"-".repeat(76)}${RESET}`);

  const m = res.metrics;
  console.log(`${BOLD}${MAGENTA}[Plane 1] Untrusted Repo, Skill & Lifecycle Trap Surface${RESET}`);
  console.log(
    `  * Skill Remote Shell Pipes (curl | sh): ${
      res.ruleCounts.RTR005 ? `${RED}${res.ruleCounts.RTR005} file(s) flagged${RESET}` : `${GREEN}0 remote shell pipes${RESET}`
    }`
  );
  console.log(
    `  * Standalone Zero-Width in Skills:      ${
      m.skillZeroWidthCount > 0 ? `${YELLOW}${m.skillZeroWidthCount} U+200B char(s)${RESET}` : `${GREEN}0 standalone zero-width chars${RESET}`
    }`
  );
  console.log(
    `  * Emoji ZWJ Sequences Separated:        ${CYAN}${m.emojiZwjFilteredCount} composite emoji U+200D filtered (RTR014 guard)${RESET}`
  );
  console.log(
    `  * Benign package.json Build Scripts:    ${CYAN}${m.benignLifecycleCount} local build/prepare script(s) separated (RTR013 guard)${RESET}`
  );

  console.log(`\n${BOLD}${MAGENTA}[Plane 2] Transcript tool_result & Issue Poisoning Replay${RESET}`);
  console.log(
    `  * Prompt-Override / Delimiter Spoofs:   ${
      (res.ruleCounts.RTR008 || 0) + (res.ruleCounts.RTR009 || 0) > 0
        ? `${RED}${(res.ruleCounts.RTR008 || 0) + (res.ruleCounts.RTR009 || 0)} untrusted tool_result payload(s) flagged${RESET}`
        : `${GREEN}0 untrusted overrides${RESET}`
    }`
  );
  console.log(
    `  * Harness <system-reminder> Filtered:   ${CYAN}${m.harnessSystemReminderCount} native attachment rows excluded (RTR012 guard)${RESET}`
  );
  console.log(
    `  * Zero-Width Ingested in tool_result:   ${
      m.totalTranscriptZeroWidth > 0
        ? `${YELLOW}${m.totalTranscriptZeroWidth} char(s) across ${m.transcriptsWithZeroWidth} session(s) (U+200B / U+200E)${RESET}`
        : `${GREEN}0 zero-width chars${RESET}`
    }`
  );

  console.log(`\n${BOLD}Rule Breakdown:${RESET}`);
  const sortedRules = Object.entries(res.ruleCounts).sort((a, b) => {
    const order = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
    const ma = RULE_META[a[0]] || { severity: "INFO" };
    const mb = RULE_META[b[0]] || { severity: "INFO" };
    return (order[mb.severity] || 0) - (order[ma.severity] || 0) || b[1] - a[1];
  });

  for (const [ruleId, count] of sortedRules) {
    const meta = RULE_META[ruleId];
    if (!meta) continue;
    const col = severityColor(meta.severity);
    console.log(
      `  ${col}[${meta.severity.padEnd(8)}]${RESET} ${BOLD}${ruleId}${RESET} (${String(count).padStart(2)}x) ${meta.title}`
    );
  }

  const notable = [
    ...res.findings.filter((f) => f.severity === "CRITICAL"),
    ...res.findings.filter((f) => f.severity === "HIGH"),
    ...res.findings.filter((f) => f.severity === "MEDIUM"),
    ...res.findings.filter((f) => f.severity === "LOW")
  ].slice(0, 5);

  if (notable.length > 0) {
    console.log(`\n${BOLD}Top Evidence Samples:${RESET}`);
    for (const f of notable) {
      const col = severityColor(f.severity);
      console.log(`  ${col}* ${f.ruleId}${RESET}: ${f.detail}`);
    }
  }

  console.log(`\n${DIM}Run 'npx repotrap --gh-issue owner/repo#123' to pre-scan an untrusted GitHub issue before agent triage.${RESET}\n`);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    process.exit(0);
  }
  if (opts.version) {
    console.log("0.1.0");
    process.exit(0);
  }
  if (opts.emitHook) {
    const { hookScript, settingsSnippet } = generateGuardHook();
    if (opts.json) {
      console.log(JSON.stringify({ hookScript, settingsSnippet }, null, 2));
    } else {
      console.log(`${BOLD}${CYAN}# 1. Save to ~/.claude/hooks/repotrap-guard-hook.mjs:${RESET}\n`);
      console.log(hookScript);
      console.log(`${BOLD}${CYAN}# 2. Merge into ~/.claude/settings.json:${RESET}\n`);
      console.log(JSON.stringify(settingsSnippet, null, 2));
    }
    process.exit(0);
  }

  if (opts.file) {
    const content = fs.readFileSync(opts.file, "utf8");
    const res = scanTextForPromptTraps(content, opts.file, true);
    console.log(JSON.stringify(res, null, 2));
    process.exit(res.findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH") ? 1 : 0);
  }

  if (opts.ghIssue) {
    const m = opts.ghIssue.match(/^([^#]+)#(\d+)$/);
    if (!m) {
      console.error("Invalid --gh-issue format. Expected owner/repo#123");
      process.exit(1);
    }
    const [, repo, num] = m;
    const out = execFileSync("gh", ["issue", "view", num, "--repo", repo, "--json", "title,body,comments"], {
      encoding: "utf8"
    });
    const res = scanTextForPromptTraps(out, opts.ghIssue, true);
    console.log(JSON.stringify(res, null, 2));
    process.exit(res.findings.some((f) => f.severity === "CRITICAL" || f.severity === "HIGH") ? 1 : 0);
  }

  const result = opts.demo
    ? getDemoResult()
    : auditRepoTraps({
        workspaceDir: opts.workspaceDir || "/Volumes/Apple External Drive/Prince Jain/Github"
      });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    renderReport(result);
  }

  if (opts.failOn) {
    const ranks = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const threshold = ranks[opts.failOn] || 4;
    const triggered = result.findings.some((f) => (ranks[f.severity] || 0) >= threshold);
    if (triggered) process.exit(1);
  }
}

main();
