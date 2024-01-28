import fs from "node:fs";
import path from "node:path";

export const RULE_META = {
  // Plane 1: Untrusted Repo, Skill & Issue/PR Surface
  RTR001: {
    id: "RTR001",
    plane: "repo",
    severity: "CRITICAL",
    title: "Workspace .claude/settings.json Defines Auto-Executing Hooks or Helper Scripts",
    points: 30
  },
  RTR002: {
    id: "RTR002",
    plane: "repo",
    severity: "CRITICAL",
    title: "Workspace .mcp.json or .vscode/tasks.json Spawns Commands on Folder Open",
    points: 25
  },
  RTR003: {
    id: "RTR003",
    plane: "repo",
    severity: "CRITICAL",
    title: "Unicode Tag Characters (U+E0000) or Bidirectional Override Smuggling (U+202A-U+202E)",
    points: 30
  },
  RTR004: {
    id: "RTR004",
    plane: "repo",
    severity: "HIGH",
    title: "HTML Comment or Hidden Element Contains Imperative Prompt-Injection Verbs",
    points: 20
  },
  RTR005: {
    id: "RTR005",
    plane: "repo",
    severity: "HIGH",
    title: "Skill or Instruction File Pipes Remote URL Directly to Shell (curl | sh / eval)",
    points: 18
  },
  RTR006: {
    id: "RTR006",
    plane: "repo",
    severity: "MEDIUM",
    title: "package.json Lifecycle Hook (preinstall/postinstall) Runs Network or Shell Payload",
    points: 15
  },
  RTR007: {
    id: "RTR007",
    plane: "repo",
    severity: "LOW",
    title: "Standalone Zero-Width Space (U+200B / U+FEFF) in Skill or Documentation File",
    points: 5
  },

  // Plane 2: Session Transcript tool_result & Issue Poisoning Replay
  RTR008: {
    id: "RTR008",
    plane: "transcript",
    severity: "CRITICAL",
    title: "Spoofed <system-reminder> or </tool_result> Delimiter Inside Untrusted Tool Output",
    points: 30
  },
  RTR009: {
    id: "RTR009",
    plane: "transcript",
    severity: "CRITICAL",
    title: "Explicit Prompt-Override or Instruction-Hijack Phrase Inside Tool Output",
    points: 25
  },
  RTR010: {
    id: "RTR010",
    plane: "transcript",
    severity: "HIGH",
    title: "Hidden HTML Comment Inside Tool Output Contains Imperative Agent Instructions",
    points: 18
  },
  RTR011: {
    id: "RTR011",
    plane: "transcript",
    severity: "MEDIUM",
    title: "Standalone Zero-Width or Directionality Marks (U+200B / U+200E) Ingested in Tool Output",
    points: 8
  },
  RTR012: {
    id: "RTR012",
    plane: "transcript",
    severity: "INFO",
    title: "Harness-Native <system-reminder> Attachment Rows Filtered (False-Positive Guard)",
    points: 0
  },
  RTR013: {
    id: "RTR013",
    plane: "repo",
    severity: "INFO",
    title: "Benign Local package.json Build Lifecycle Scripts Separated (False-Positive Guard)",
    points: 0
  }
};

export function maskPath(p) {
  if (!p) return "";
  return String(p)
    .replace(/\/Users\/[a-zA-Z0-9._-]+/g, "~")
    .replace(/\/home\/[a-zA-Z0-9._-]+/g, "~");
}

// Detect Unicode Tag block (U+E0000 - U+E007F, UTF-16 surrogates \uDB40[\uDC00-\uDC7F])
// and Bidirectional Overrides (U+202A - U+202E, U+2066 - U+2069)
const BIDI_OR_TAG_RE = /[\u202A-\u202E\u2066-\u2069]|\uDB40[\uDC00-\uDC7F]/g;

export function analyzeZeroWidthCharacters(text) {
  const s = String(text || "");
  let bidiOrTagCount = 0;
  let standaloneZeroWidthCount = 0;
  const detectedCodes = new Set();

  const bidiMatches = s.match(BIDI_OR_TAG_RE);
  if (bidiMatches) {
    bidiOrTagCount += bidiMatches.length;
    for (const m of bidiMatches) {
      const cp = m.codePointAt(0);
      detectedCodes.add("U+" + cp.toString(16).toUpperCase());
    }
  }

  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code === 0x200b || (code === 0xfeff && i > 0)) {
      standaloneZeroWidthCount++;
      detectedCodes.add("U+" + code.toString(16).toUpperCase().padStart(4, "0"));
    }
  }

  return {
    bidiOrTagCount,
    standaloneZeroWidthCount,
    detectedCodes: [...detectedCodes]
  };
}

const IMPERATIVE_INJECTION_RE = /\b(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior)|system\s+prompt|you\s+are\s+now|important:\s*run\s+|curl\s+-|wget\s+http|bash\s+-c|cat\s+~\/\.|\.env\b|id_rsa\b|PreToolUse)/i;
const SPOOFED_DELIMITER_RE = /<\/?(?:system-reminder|tool_result|EXTREMELY_IMPORTANT|function_calls|antml:invoke)\b/i;
const REMOTE_SHELL_PIPE_RE = /\b(?:curl|wget)\b[^\n|]{3,140}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i;

export function scanTextForPromptTraps(text, sourceLabel = "input", isTranscriptToolResult = false) {
  const findings = [];
  const s = String(text || "");
  if (!s) return { findings, zwStats: { bidiOrTagCount: 0, standaloneZeroWidthCount: 0 } };

  const zwStats = analyzeZeroWidthCharacters(s);

  if (zwStats.bidiOrTagCount > 0) {
    findings.push({
      ruleId: "RTR003",
      plane: isTranscriptToolResult ? "transcript" : "repo",
      severity: "CRITICAL",
      file: maskPath(sourceLabel),
      detail: `${zwStats.bidiOrTagCount} invisible Unicode Tag or Bidirectional override character(s) (${zwStats.detectedCodes.join(", ")}) detected in ${maskPath(sourceLabel)}`,
      evidence: `Codes: ${zwStats.detectedCodes.join(", ")}`
    });
  }

  if (zwStats.standaloneZeroWidthCount > 0) {
    findings.push({
      ruleId: isTranscriptToolResult ? "RTR011" : "RTR007",
      plane: isTranscriptToolResult ? "transcript" : "repo",
      severity: isTranscriptToolResult ? "MEDIUM" : "LOW",
      file: maskPath(sourceLabel),
      detail: `${zwStats.standaloneZeroWidthCount} standalone zero-width/directionality character(s) (${zwStats.detectedCodes.join(", ")}) in ${maskPath(sourceLabel)}`,
      evidence: `Codes: ${zwStats.detectedCodes.join(", ")}`
    });
  }

  // Check HTML comments for hidden prompt injection
  const htmlComments = [...s.matchAll(/<!--([\s\S]{1,1500}?)-->/g)];
  for (const m of htmlComments) {
    const body = m[1];
    if (IMPERATIVE_INJECTION_RE.test(body) || SPOOFED_DELIMITER_RE.test(body)) {
      findings.push({
        ruleId: isTranscriptToolResult ? "RTR010" : "RTR004",
        plane: isTranscriptToolResult ? "transcript" : "repo",
        severity: "HIGH",
        file: maskPath(sourceLabel),
        detail: `Hidden HTML comment in ${maskPath(sourceLabel)} contains imperative agent/shell instructions`,
        evidence: `<!-- ${body.trim().slice(0, 140)} -->`
      });
    }
  }

  // Check for spoofed harness delimiters inside untrusted tool results or issue bodies
  if (isTranscriptToolResult && SPOOFED_DELIMITER_RE.test(s)) {
    const match = s.match(SPOOFED_DELIMITER_RE);
    findings.push({
      ruleId: "RTR008",
      plane: "transcript",
      severity: "CRITICAL",
      file: maskPath(sourceLabel),
      detail: `Untrusted tool output in ${maskPath(sourceLabel)} contains spoofed harness delimiter (${match[0]})`,
      evidence: match[0]
    });
  }

  // Check for explicit prompt override phrases inside tool_result
  if (
    isTranscriptToolResult &&
    /\b(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions|new\s+system\s+instructions\s*:)/i.test(s)
  ) {
    findings.push({
      ruleId: "RTR009",
      plane: "transcript",
      severity: "CRITICAL",
      file: maskPath(sourceLabel),
      detail: `Untrusted tool output in ${maskPath(sourceLabel)} contains explicit prompt-override phrase`,
      evidence: s.match(/\b(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions|new\s+system\s+instructions\s*:)/i)[0]
    });
  }

  // Check for remote shell pipe in skill / instruction files
  if (!isTranscriptToolResult && REMOTE_SHELL_PIPE_RE.test(s)) {
    const match = s.match(REMOTE_SHELL_PIPE_RE);
    findings.push({
      ruleId: "RTR005",
      plane: "repo",
      severity: "HIGH",
      file: maskPath(sourceLabel),
      detail: `Instruction/skill file ${maskPath(sourceLabel)} instructs agent to pipe remote URL directly into shell`,
      evidence: match[0].trim().slice(0, 160)
    });
  }

  return { findings, zwStats };
}

export function scanWorkspaceConfigFiles(repoDir) {
  const findings = [];
  let benignLifecycleCount = 0;

  // 1. Check .claude/settings.json and .claude/settings.local.json inside repo
  for (const rel of [".claude/settings.json", ".claude/settings.local.json"]) {
    const p = path.join(repoDir, rel);
    if (!fs.existsSync(p)) continue;
    try {
      const cfg = JSON.parse(fs.readFileSync(p, "utf8"));
      const dangerousKeys = ["hooks", "apiKeyHelper", "otelHeadersHelper", "awsAuthRefresh", "statusLine"].filter(
        (k) => Boolean(cfg?.[k])
      );
      if (dangerousKeys.length > 0) {
        findings.push({
          ruleId: "RTR001",
          plane: "repo",
          severity: "CRITICAL",
          file: maskPath(p),
          detail: `Workspace ${rel} defines auto-executing ${dangerousKeys.join(", ")} on session start or tool invocation`,
          evidence: `Keys: ${dangerousKeys.join(", ")}`
        });
      }
    } catch {
      // ignore
    }
  }

  // 2. Check .mcp.json and .vscode/tasks.json
  const mcpPath = path.join(repoDir, ".mcp.json");
  if (fs.existsSync(mcpPath)) {
    try {
      const mcp = JSON.parse(fs.readFileSync(mcpPath, "utf8"));
      const servers = Object.keys(mcp?.mcpServers || mcp || {});
      if (servers.length > 0) {
        findings.push({
          ruleId: "RTR002",
          plane: "repo",
          severity: "CRITICAL",
          file: maskPath(mcpPath),
          detail: `Workspace .mcp.json defines ${servers.length} repo-scoped MCP server(s) (${servers.slice(0, 4).join(", ")})`,
          evidence: `Servers: ${servers.slice(0, 4).join(", ")}`
        });
      }
    } catch {
      // ignore
    }
  }

  const vscodeTasksPath = path.join(repoDir, ".vscode", "tasks.json");
  if (fs.existsSync(vscodeTasksPath)) {
    try {
      const raw = fs.readFileSync(vscodeTasksPath, "utf8");
      if (/"runOn"\s*:\s*"folderOpen"/i.test(raw)) {
        findings.push({
          ruleId: "RTR002",
          plane: "repo",
          severity: "CRITICAL",
          file: maskPath(vscodeTasksPath),
          detail: `Workspace .vscode/tasks.json contains task with "runOn": "folderOpen"`,
          evidence: `"runOn": "folderOpen"`
        });
      }
    } catch {
      // ignore
    }
  }

  // 3. Check package.json lifecycle hooks
  const pkgPath = path.join(repoDir, "package.json");
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      const scripts = pkg?.scripts || {};
      for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
        const cmd = scripts[hook];
        if (!cmd) continue;
        if (/\b(curl|wget|nc\s|netcat|bash\s+-c|sh\s+-c|base64\s+-d|eval\s|http:\/\/|https:\/\/)\b/i.test(cmd)) {
          findings.push({
            ruleId: "RTR006",
            plane: "repo",
            severity: "MEDIUM",
            file: maskPath(pkgPath),
            detail: `package.json "${hook}" lifecycle script runs network or shell command (${cmd.slice(0, 100)})`,
            evidence: `${hook}: ${cmd.slice(0, 120)}`
          });
        } else {
          benignLifecycleCount++;
        }
      }
    } catch {
      // ignore
    }
  }

  return { findings, benignLifecycleCount };
}

export function scanTranscriptFile(filePath) {
  const findings = [];
  let harnessSystemReminderCount = 0;
  let spoofedToolResultDelimiterCount = 0;
  let toolResultZeroWidthCount = 0;
  let toolResultHtmlCommentCount = 0;

  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split("\n");

  for (const line of lines) {
    if (!line.trim() || line.length > 120000) continue;

    // Check if line has <system-reminder>
    const hasSysRem = line.includes("<system-reminder>");
    const hasToolRes =
      line.includes("tool_result") ||
      line.includes("function_call_output") ||
      line.includes("custom_tool_call_output");
    const hasZw = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/.test(line);
    const hasComment = line.includes("<!--");
    const hasOverride = /ignore (?:all )?(?:previous|prior) instructions/i.test(line);

    if (!hasSysRem && !hasToolRes && !hasZw && !hasComment && !hasOverride) continue;

    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }

    // False-positive guard (RTR012): Claude Code native attachment / api-request rows
    if (
      hasSysRem &&
      (obj.type === "attachment" ||
        obj.type === "api-request-shape" ||
        obj.type === "api-request-blob")
    ) {
      harnessSystemReminderCount++;
      continue;
    }

    // Extract untrusted tool_result / function_call_output text
    const toolPayloads = [];
    if (Array.isArray(obj?.message?.content)) {
      for (const c of obj.message.content) {
        if (c?.type === "tool_result") {
          const txt = typeof c.content === "string" ? c.content : JSON.stringify(c.content || "");
          toolPayloads.push(txt);
        }
      }
    }
    if (
      obj?.type === "response_item" &&
      (obj?.payload?.type === "function_call_output" || obj?.payload?.type === "custom_tool_call_output")
    ) {
      const rawOut = obj.payload.output;
      toolPayloads.push(typeof rawOut === "string" ? rawOut : JSON.stringify(rawOut || ""));
    }
    if (obj?.type === "user" && typeof obj?.message?.content === "string") {
      toolPayloads.push(obj.message.content);
    }

    for (const payload of toolPayloads) {
      if (payload.includes("<!--")) toolResultHtmlCommentCount++;
      const res = scanTextForPromptTraps(payload, path.basename(filePath), true);
      for (const f of res.findings) {
        if (f.ruleId === "RTR008") spoofedToolResultDelimiterCount++;
        findings.push(f);
      }
      toolResultZeroWidthCount += res.zwStats.standaloneZeroWidthCount;
    }
  }

  return {
    findings,
    harnessSystemReminderCount,
    spoofedToolResultDelimiterCount,
    toolResultZeroWidthCount,
    toolResultHtmlCommentCount
  };
}
