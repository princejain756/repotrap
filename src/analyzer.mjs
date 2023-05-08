export const RULE_META = {
  // Plane 1: Untrusted Repo, Skill & Issue/PR Surface
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
  RTR007: {
    id: "RTR007",
    plane: "repo",
    severity: "LOW",
    title: "Standalone Zero-Width Space (U+200B / U+FEFF) in Skill or Documentation File",
    points: 5
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
const REMOTE_SHELL_PIPE_RE = /\b(?:curl|wget)\b[^\n|]{3,140}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i;

export function scanTextForPromptTraps(text, sourceLabel = "input") {
  const findings = [];
  const s = String(text || "");
  if (!s) return { findings, zwStats: { bidiOrTagCount: 0, standaloneZeroWidthCount: 0 } };

  const zwStats = analyzeZeroWidthCharacters(s);

  if (zwStats.bidiOrTagCount > 0) {
    findings.push({
      ruleId: "RTR003",
      plane: "repo",
      severity: "CRITICAL",
      file: maskPath(sourceLabel),
      detail: `${zwStats.bidiOrTagCount} invisible Unicode Tag or Bidirectional override character(s) (${zwStats.detectedCodes.join(", ")}) detected in ${maskPath(sourceLabel)}`,
      evidence: `Codes: ${zwStats.detectedCodes.join(", ")}`
    });
  }

  if (zwStats.standaloneZeroWidthCount > 0) {
    findings.push({
      ruleId: "RTR007",
      plane: "repo",
      severity: "LOW",
      file: maskPath(sourceLabel),
      detail: `${zwStats.standaloneZeroWidthCount} standalone zero-width character(s) (${zwStats.detectedCodes.join(", ")}) in ${maskPath(sourceLabel)}`,
      evidence: `Codes: ${zwStats.detectedCodes.join(", ")}`
    });
  }

  // Hidden HTML comments are the cheapest place to bury agent instructions:
  // they render invisible on GitHub and inside Markdown viewers.
  const htmlComments = [...s.matchAll(/<!--([\s\S]{1,1500}?)-->/g)];
  for (const m of htmlComments) {
    const body = m[1];
    if (IMPERATIVE_INJECTION_RE.test(body)) {
      findings.push({
        ruleId: "RTR004",
        plane: "repo",
        severity: "HIGH",
        file: maskPath(sourceLabel),
        detail: `Hidden HTML comment in ${maskPath(sourceLabel)} contains imperative agent/shell instructions`,
        evidence: `<!-- ${body.trim().slice(0, 140)} -->`
      });
    }
  }

  // A skill that pipes a remote URL straight into a shell runs arbitrary code
  // the first time an agent follows its setup section.
  if (REMOTE_SHELL_PIPE_RE.test(s)) {
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