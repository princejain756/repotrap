export const RULE_META = {
  // Plane 1: Untrusted Repo, Skill & Issue/PR Surface
  RTR003: {
    id: "RTR003",
    plane: "repo",
    severity: "CRITICAL",
    title: "Unicode Tag Characters (U+E0000) or Bidirectional Override Smuggling (U+202A-U+202E)",
    points: 30
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
