The discussion on `r/ClaudeAI` (`1xozfcv`) about why 98% of the `16,060` open GitHub issues on `anthropics/claude-code` cannot simply be handed to autonomous triage agents hit on a real engineering problem: **untrusted input poisoning**.

Whenever you point Claude Code or Codex CLI at an external GitHub issue (`gh issue view`), a cloned PR branch, or a third-party `SKILL.md` file, four classes of traps can hijack the agent:
1. **Repo-open config hooks**: `.claude/settings.json` (`hooks`, `apiKeyHelper`, `statusLine`), `.mcp.json`, or `.vscode/tasks.json` (`"runOn": "folderOpen"`) inside a cloned repo that run commands on startup.
2. **Invisible Unicode steganography**: Unicode Tag characters (`U+E0000` to `U+E007F`), bidirectional overrides (`U+202A` to `U+202E`), and standalone zero-width spaces (`U+200B`).
3. **Spoofed `<system-reminder>` and `</tool_result>` delimiters** inside untrusted issue bodies or web responses.
4. **Hidden HTML comment instructions & remote shell pipes** (hidden HTML comment blocks with override instructions or `curl ... | bash` inside skill files).

### Three false-positive traps and blind spots in my first scanner

When I ran my first scanner script across `525` local skill markdown files, `16` workspace repos, and `153` local Claude Code and Codex CLI transcripts, three things broke:

1. **Claude Code's `1,526` native `type: "attachment"` `<system-reminder>` rows**: Scanning raw `.jsonl` lines for `<system-reminder>` to detect delimiter spoofing flagged `1,526` rows across `125` sessions because Claude Code writes its own internal system reminders as `type: "attachment"` and `type: "api-request-*"` records. Filtering out native attachment records (`RTR012`) isolated untrusted `tool_result` payloads (`RTR008`).
2. **Codex CLI's `custom_tool_call_output` nested object payloads (`142` zero-width characters across `5` sessions)**: Unlike `function_call_output` (where `payload.output` is a string), Codex CLI's `custom_tool_call_output` stores `payload.output` as a nested JSON object. My initial `String(payload.output)` call turned the tool output into `"[object Object]"` and missed `138` of the `142` standalone `U+200B` and `U+200E` characters ingested across `15` tool outputs (`RTR011`).
3. **Composite Emoji `U+200D` ZWJ vs standalone `U+200B` (`RTR014`)**: A raw zero-width regex flagged composite emojis (`1` in `notebook-guidance/SKILL.md`) until I separated Emoji Zero-Width Joiner sequences (`<Emoji> U+200D <Emoji>`) from standalone `U+200B` spaces (`2` in `signs-of-ai-writing.md`, `RTR007`) and `1` live `curl -fsSL https://composio.dev/install | bash` remote shell pipe in `composio-cli/SKILL.md` (`RTR005`).

### Running `repotrap`

I published the zero-dependency scanner as `repotrap` (`npx repotrap`):

```bash
npx repotrap
```

You can also pre-scan a live GitHub issue or PR via the `gh-issue` option (`npx repotrap` with `gh-issue owner/repo#123`) before letting an agent read it, or run `emit-hook` mode to generate a deterministic `PostToolUse` sanitizer hook for `~/.claude/settings.json`.

### Limitations

- `repotrap` deterministically catches invisible Unicode (`U+E0000` tags, Bidi overrides, standalone `U+200B`), spoofed XML/system delimiters, hidden HTML comment instructions, `curl | sh` skill pipes, and `.claude`/`.mcp.json`/`.vscode` repo-open hooks. It cannot prove whether plain natural-language prose without structural markers or override phrases will sway a model.

GitHub: https://github.com/princejain756/repotrap
npm: https://www.npmjs.com/package/repotrap
